# topology_api.py  --  POX REST API  (Full SDN Monitoring Suite v3)
# Place at:  ~/pox/pox/topology_api.py
#
# ./pox.py forwarding.l2_learning openflow.discovery \
#   openflow.spanning_tree --no-flood --hold-down \
#   host_tracker web.webcore topology_api \
#   samples.pretty_log log.level --DEBUG

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.web.webcore import SplitRequestHandler
from pox.lib.revent import EventMixin
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet import ethernet, arp, ipv4, icmp, tcp, udp
import json, time, threading, collections

log = core.getLogger()

HOST_TIMEOUT   = 45
TRAFFIC_WINDOW = 5.0
LINK_SPEED_BPS = 100e6
_start_time    = time.time()

_lk = threading.Lock

_traffic_lock   = _lk(); _traffic = {}
_bw_lock        = _lk(); _bw      = {}
_events_lock    = _lk(); _events  = []; MAX_EVENTS = 1000
_alerts_lock    = _lk(); _alerts  = []; MAX_ALERTS = 1000; _alert_id = [0]
# ----- PACKET BUFFER: 10000 packets, never cleared by poll, only by manual reset
_packets_lock   = _lk(); _packets = collections.deque(maxlen=10000)
_pkt_id_ctr     = [0]
_pkt_stats_lock = _lk()
_pkt_stats      = {"total":0,"arp":0,"icmp":0,"tcp":0,"udp":0,"other":0,"hosts":{}}
_flows_lock     = _lk(); _flows = {}
_bwh_lock       = _lk(); _bwh   = {}; BW_HIST = 120
_conn_lock      = _lk(); _connections = {}; MAX_CONNS = 2000
_talkers_lock   = _lk(); _talkers = {}
_hosts_lock     = _lk(); _host_intel = {}
_sw_uptime_lock = _lk(); _sw_uptime = {}
_cmdlog_lock    = _lk(); _cmdlog = []; MAX_CMDLOG = 2000
# Controller stats: PacketIn count, total bytes seen by controller
_ctrl_lock      = _lk()
_ctrl_stats     = {"packetin_count":0,"total_bytes":0,"per_dpid":{}}

_threat_lock        = _lk()
_mac_location       = {}
_port_scan_state    = {}
_icmp_flood_state   = {}
_arp_flood_state    = {}
_bcast_state        = {}
_dns_state          = {}
_syn_state          = {}
_ip_sweep_state     = {}
_ttl_state          = {}
_alert_history      = collections.deque(maxlen=500)

# Thresholds
PORT_SCAN_THRESHOLD  = 15
ICMP_FLOOD_THRESHOLD = 50
ARP_FLOOD_THRESHOLD  = 30
BCAST_THRESHOLD      = 100
DNS_FLOOD_THRESHOLD  = 40
SYN_THRESHOLD        = 20
IP_SWEEP_THRESHOLD   = 10

# MAC spoof: raised thresholds to eliminate pingall false positives.
# Root cause explanation: when you run "pingall" in Mininet, every host
# sends ARP broadcasts which flood through ALL switches. POX sees these
# packets arrive on EVERY switch, making it look like the MAC "moved".
# Fix: track a SET of known dpids per MAC. Only alert when a genuinely
# new switch appears AND the MAC was stable on exactly one switch for
# MAC_SPOOF_MIN_AGE seconds (meaning real hosts wouldn't move that fast).
MAC_SPOOF_MIN_AGE = 45   # seconds stable before move is suspicious
STARTUP_GRACE     = 90   # 90s grace after start (full topology settling)

# MITRE ATT&CK mapping with URLs
MITRE_MAP = {
    "port_scan":       ("T1046","Network Service Scanning",
                        "https://attack.mitre.org/techniques/T1046/"),
    "icmp_flood":      ("T1498","Network Denial of Service",
                        "https://attack.mitre.org/techniques/T1498/"),
    "arp_flood":       ("T1557.002","ARP Cache Poisoning",
                        "https://attack.mitre.org/techniques/T1557/002/"),
    "broadcast_storm": ("T1498.001","Direct Network Flood",
                        "https://attack.mitre.org/techniques/T1498/001/"),
    "mac_spoof":       ("T1557","Adversary-in-the-Middle",
                        "https://attack.mitre.org/techniques/T1557/"),
    "dns_flood":       ("T1071.004","Application Layer Protocol: DNS",
                        "https://attack.mitre.org/techniques/T1071/004/"),
    "syn_scan":        ("T1046","Network Service Scanning (SYN)",
                        "https://attack.mitre.org/techniques/T1046/"),
    "ip_sweep":        ("T1018","Remote System Discovery",
                        "https://attack.mitre.org/techniques/T1018/"),
    "ttl_anomaly":     ("T1040","Network Sniffing / Traceroute",
                        "https://attack.mitre.org/techniques/T1040/"),
    "large_transfer":  ("T1030","Data Transfer Size Limits",
                        "https://attack.mitre.org/techniques/T1030/"),
}

LARGE_TRANSFER_BYTES = 500000  # 500KB in a single packet burst = suspicious


# ---- helpers -----------------------------------------------------------------

def _is_switch_mac(mac_str):
    if mac_str in ("ff:ff:ff:ff:ff:ff","00:00:00:00:00:00"):
        return True
    parts = mac_str.split(":")
    if len(parts) != 6:
        return True
    try:
        b0 = int(parts[0], 16)
        if b0 & 0x01: return True        # multicast
        if parts[:5] == ["00","00","00","00","00"]: return True
    except Exception:
        return True
    return False

def _add_event(msg, level="info"):
    with _events_lock:
        _events.append({"ts":round(time.time(),2),"msg":msg,"level":level})
        if len(_events) > MAX_EVENTS: del _events[0]

def _add_alert(atype, severity, src, dst, msg):
    now = time.time()
    tid, tdesc, turl = MITRE_MAP.get(atype, ("","",""))
    mitre_label = ("%s - %s" % (tid, tdesc)) if tid else ""
    with _alerts_lock:
        for a in _alerts:
            if (a["active"] and a["type"]==atype
                    and a["src"]==src and now-a["ts"]<60):
                a["count"]+=1; a["ts"]=round(now,2); return
        _alert_id[0]+=1
        _alerts.append({"id":_alert_id[0],"ts":round(now,2),"type":atype,
                        "severity":severity,"src":src,"dst":dst,"msg":msg,
                        "count":1,"active":True,
                        "mitre":mitre_label,"mitre_id":tid,
                        "mitre_desc":tdesc,"mitre_url":turl})
        if len(_alerts)>MAX_ALERTS: del _alerts[0]
    _alert_history.append({"ts":round(now,2),"type":atype,"severity":severity})
    _add_event("[%s] %s"%(severity.upper(),msg),
               "warn" if severity in ("critical","high") else "info")
    _bump_threat(src, severity)

def _bump_threat(src, severity):
    score_map = {"critical":25,"high":15,"medium":8,"low":3}
    score = score_map.get(severity, 3)
    with _hosts_lock:
        for mac, h in _host_intel.items():
            if h.get("ip")==src or mac==src:
                h["threat_score"] = min(100, h.get("threat_score",0)+score)
                h["alert_count"]  = h.get("alert_count",0)+1
                break

def _update_host(mac, ip, dpid, port, pkt_len, direction, proto=""):
    now = time.time()
    with _hosts_lock:
        if mac not in _host_intel:
            _host_intel[mac] = {
                "mac":mac,"ip":ip or "","dpid":dpid,"port":port,
                "first_seen":round(now,2),"last_seen":round(now,2),
                "tx_bytes":0,"rx_bytes":0,"tx_pkts":0,"rx_pkts":0,
                "protocols":set(),"threat_score":0,"alert_count":0,
            }
        h = _host_intel[mac]
        h["last_seen"] = round(now,2)
        if ip: h["ip"] = ip
        h["dpid"] = dpid; h["port"] = port
        if direction=="tx": h["tx_bytes"]+=pkt_len; h["tx_pkts"]+=1
        else:               h["rx_bytes"]+=pkt_len; h["rx_pkts"]+=1
        if proto: h.setdefault("protocols",set()).add(proto)

def _host_intel_json():
    with _hosts_lock:
        out = []
        for mac, h in _host_intel.items():
            d = dict(h)
            d["protocols"] = list(h.get("protocols", set()))
            out.append(d)
    out.sort(key=lambda x: x.get("tx_bytes",0)+x.get("rx_bytes",0), reverse=True)
    return out

def log_command(cmd, source="mininet"):
    with _cmdlog_lock:
        _cmdlog.append({"ts":round(time.time(),2),"cmd":cmd,"source":source})
        if len(_cmdlog) > MAX_CMDLOG: del _cmdlog[0]


# ---- Traffic Monitor ---------------------------------------------------------

class TrafficMonitor(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        from pox.lib.recoco import Timer
        Timer(3, self._req_stats, recurring=True)
        Timer(300, self._decay_threats, recurring=True)

    def _decay_threats(self):
        with _hosts_lock:
            for h in _host_intel.values():
                h["threat_score"] = max(0, h.get("threat_score",0)-2)

    def _req_stats(self):
        if not core.hasComponent("openflow"): return
        for conn in core.openflow.connections:
            conn.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
            body = of.ofp_flow_stats_request()
            body.match=of.ofp_match(); body.table_id=0xff
            body.out_port=of.OFPP_NONE
            conn.send(of.ofp_stats_request(body=body))

    def _handle_PacketIn(self, event):
        dpid = dpid_to_str(event.dpid); now = time.time()
        with _traffic_lock: _traffic[dpid] = now
        # Controller traffic stats
        with _ctrl_lock:
            _ctrl_stats["packetin_count"] += 1
            _ctrl_stats["total_bytes"]    += event.ofp.total_len
            pd = _ctrl_stats["per_dpid"].setdefault(dpid, {"count":0,"bytes":0})
            pd["count"]+=1; pd["bytes"]+=event.ofp.total_len

        eth = event.parsed
        if not eth: return
        sm = str(eth.src); dm = str(eth.dst)
        pkt_len = event.ofp.total_len
        proto="other"; si=""; di=""; sp=0; dp=0; info=""
        flags_syn=False; flags_ack=False; flags_rst=False; flags_fin=False
        ttl_val=0; is_dns=False; ip_proto_num=0

        if eth.type == ethernet.ARP_TYPE:
            proto="arp"; a=eth.payload
            if a:
                si=str(a.protosrc); di=str(a.protodst)
                op="Request" if a.opcode==arp.REQUEST else "Reply"
                info="ARP %s %s -> %s"%(op,si,di)
        elif eth.type == ethernet.IP_TYPE:
            ip=eth.payload
            if ip:
                si=str(ip.srcip); di=str(ip.dstip)
                ttl_val=ip.ttl; ip_proto_num=ip.protocol
                if ip.protocol==ipv4.ICMP_PROTOCOL:
                    proto="icmp"; info="ICMP %s -> %s"%(si,di)
                elif ip.protocol==ipv4.TCP_PROTOCOL:
                    proto="tcp"; t=ip.payload
                    if t and hasattr(t,"srcport"):
                        sp=t.srcport; dp=t.dstport
                        try:
                            flags_syn=bool(t.SYN); flags_ack=bool(t.ACK)
                            flags_rst=bool(t.RST); flags_fin=bool(t.FIN)
                        except: pass
                        info="TCP %s:%d -> %s:%d"%(si,sp,di,dp)
                    else: info="TCP %s -> %s"%(si,di)
                elif ip.protocol==ipv4.UDP_PROTOCOL:
                    proto="udp"; u=ip.payload
                    if u and hasattr(u,"srcport"):
                        sp=u.srcport; dp=u.dstport
                        is_dns=(dp==53 or sp==53)
                        info="UDP %s:%d -> %s:%d"%(si,sp,di,dp)
                    else: info="UDP %s -> %s"%(si,di)
                else:
                    info="IP proto=%d %s->%s"%(ip.protocol,si,di)
        else:
            info="ETH 0x%04x"%eth.type

        # ---- Packet buffer (persistent, not cleared by polling) ----
        with _packets_lock:
            _pkt_id_ctr[0]+=1
            flags_str = ""
            if flags_syn: flags_str+="S"
            if flags_ack: flags_str+="A"
            if flags_rst: flags_str+="R"
            if flags_fin: flags_str+="F"
            _packets.append({
                "id":_pkt_id_ctr[0],"ts":round(now,3),
                "src_mac":sm,"dst_mac":dm,"src_ip":si,"dst_ip":di,
                "proto":proto,"len":pkt_len,"info":info,
                "sw":dpid,"port":event.port,"sp":sp,"dp":dp,
                "flags":flags_str,"ttl":ttl_val,"ip_proto":ip_proto_num,
            })

        # Protocol stats
        with _pkt_stats_lock:
            _pkt_stats["total"]+=1
            key = proto if proto in _pkt_stats else "other"
            _pkt_stats[key]+=1
            h=_pkt_stats["hosts"]
            if sm not in h: h[sm]={"tx_bytes":0,"rx_bytes":0,"tx_pkts":0,"rx_pkts":0}
            h[sm]["tx_bytes"]+=pkt_len; h[sm]["tx_pkts"]+=1
            if dm not in h: h[dm]={"tx_bytes":0,"rx_bytes":0,"tx_pkts":0,"rx_pkts":0}
            h[dm]["rx_bytes"]+=pkt_len; h[dm]["rx_pkts"]+=1

        # Host intel
        _update_host(sm, si, dpid, event.port, pkt_len, "tx", proto)
        if dm not in ("ff:ff:ff:ff:ff:ff","00:00:00:00:00:00"):
            _update_host(dm, di, dpid, event.port, pkt_len, "rx", proto)

        # Connection tracker
        if proto in ("tcp","udp") and si and di and sp and dp:
            key = (si,di,sp,dp)
            with _conn_lock:
                if key not in _connections:
                    if len(_connections)>=MAX_CONNS:
                        oldest=min(_connections,key=lambda k:_connections[k]["last"])
                        del _connections[oldest]
                    state="SYN" if (proto=="tcp" and flags_syn and not flags_ack) else "ESTAB"
                    _connections[key]={"src_ip":si,"dst_ip":di,"src_port":sp,"dst_port":dp,
                                       "proto":proto,"state":state,"start":round(now,2),
                                       "last":round(now,2),"bytes":pkt_len,"pkts":1}
                else:
                    c=_connections[key]; c["last"]=round(now,2)
                    c["bytes"]+=pkt_len; c["pkts"]+=1
                    if proto=="tcp" and flags_ack and c["state"]=="SYN":
                        c["state"]="ESTAB"
                    if flags_fin or flags_rst: c["state"]="CLOSED"

        # Top talkers
        if si and di:
            tk=(si,di)
            with _talkers_lock:
                if tk not in _talkers:
                    _talkers[tk]={"src":si,"dst":di,"pkts":0,"bytes":0,"protos":set()}
                _talkers[tk]["pkts"]+=1
                _talkers[tk]["bytes"]+=pkt_len
                _talkers[tk]["protos"].add(proto)

        # Build switch hw macs set for spoof filter
        sw_hw_macs=set()
        if core.hasComponent("openflow"):
            try:
                for conn in core.openflow.connections:
                    for p in conn.features.ports:
                        sw_hw_macs.add(str(p.hw_addr))
            except: pass

        self._detect(sm,dm,si,di,proto,sp,dp,dpid,event.port,now,
                     pkt_len,flags_syn,flags_ack,ttl_val,is_dns,sw_hw_macs)

    def _detect(self,sm,dm,si,di,proto,sp,dp,dpid,port,now,
                pkt_len,flags_syn,flags_ack,ttl_val,is_dns,sw_hw_macs):
        grace_ok = (now-_start_time) > STARTUP_GRACE
        with _threat_lock:

            # 1. MAC SPOOF - see comment at top for why pingall triggers false positives.
            # Fix: track SET of known dpids per MAC.  Only fire if brand-new dpid
            # AND MAC was stable (single dpid) for >= MAC_SPOOF_MIN_AGE seconds.
            if grace_ok and not _is_switch_mac(sm) and sm not in sw_hw_macs:
                prev=_mac_location.get(sm)
                if prev is None:
                    _mac_location[sm]={"dpid":dpid,"port":port,"ts":now,"seen_dpids":{dpid}}
                else:
                    seen=prev.get("seen_dpids",{prev["dpid"]})
                    if dpid in seen:
                        prev["port"]=port; prev["ts"]=now
                    else:
                        age=now-prev["ts"]
                        if age>=MAC_SPOOF_MIN_AGE and len(seen)==1:
                            _add_alert("mac_spoof","critical",sm,dpid,
                                "MAC spoof: %s on new switch %s/p%d after %.0fs stable on %s/p%d"
                                %(sm,dpid,port,age,prev["dpid"],prev["port"]))
                        seen.add(dpid)
                        prev["seen_dpids"]=seen
                        prev["dpid"]=dpid; prev["port"]=port; prev["ts"]=now

            # 2. Port scan
            if proto=="tcp" and si and dp>0:
                s=_port_scan_state.setdefault(si,{"ts":now,"ports":set()})
                if now-s["ts"]>10: s.update({"ts":now,"ports":set()})
                s["ports"].add(dp)
                if len(s["ports"])>=PORT_SCAN_THRESHOLD:
                    _add_alert("port_scan","high",si,di or "net",
                        "Port scan: %s probed %d ports in 10s"%(si,len(s["ports"])))
                    s["ports"]=set()

            # 3. SYN scan
            if proto=="tcp" and flags_syn and not flags_ack and si:
                s=_syn_state.setdefault(sm,{"ts":now,"half_open":set()})
                if now-s["ts"]>10: s.update({"ts":now,"half_open":set()})
                s["half_open"].add((di,dp))
                if len(s["half_open"])>=SYN_THRESHOLD:
                    _add_alert("syn_scan","high",si or sm,di or "net",
                        "SYN scan: %s -> %d half-open conns in 10s"%(si or sm,len(s["half_open"])))
                    s["half_open"]=set()

            # 4. IP sweep
            if proto=="icmp" and si:
                s=_ip_sweep_state.setdefault(sm,{"ts":now,"ips":set()})
                if now-s["ts"]>10: s.update({"ts":now,"ips":set()})
                s["ips"].add(di)
                if len(s["ips"])>=IP_SWEEP_THRESHOLD:
                    _add_alert("ip_sweep","high",si,di,
                        "IP sweep: %s pinged %d hosts in 10s"%(si,len(s["ips"])))
                    s["ips"]=set()

            # 5. ICMP flood
            if proto=="icmp":
                s=_icmp_flood_state.setdefault(sm,{"ts":now,"count":0})
                if now-s["ts"]>3: s.update({"ts":now,"count":0})
                s["count"]+=1
                if s["count"]>=ICMP_FLOOD_THRESHOLD:
                    _add_alert("icmp_flood","high",si or sm,di or "*",
                        "ICMP flood: %s -> %d pkts in 3s"%(si or sm,s["count"]))
                    s["count"]=0

            # 6. ARP flood
            if proto=="arp":
                s=_arp_flood_state.setdefault(sm,{"ts":now,"count":0})
                if now-s["ts"]>3: s.update({"ts":now,"count":0})
                s["count"]+=1
                if s["count"]>=ARP_FLOOD_THRESHOLD:
                    _add_alert("arp_flood","medium",sm,"broadcast",
                        "ARP flood: %s -> %d pkts in 3s"%(sm,s["count"]))
                    s["count"]=0

            # 7. Broadcast storm
            if dm=="ff:ff:ff:ff:ff:ff":
                s=_bcast_state.setdefault(sm,{"ts":now,"count":0})
                if now-s["ts"]>3: s.update({"ts":now,"count":0})
                s["count"]+=1
                if s["count"]>=BCAST_THRESHOLD:
                    _add_alert("broadcast_storm","medium",sm,"broadcast",
                        "Broadcast storm: %s -> %d broadcasts in 3s"%(sm,s["count"]))
                    s["count"]=0

            # 8. DNS flood/tunneling
            if is_dns:
                s=_dns_state.setdefault(sm,{"ts":now,"count":0,"bytes":0})
                if now-s["ts"]>3: s.update({"ts":now,"count":0,"bytes":0})
                s["count"]+=1; s["bytes"]+=pkt_len
                if s["count"]>=DNS_FLOOD_THRESHOLD:
                    _add_alert("dns_flood","medium",si or sm,di or "dns",
                        "DNS flood: %s -> %d DNS pkts, %dB in 3s"%(si or sm,s["count"],s["bytes"]))
                    s["count"]=0; s["bytes"]=0

            # 9. TTL anomaly
            if ttl_val>0 and ttl_val<5 and si:
                if _ttl_state.get(si) is None:
                    _add_alert("ttl_anomaly","low",si,di or "?",
                        "TTL anomaly: %s TTL=%d (traceroute/recon?)"%(si,ttl_val))
                _ttl_state[si]=ttl_val

            # 10. Large transfer detection
            if pkt_len>LARGE_TRANSFER_BYTES and si:
                _add_alert("large_transfer","medium",si,di or "?",
                    "Large packet: %s -> %s (%d bytes)"%(si,di,pkt_len))

    def _handle_PortStatsReceived(self, event):
        dpid=dpid_to_str(event.dpid); now=time.time()
        with _bw_lock:
            if dpid not in _bw: _bw[dpid]={}
            for s in event.stats:
                pno=s.port_no
                if pno==65534: continue
                tx=s.tx_bytes; rx=s.rx_bytes; prev=_bw[dpid].get(pno)
                if prev:
                    dt=now-prev["ts"]
                    if dt>0:
                        rtx=max(0,(tx-prev["tx"])/dt)
                        rrx=max(0,(rx-prev["rx"])/dt)
                        util=min(100,round((rtx+rrx)/LINK_SPEED_BPS*100,1))
                        _bw[dpid][pno]={"tx":tx,"rx":rx,"ts":now,
                                        "rate_tx":rtx,"rate_rx":rrx,"util":util,
                                        "tx_pkts":s.tx_packets,"rx_pkts":s.rx_packets,
                                        "tx_drop":s.tx_dropped,"rx_drop":s.rx_dropped,
                                        "tx_err":s.tx_errors,"rx_err":s.rx_errors}
                        with _bwh_lock:
                            if dpid not in _bwh: _bwh[dpid]={}
                            if pno not in _bwh[dpid]:
                                _bwh[dpid][pno]=collections.deque(maxlen=BW_HIST)
                            _bwh[dpid][pno].append(
                                {"ts":round(now,1),"rate_tx":round(rtx),
                                 "rate_rx":round(rrx),"util":util})
                    else:
                        _bw[dpid][pno]["tx"]=tx; _bw[dpid][pno]["rx"]=rx
                else:
                    _bw[dpid][pno]={"tx":tx,"rx":rx,"ts":now,
                                    "rate_tx":0,"rate_rx":0,"util":0,
                                    "tx_pkts":0,"rx_pkts":0,
                                    "tx_drop":0,"rx_drop":0,"tx_err":0,"rx_err":0}

    def _handle_FlowStatsReceived(self, event):
        dpid=dpid_to_str(event.dpid); out=[]
        for fs in event.stats:
            m=fs.match
            actions=[("output:%s"%a.port) if isinstance(a,of.ofp_action_output)
                     else type(a).__name__ for a in fs.actions]
            out.append({"priority":fs.priority,
                        "in_port": m.in_port  if m.in_port  is not None else "",
                        "dl_src":  str(m.dl_src) if m.dl_src else "",
                        "dl_dst":  str(m.dl_dst) if m.dl_dst else "",
                        "dl_type": ("0x%04x"%m.dl_type) if m.dl_type else "",
                        "nw_src":  str(m.nw_src) if m.nw_src else "",
                        "nw_dst":  str(m.nw_dst) if m.nw_dst else "",
                        "nw_proto":m.nw_proto if m.nw_proto is not None else "",
                        "tp_src":  m.tp_src if m.tp_src is not None else "",
                        "tp_dst":  m.tp_dst if m.tp_dst is not None else "",
                        "actions": ", ".join(actions) if actions else "DROP",
                        "packet_count":fs.packet_count,"byte_count":fs.byte_count,
                        "duration_sec":fs.duration_sec,"idle_timeout":fs.idle_timeout,
                        "hard_timeout":fs.hard_timeout,"cookie":fs.cookie})
        out.sort(key=lambda x:x["priority"],reverse=True)
        with _flows_lock: _flows[dpid]=out

    def _handle_ConnectionUp(self, event):
        dpid=dpid_to_str(event.dpid)
        with _sw_uptime_lock: _sw_uptime[dpid]=round(time.time(),2)
        _add_event("Switch %s connected"%dpid,"info")
        log_command("switch %s connected"%dpid,"controller")

    def _handle_ConnectionDown(self, event):
        dpid=dpid_to_str(event.dpid)
        _add_event("Switch %s disconnected"%dpid,"warn")
        log_command("switch %s disconnected"%dpid,"controller")
        with _threat_lock:
            for m in [k for k,v in _mac_location.items() if v.get("dpid")==dpid]:
                del _mac_location[m]


# ---- HTTP Handler ------------------------------------------------------------

class TopologyHandler(SplitRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.send_header("Content-Type","application/json")
    def do_OPTIONS(self):
        self.send_response(200); self._cors(); self.end_headers()
    def _qs(self):
        qs=self.path.split("?",1)[1] if "?" in self.path else ""; out={}
        for p in qs.split("&"):
            if "=" in p: k,v=p.split("=",1); out[k]=v
        return out
    def _parts(self):
        return [p for p in self.path.split("?")[0].split("/") if p and p!="topo"]
    def _send(self, obj):
        body=json.dumps(obj)
        self.send_response(200); self._cors()
        self.send_header("Content-Length",str(len(body))); self.end_headers()
        self.wfile.write(body)
    def _body(self):
        n=int(self.headers.get("Content-Length",0))
        raw=self.rfile.read(n) if n else b"{}"
        try: return json.loads(raw)
        except: return {}

    def do_GET(self):
        parts=self._parts(); qs=self._qs()
        if   parts==["switches"]:      self._send(self._sw())
        elif parts==["links"]:         self._send(self._lk_data())
        elif parts==["hosts"]:         self._send(self._ht())
        elif parts==["traffic"]:       self._send(self._tr())
        elif parts==["bandwidth"]:     self._send(self._bwget())
        elif parts==["events"]:        self._send(self._ev())
        elif parts==["alerts"]:        self._send(self._al())
        elif parts==["packets"]:       self._send(self._pk(qs))
        elif parts==["packetstats"]:   self._send(self._ps())
        elif parts==["flows"]:         self._send(self._fl(qs.get("dpid","")))
        elif parts==["bwhistory"]:     self._send(self._bwh(qs))
        elif parts==["connections"]:   self._send(self._connget(qs))
        elif parts==["talkers"]:       self._send(self._talkget(qs))
        elif parts==["hostintel"]:     self._send(_host_intel_json())
        elif parts==["alerttimeline"]: self._send(self._altime())
        elif parts==["portutil"]:      self._send(self._portutil())
        elif parts==["swuptime"]:      self._send(self._swup())
        elif parts==["summary"]:       self._send(self._summary())
        elif parts==["cmdlog"]:        self._send(self._get_cmdlog())
        elif parts==["ctrlstats"]:     self._send(self._ctrlstats())
        elif parts==["test","run"]:    self._send(self._run_test(qs))
        else:
            self._send({"switches":self._sw(),"links":self._lk_data(),"hosts":self._ht()})

    def do_POST(self):
        parts=self._parts(); p=self._body()
        if   parts==["ping"]:                self._send(self._ping(p))
        elif parts==["alerts","dismiss"]:    self._send(self._dis(p))
        elif parts==["alerts","clear"]:      self._send(self._clr())
        elif parts==["flows","delete"]:      self._send(self._dfl(p))
        elif parts==["flows","add"]:         self._send(self._addfl(p))
        elif parts==["qos","set"]:           self._send(self._qos(p))
        elif parts==["packetstats","reset"]: self._send(self._rps())
        elif parts==["packets","clear"]:     self._send(self._clrpkts())
        elif parts==["connections","clear"]: self._send(self._clrconn())
        elif parts==["hostintel","reset"]:   self._send(self._rhi())
        elif parts==["cmdlog","add"]:        self._send(self._add_cmd(p))
        elif parts==["cmdlog","clear"]:      self._send(self._clr_cmd())
        elif parts==["block","host"]:        self._send(self._block_host(p))
        else: self._send({"error":"unknown"})

    # ---- topology -----------------------------------------------------------
    def _sw(self):
        if not core.hasComponent("openflow"): return []
        out=[]
        for conn in core.openflow.connections:
            dpid=dpid_to_str(conn.dpid); ports=[]
            with _bw_lock: bw_dpid=_bw.get(dpid,{})
            for p in conn.features.ports:
                if p.port_no in (0,65534): continue
                name=p.name
                if isinstance(name,bytes): name=name.decode("utf-8","replace")
                pv=bw_dpid.get(p.port_no,{})
                ports.append({"port_no":p.port_no,"name":name,"hw_addr":str(p.hw_addr),
                               "util":pv.get("util",0),
                               "rate_tx":round(pv.get("rate_tx",0)),
                               "rate_rx":round(pv.get("rate_rx",0)),
                               "tx_drop":pv.get("tx_drop",0),
                               "rx_drop":pv.get("rx_drop",0)})
            total_bw=sum(v.get("rate_tx",0)+v.get("rate_rx",0)
                         for v in bw_dpid.values())
            with _sw_uptime_lock:
                up_since=_sw_uptime.get(dpid,0)
                uptime=round(time.time()-up_since) if up_since else 0
            with _flows_lock: fcount=len(_flows.get(dpid,[]))
            out.append({"dpid":dpid,"ports":ports,"total_bw":round(total_bw),
                        "uptime":uptime,"flow_count":fcount})
        return out

    def _lk_data(self):
        if not core.hasComponent("openflow_discovery"): return []
        return [{"src_dpid":dpid_to_str(l.dpid1),"src_port":l.port1,
                 "dst_dpid":dpid_to_str(l.dpid2),"dst_port":l.port2,"status":"up"}
                for l in core.openflow_discovery.adjacency]

    def _adp(self):
        if not core.hasComponent("openflow"): return set()
        return {dpid_to_str(c.dpid) for c in core.openflow.connections}
    def _swp(self):
        if not core.hasComponent("openflow_discovery"): return set()
        s=set()
        for l in core.openflow_discovery.adjacency:
            s.add((dpid_to_str(l.dpid1),l.port1))
            s.add((dpid_to_str(l.dpid2),l.port2))
        return s
    def _hwm(self):
        if not core.hasComponent("openflow"): return set()
        return {str(p.hw_addr) for c in core.openflow.connections
                for p in c.features.ports}

    def _ht(self):
        if not core.hasComponent("host_tracker"): return []
        adp=self._adp(); swp=self._swp(); hwm=self._hwm()
        now=time.time(); out=[]
        # Build dpid -> switch number map
        sw_list=sorted(adp)
        sw_num={d:i+1 for i,d in enumerate(sw_list)}
        try:
            for mac,e in core.host_tracker.entryByMAC.items():
                ms=str(mac); ds=dpid_to_str(e.dpid) if e.dpid else None; pt=e.port
                if ds not in adp: continue
                if (ds,pt) in swp: continue
                if pt in (0,65534): continue
                try:
                    if int(ms.split(":")[0],16)&1: continue
                except: continue
                if ms in ("00:00:00:00:00:00","ff:ff:ff:ff:ff:ff"): continue
                if ms in hwm: continue
                try:
                    if now-e.lastTimeSeen>HOST_TIMEOUT: continue
                except: pass
                with _hosts_lock: hi=_host_intel.get(ms,{})
                ips=[str(ip) for ip in e.ipAddrs]
                ip0=ips[0] if ips else ""
                try: hname="h"+str(int(ip0.split(".")[-1])) if ip0 else "h"+str(sw_num.get(ds,1))
                except: hname="h"+str(sw_num.get(ds,1))
                out.append({"mac":ms,"dpid":ds,"port":pt,
                            "ipAddresses":ips,
                            "ip": ip0,
                            "name": hname,
                            "sw_num": sw_num.get(ds,0),
                            "threat_score":hi.get("threat_score",0),
                            "alert_count":hi.get("alert_count",0)})
        except Exception as ex: log.warning("host_tracker error: %s"%ex)
        return out

    # ---- monitoring ---------------------------------------------------------
    def _tr(self):
        now=time.time()
        with _traffic_lock:
            return {d:round(now-t,2) for d,t in _traffic.items() if now-t<TRAFFIC_WINDOW}

    def _bwget(self):
        res={}
        with _bw_lock:
            for d,ports in _bw.items():
                res[d]={str(p):{"rate_tx":round(v.get("rate_tx",0)),
                                "rate_rx":round(v.get("rate_rx",0)),
                                "util":v.get("util",0)}
                        for p,v in ports.items()}
        return res

    def _ev(self):
        with _events_lock: return list(_events)

    def _al(self):
        with _alerts_lock: return list(_alerts)

    def _altime(self):
        return list(_alert_history)

    def _dis(self,p):
        aid=p.get("id")
        with _alerts_lock:
            for a in _alerts:
                if a["id"]==aid: a["active"]=False; return {"ok":True}
        return {"ok":False,"error":"not found"}

    def _clr(self):
        with _alerts_lock:
            for a in _alerts: a["active"]=False
        return {"ok":True}

    # PACKETS: return all stored packets, filtered only on request
    def _pk(self, qs):
        limit=int(qs.get("limit","5000"))
        since_id=int(qs.get("since_id","0"))
        pf=qs.get("protocol","").lower()
        s=qs.get("search","").lower()
        with _packets_lock: pkts=list(_packets)
        # since_id filter for incremental fetch
        if since_id>0: pkts=[p for p in pkts if p["id"]>since_id]
        if pf: pkts=[p for p in pkts if p["proto"]==pf]
        if s:
            pkts=[p for p in pkts if
                  s in p.get("src_ip","") or s in p.get("dst_ip","") or
                  s in p.get("src_mac","") or s in p.get("dst_mac","") or
                  s in p.get("info","").lower()]
        return pkts[-limit:]

    def _ps(self):
        with _pkt_stats_lock:
            s=dict(_pkt_stats)
            hl=[{"mac":m,"tx_bytes":v["tx_bytes"],"rx_bytes":v["rx_bytes"],
                 "tx_pkts":v["tx_pkts"],"rx_pkts":v["rx_pkts"]}
                for m,v in _pkt_stats["hosts"].items()]
        with _hosts_lock:
            for h in hl:
                hi=_host_intel.get(h["mac"],{})
                h["ip"]=hi.get("ip","")
        hl.sort(key=lambda x:x["tx_bytes"]+x["rx_bytes"],reverse=True)
        s["top_hosts"]=hl[:20]; del s["hosts"]
        return s

    def _rps(self):
        with _pkt_stats_lock:
            for k in ("total","arp","icmp","tcp","udp","other"): _pkt_stats[k]=0
            _pkt_stats["hosts"]={}
        return {"ok":True}

    def _clrpkts(self):
        with _packets_lock: _packets.clear()
        with _pkt_stats_lock:
            for k in ("total","arp","icmp","tcp","udp","other"): _pkt_stats[k]=0
            _pkt_stats["hosts"]={}
        return {"ok":True}

    def _fl(self,df=""):
        with _flows_lock:
            return {df:_flows.get(df,[])} if df else dict(_flows)

    def _connget(self,qs):
        now=time.time()
        state_f=qs.get("state","").upper()
        limit=int(qs.get("limit","200"))
        with _conn_lock: conns=list(_connections.values())
        for c in conns: c["duration"]=round(now-c["start"],1)
        if state_f: conns=[c for c in conns if c["state"]==state_f]
        conns.sort(key=lambda x:x["bytes"],reverse=True)
        return conns[:limit]

    def _clrconn(self):
        with _conn_lock: _connections.clear()
        return {"ok":True}

    def _talkget(self,qs):
        limit=int(qs.get("limit","30"))
        with _talkers_lock:
            t=[{"src":v["src"],"dst":v["dst"],"pkts":v["pkts"],"bytes":v["bytes"],
                "protos":list(v.get("protos",set()))} for v in _talkers.values()]
        t.sort(key=lambda x:x["bytes"],reverse=True)
        return t[:limit]

    def _portutil(self):
        res={}
        with _bw_lock:
            for dpid,ports in _bw.items():
                res[dpid]={}
                for pno,v in ports.items():
                    res[dpid][str(pno)]={
                        "util":v.get("util",0),
                        "rate_tx":round(v.get("rate_tx",0)),
                        "rate_rx":round(v.get("rate_rx",0)),
                        "tx_drop":v.get("tx_drop",0),
                        "rx_drop":v.get("rx_drop",0),
                    }
        return res

    def _swup(self):
        now=time.time()
        with _sw_uptime_lock:
            return {d:{"connected_since":ts,"uptime_secs":round(now-ts)}
                    for d,ts in _sw_uptime.items()}

    def _bwh(self,qs):
        df=qs.get("dpid",""); pf=qs.get("port","")
        with _bwh_lock:
            if df:
                d=_bwh.get(df,{})
                if pf:
                    try: pno=int(pf); return {df:{pf:list(d.get(pno,[]))}}
                    except ValueError: pass
                return {df:{str(k):list(v) for k,v in d.items()}}
            return {d:{str(k):list(v) for k,v in ports.items()}
                    for d,ports in _bwh.items()}

    def _rhi(self):
        with _hosts_lock: _host_intel.clear()
        return {"ok":True}

    def _get_cmdlog(self):
        with _cmdlog_lock: return list(_cmdlog)

    def _add_cmd(self,p):
        cmd=p.get("cmd",""); src=p.get("source","manual")
        if cmd: log_command(cmd,src)
        return {"ok":True}

    def _clr_cmd(self):
        with _cmdlog_lock: _cmdlog[:]=[]
        return {"ok":True}

    def _ctrlstats(self):
        with _ctrl_lock:
            return dict(_ctrl_stats)

    def _summary(self):
        now=time.time()
        with _alerts_lock:
            active=[a for a in _alerts if a["active"]]
            crit=len([a for a in active if a["severity"]=="critical"])
            high=len([a for a in active if a["severity"]=="high"])
            med =len([a for a in active if a["severity"]=="medium"])
            low =len([a for a in active if a["severity"]=="low"])
            by_type={}
            for a in _alerts:
                by_type[a["type"]]=by_type.get(a["type"],0)+a["count"]
        with _pkt_stats_lock: pkt_total=_pkt_stats["total"]
        with _bw_lock:
            total_bw=sum(v.get("rate_tx",0)+v.get("rate_rx",0)
                         for ports in _bw.values() for v in ports.values())
        with _conn_lock: active_conns=len(_connections)
        sw_count=len(self._sw()); host_count=len(self._ht())
        hi=_host_intel_json(); top_threat=hi[:5] if hi else []
        with _ctrl_lock: ctrl=dict(_ctrl_stats)
        return {
            "ts":round(now,2),"uptime":round(now-_start_time),
            "switches":sw_count,"hosts":host_count,
            "alerts":{"active":len(active),"critical":crit,"high":high,"medium":med,"low":low},
            "packets_total":pkt_total,"total_bandwidth":round(total_bw),
            "active_connections":active_conns,"alert_by_type":by_type,
            "top_threat_hosts":top_threat,"ctrl_packetin":ctrl["packetin_count"],
            "ctrl_total_bytes":ctrl["total_bytes"],
        }

    # ---- flow management ----------------------------------------------------
    def _find_conn(self,ds):
        if not core.hasComponent("openflow"): return None
        return next((c for c in core.openflow.connections
                     if dpid_to_str(c.dpid)==ds),None)

    def _dfl(self,p):
        conn=self._find_conn(p.get("dpid",""))
        if not conn: return {"ok":False,"error":"not connected"}
        msg=of.ofp_flow_mod(command=of.OFPFC_DELETE); msg.match=of.ofp_match()
        try:
            if p.get("in_port"): msg.match.in_port=int(p["in_port"])
            if p.get("dl_src"):  msg.match.dl_src=EthAddr(str(p["dl_src"]))
            if p.get("nw_src"):  msg.match.nw_src=IPAddr(str(p["nw_src"]))
            if p.get("nw_dst"):  msg.match.nw_dst=IPAddr(str(p["nw_dst"]))
        except Exception as e: return {"ok":False,"error":str(e)}
        conn.send(msg)
        _add_event("Flow deleted on %s"%dpid_to_str(conn.dpid),"info")
        log_command("del-flows %s"%dpid_to_str(conn.dpid),"operator")
        return {"ok":True}

    def _addfl(self,p):
        conn=self._find_conn(p.get("dpid",""))
        if not conn: return {"ok":False,"error":"not connected"}
        msg=of.ofp_flow_mod()
        msg.priority=int(p.get("priority",100))
        msg.idle_timeout=int(p.get("idle_timeout",0))
        msg.hard_timeout=int(p.get("hard_timeout",0))
        msg.match=of.ofp_match()
        try:
            if p.get("in_port"):  msg.match.in_port=int(p["in_port"])
            if p.get("dl_src"):   msg.match.dl_src=EthAddr(str(p["dl_src"]))
            if p.get("dl_dst"):   msg.match.dl_dst=EthAddr(str(p["dl_dst"]))
            if p.get("nw_src"):   msg.match.nw_src=IPAddr(str(p["nw_src"]))
            if p.get("nw_dst"):   msg.match.nw_dst=IPAddr(str(p["nw_dst"]))
            if p.get("nw_proto"): msg.match.nw_proto=int(p["nw_proto"])
            if p.get("tp_dst"):   msg.match.tp_dst=int(p["tp_dst"])
        except Exception as e: return {"ok":False,"error":str(e)}
        ap=p.get("action_port")
        if ap and ap!="drop": msg.actions.append(of.ofp_action_output(port=int(ap)))
        conn.send(msg)
        _add_event("Flow added on %s (pri %d)"%(dpid_to_str(conn.dpid),msg.priority),"info")
        log_command("add-flow %s pri=%d"%(dpid_to_str(conn.dpid),msg.priority),"operator")
        return {"ok":True}

    def _qos(self,p):
        conn=self._find_conn(p.get("dpid",""))
        if not conn: return {"ok":False,"error":"not connected"}
        dscp=int(p.get("dscp",0)); queue_id=int(p.get("queue_id",-1))
        out_port=int(p.get("out_port",of.OFPP_NORMAL))
        msg=of.ofp_flow_mod()
        msg.priority=int(p.get("priority",200))
        msg.idle_timeout=int(p.get("idle_timeout",0))
        msg.hard_timeout=int(p.get("hard_timeout",0))
        msg.match=of.ofp_match()
        m=p.get("match",{})
        try:
            if m.get("nw_src"):   msg.match.nw_src=IPAddr(m["nw_src"])
            if m.get("nw_dst"):   msg.match.nw_dst=IPAddr(m["nw_dst"])
            if m.get("nw_proto"): msg.match.nw_proto=int(m["nw_proto"])
            if m.get("tp_dst"):   msg.match.tp_dst=int(m["tp_dst"])
        except Exception as e: return {"ok":False,"error":str(e)}
        if dscp>0: msg.actions.append(of.ofp_action_set_nw_tos(nw_tos=dscp<<2))
        if queue_id>=0: msg.actions.append(of.ofp_action_enqueue(port=out_port,queue_id=queue_id))
        else: msg.actions.append(of.ofp_action_output(port=out_port))
        conn.send(msg)
        _add_event("QoS on %s DSCP=%d q=%d"%(dpid_to_str(conn.dpid),dscp,queue_id),"info")
        log_command("qos-set %s dscp=%d"%(dpid_to_str(conn.dpid),dscp),"operator")
        return {"ok":True}

    def _block_host(self,p):
        """Install drop rules for a host IP on all switches."""
        ip=p.get("ip","")
        if not ip: return {"ok":False,"error":"ip required"}
        count=0
        if core.hasComponent("openflow"):
            for conn in core.openflow.connections:
                msg=of.ofp_flow_mod()
                msg.priority=500; msg.match=of.ofp_match()
                try: msg.match.nw_src=IPAddr(ip)
                except: continue
                msg.match.dl_type=0x0800
                # empty actions = DROP
                conn.send(msg)
                count+=1
        _add_event("Host %s blocked on %d switches"%(ip,count),"warn")
        log_command("block-host %s on %d switches"%(ip,count),"operator")
        return {"ok":True,"switches_affected":count}

    def _ping(self,p):
        src=p.get("src",""); dst=p.get("dst","")
        if not src or not dst: return {"ok":False,"error":"src and dst required"}
        log_command("ping %s -> %s"%(src,dst),"operator")
        _add_event("Ping: %s -> %s"%(src,dst),"info")
        return {"ok":True,"message":"Ping %s -> %s logged"%(src,dst)}

    def _run_test(self,qs):
        test_type=qs.get("type","ping")
        src=qs.get("src","h1"); dst=qs.get("dst","h2"); extra=qs.get("extra","")
        port=extra or "80"
        # Build command dict -- all use host names (h1/h2) directly as typed by user
        cmds={
            "ping":         ("ping -c 4 %s"%dst, None),
            "ping_flood":   ("ping -c 100 -i 0.01 %s"%dst, None),
            "traceroute":   ("traceroute %s"%dst, None),
            "iperf_tcp":    ("iperf -c %s -t 10 -i 1"%dst, ["%s iperf -s &"%dst]),
            "iperf_udp":    ("iperf -c %s -u -b 10M -t 10 -i 1"%dst, ["%s iperf -s &"%dst]),
            "iperf_bidir":  ("iperf -c %s -d -t 10"%dst, ["%s iperf -s &"%dst]),
            "hping_syn":    ("hping3 -S -p %s --flood %s"%(port,dst), None),
            "hping_icmp":   ("hping3 --icmp -c 100 %s"%dst, None),
            "hping_udp":    ("hping3 --udp -p %s --flood %s"%(port,dst), None),
            "hping_rand":   ("hping3 --rand-source -S -p %s --flood %s"%(port,dst), None),
            "hping_land":   ("hping3 -S -p %s -a %s %s"%(port,dst,dst), None),
            "hping_rst":    ("hping3 -R -p %s --flood %s"%(port,dst), None),
            "hping_xmas":   ("hping3 -F -U -P -p %s %s"%(port,dst), None),
            "nmap":         ("nmap -sV -p 1-1024 %s"%dst, None),
            "nmap_ping":    ("nmap -sn %s"%dst, None),
            "port_sweep":   ("nmap -p 1-1024 -T4 %s"%dst, None),
            "os_detect":    ("nmap -O %s"%dst, None),
            "ssh_scan":     ("nmap -p 22 -sV %s"%dst, None),
            "arp_scan":     ("arp-scan --localnet", None),
            "arping":       ("arping -c 4 %s"%dst, None),
            "dns":          ("nslookup %s"%(extra or "google.com"), None),
            "wget":         ("wget -q -O /dev/null http://%s/"%dst, None),
            "http_server":  ("python3 -m http.server %s &"%(extra or "8080"), None),
            "http_client":  ("curl -s -o /dev/null -w '%%{http_code}' http://%s:%s/"%(dst,extra or "8080"), None),
            "tcp_connect":  ("nc -zvw3 %s %s"%(dst,port), None),
            "udp_flood":    ("hping3 --udp -p %s --flood %s"%(port,dst), None),
            "slowloris":    ("hping3 -S --flood -p %s %s"%(extra or "8080",dst),
                             ["%s python3 -m http.server %s &"%(dst,extra or "8080")]),
            "packet_loss":  ("ping -c 50 -i 0.1 %s"%dst, None),
            "mtr":          ("mtr --report --report-cycles 5 %s"%dst, None),
        }
        entry=cmds.get(test_type,("%s %s"%(test_type,dst),None))
        cmd,setup=entry
        # full_cmd: just "src cmd" -- no "mininet>" prefix, user pastes directly
        full="%s %s"%(src,cmd)
        setup_cmds=setup  # list of setup commands or None
        log_command("mininet> "+full,"test-tool")
        _add_event("Test [%s]: %s -> %s"%(test_type,src,dst),"info")
        result={"ok":True,"cmd":cmd,"full_cmd":full,
                "note":"Paste in Mininet terminal after 'mininet> ' prompt"}
        if setup_cmds:
            result["setup_cmds"]=setup_cmds
            result["note"]="Run setup commands first, then run the main command"
        return result


def launch():
    def _start():
        if not core.hasComponent("WebServer"):
            log.error("web.webcore must be loaded first"); return
        TrafficMonitor()
        core.WebServer.set_handler("/topo/",TopologyHandler,{})
        log.info("topology_api ready  http://0.0.0.0:8000/topo/all")
        _add_event("topology_api v3 started","info")
    core.call_when_ready(_start,["WebServer","openflow"])
