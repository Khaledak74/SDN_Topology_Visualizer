// App.js  —  SDN Topology Visualizer  v3  (Full Monitoring Suite)
// 15 tabs: DASHBOARD · TOPOLOGY · ALERTS · THREATS · PACKETS
//          SESSIONS · HOSTS · FLOWS · QoS · GRAPHS · TESTS · CMDLOG · REPORTS · EXPORT
import { useState, useEffect, useRef, useCallback } from "react";

// ── palette ──────────────────────────────────────────────────────────────────
const C={
  bg:"#0d1117",panel:"#161b22",border:"#30363d",text:"#e6edf3",
  muted:"#8b949e",accent:"#58a6ff",green:"#3fb950",orange:"#f0883e",
  red:"#f85149",purple:"#bc8cff",yellow:"#e3b341",teal:"#39d353",
  navy:"#1f2937",card:"#1c2128",dark:"#010409",cyan:"#79c0ff",pink:"#ff7b72",
};
const SEV={critical:"#f85149",high:"#f0883e",medium:"#e3b341",low:"#58a6ff"};
const PROTO={arp:"#bc8cff",icmp:"#3fb950",tcp:"#58a6ff",udp:"#f0883e",other:"#8b949e"};
const STABLE=4;
const SVG_W=920, SVG_H=580;

// ── formatters ────────────────────────────────────────────────────────────────
const fB=b=>b>1e9?(b/1e9).toFixed(2)+"GB/s":b>1e6?(b/1e6).toFixed(2)+"MB/s":b>1e3?(b/1e3).toFixed(1)+"KB/s":b+"B/s";
const fS=b=>b>1e9?(b/1e9).toFixed(2)+" GB":b>1e6?(b/1e6).toFixed(2)+" MB":b>1e3?(b/1e3).toFixed(1)+" KB":b+" B";
const fT=ts=>{const d=new Date(ts*1000);return d.toTimeString().slice(0,8)+"."+String(d.getMilliseconds()).padStart(3,"0");};
const fAge=s=>{if(!s||s<1)return"0s";if(s<60)return s+"s";if(s<3600)return Math.floor(s/60)+"m"+Math.floor(s%60)+"s";return Math.floor(s/3600)+"h"+Math.floor((s%3600)/60)+"m";};
const nId=(a,b)=>[a,b].sort().join("||");
const pct=(v,mx)=>Math.min(100,mx?Math.round(v/mx*100):0);

// ── shared styles ─────────────────────────────────────────────────────────────
const S={
  card:{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,padding:12},
  title:{color:C.muted,fontSize:11,fontWeight:700,letterSpacing:1,textTransform:"uppercase",
    marginBottom:8,paddingBottom:6,borderBottom:`1px solid ${C.border}`},
  btn:{background:C.navy,color:C.text,border:"none",borderRadius:6,padding:"6px 14px",
    fontSize:12,cursor:"pointer",fontFamily:"inherit"},
  inp:{background:C.dark,color:C.text,border:`1px solid ${C.border}`,borderRadius:6,
    padding:"5px 10px",fontSize:12,fontFamily:"monospace",outline:"none"},
  pill:{borderRadius:10,fontSize:10,fontWeight:700,padding:"1px 7px",display:"inline-block"},
  row:{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"},
  col:{display:"flex",flexDirection:"column",gap:8},
};

// ── micro components ─────────────────────────────────────────────────────────
function Badge({n,color=C.red}){
  if(!n||n<1)return null;
  return<span style={{background:color,color:"#fff",borderRadius:10,fontSize:10,fontWeight:700,
    padding:"1px 6px",marginLeft:5,minWidth:18,textAlign:"center",display:"inline-block"}}>
    {n>999?"999+":n>99?"99+":n}</span>;
}
function Pill({label,color}){
  return<span style={{...S.pill,background:(color||C.muted)+"25",color:color||C.muted}}>{label}</span>;
}
function KPI({label,value,color,sub}){
  return(
    <div style={{...S.card,flex:1,minWidth:110,textAlign:"center",padding:"10px 8px"}}>
      <div style={{color:color||C.accent,fontSize:24,fontWeight:800,fontFamily:"monospace"}}>{value}</div>
      <div style={{color:C.muted,fontSize:10,marginTop:2}}>{label}</div>
      {sub&&<div style={{color:C.muted,fontSize:9,marginTop:2}}>{sub}</div>}
    </div>
  );
}
function Bar({value,max,color,height=6}){
  const w=pct(value,max||value||1);
  return<div style={{height,background:C.border,borderRadius:3}}>
    <div style={{height,width:w+"%",background:color||C.accent,borderRadius:3,transition:"width .4s"}}/>
  </div>;
}
function SparkLine({data,color,height=40,width=150}){
  if(!data||data.length<2)return<div style={{width,height,color:C.muted,fontSize:9,display:"flex",alignItems:"center",justifyContent:"center"}}>no data</div>;
  const max=Math.max(...data,1);
  const pts=data.map((v,i)=>`${(i/(data.length-1))*width},${height-2-(v/max)*(height-4)}`).join(" ");
  return<svg width={width} height={height}>
    <polyline points={pts} fill="none" stroke={color||C.accent} strokeWidth={1.5}/>
  </svg>;
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App(){
  // topology
  const [raw,setRaw]=useState({switches:[],links:[],hosts:[]});
  const [connected,setConn]=useState(false);
  const [traffic,setTraffic]=useState({});
  const [bw,setBw]=useState({});
  const [bwh,setBwh]=useState({});
  // monitoring
  const [events,setEvents]=useState([]);
  const [alerts,setAlerts]=useState([]);
  const [allPackets,setAllPackets]=useState([]);  // persistent full list
  const [lastPktId,setLastPktId]=useState(0);
  const [pktStats,setPktStats]=useState({total:0,arp:0,icmp:0,tcp:0,udp:0,other:0,top_hosts:[]});
  const [flows,setFlows]=useState({});
  const [connections,setConnections]=useState([]);
  const [talkers,setTalkers]=useState([]);
  const [hostIntel,setHostIntel]=useState([]);
  const [alertTimeline,setAlertTimeline]=useState([]);
  const [portUtil,setPortUtil]=useState({});
  const [swUptime,setSwUptime]=useState({});
  const [summary,setSummary]=useState(null);
  const [cmdlog,setCmdlog]=useState([]);
  const [ctrlStats,setCtrlStats]=useState({packetin_count:0,total_bytes:0,per_dpid:{}});
  // ui
  const [tab,setTab]=useState("DASHBOARD");
  const [unreadAlerts,setUnreadAlerts]=useState(0);
  const [unreadEvents,setUnreadEvents]=useState(0);
  const [unreadCmds,setUnreadCmds]=useState(0);
  // topology ui
  const [zoom,setZoom]=useState(1);
  const [pan,setPan]=useState({x:0,y:0});
  const [isPanning,setIsPanning]=useState(false);
  const panStart=useRef(null);
  const [pathMode,setPathMode]=useState(false);
  const [pathSrc,setPathSrc]=useState(null);
  const [activePath,setActivePath]=useState([]);
  const [selected,setSelected]=useState(null);
  const [attackViz,setAttackViz]=useState(null); // highlighted attack path
  // packets ui
  const [pktFilter,setPktFilter]=useState({proto:"",search:""});
  const [pktPaused,setPktPaused]=useState(false);
  const [pktExpanded,setPktExpanded]=useState(null);
  const [pktPageSize,setPktPageSize]=useState(1000);
  // flows ui
  const [flowDpid,setFlowDpid]=useState("");
  const [showAddFlow,setShowAddFlow]=useState(false);
  const [newFlow,setNewFlow]=useState({dpid:"",priority:"100",in_port:"",dl_src:"",dl_dst:"",nw_src:"",nw_dst:"",nw_proto:"",tp_dst:"",action_port:"",idle_timeout:"0",hard_timeout:"0"});
  // qos ui
  const [qosForm,setQosForm]=useState({dpid:"",nw_src:"",nw_dst:"",nw_proto:"6",tp_dst:"",dscp:"46",queue_id:"-1",priority:"200",out_port:"65533",idle_timeout:"0"});
  const [qosMsg,setQosMsg]=useState("");
  const [qosRules,setQosRules]=useState([]);
  // graphs ui
  const [graphDpid,setGraphDpid]=useState("");
  const [graphPort,setGraphPort]=useState("");
  // tests ui
  const [testSrc,setTestSrc]=useState("");
  const [testDst,setTestDst]=useState("");
  const [testType,setTestType]=useState("ping");
  const [testExtra,setTestExtra]=useState("");
  const [testResult,setTestResult]=useState(null);
  const [testHistory,setTestHistory]=useState([]);
  const [simSel,setSimSel]=useState(null);
  const [cidr,setCidr]=useState("10.0.0.0/24");
  const [calcResult,setCalcResult]=useState(null);
  // reports
  const [reportRange,setReportRange]=useState(3600);
  const [reportText,setReportText]=useState("");
  // hosts
  const [hostFilter,setHostFilter]=useState("");
  const [connFilter,setConnFilter]=useState("");
  // block host
  const [blockIp,setBlockIp]=useState("");
  const [blockMsg,setBlockMsg]=useState("");
  // incident notes
  const [incidentNotes,setIncidentNotes]=useState({});

  const downRef=useRef({});
  const prevLinksRef=useRef(new Map());
  const stablePollRef=useRef(0);
  const posRef=useRef({});
  const svgRef=useRef(null);
  const [svgData,setSvgData]=useState(null);
  const svgContainerRef=useRef(null);
  const prevNodeRef=useRef("");
  const lastAlertRef=useRef(0);
  const lastCmdRef=useRef(0);

  // ── layout calc ─────────────────────────────────────────────────────────────
  const buildLayout=useCallback((sws,lks,hosts)=>{
    const pos={};
    if(!sws.length)return pos;
    const deg={};
    sws.forEach(s=>{deg[s.dpid]=0;});
    lks.forEach(l=>{deg[l.src_dpid]=(deg[l.src_dpid]||0)+1;deg[l.dst_dpid]=(deg[l.dst_dpid]||0)+1;});
    const withHosts=new Set(hosts.map(h=>h.dpid));
    const maxDeg=Math.max(...Object.values(deg),1);
    const core2=[],agg=[],acc=[];
    sws.forEach(s=>{
      if(withHosts.has(s.dpid))acc.push(s.dpid);
      else if(deg[s.dpid]===maxDeg)core2.push(s.dpid);
      else agg.push(s.dpid);
    });
    const row=(ids,y)=>{const g=SVG_W/(ids.length+1);ids.forEach((id,i)=>{pos[id]={x:g*(i+1),y};});};
    if(core2.length)row(core2,90);
    if(agg.length)row(agg,220);
    if(acc.length)row(acc,360);
    const byParent={};
    hosts.forEach(h=>{if(!byParent[h.dpid])byParent[h.dpid]=[];byParent[h.dpid].push(h.mac);});
    Object.entries(byParent).forEach(([d,macs])=>{
      const sx=pos[d]?.x||SVG_W/2;
      const g=Math.min(70,150/Math.max(macs.length,1));
      macs.forEach((m,i)=>{pos[m]={x:sx+(i-(macs.length-1)/2)*g,y:490};});
    });
    return pos;
  },[]);

  // ── API helper ───────────────────────────────────────────────────────────────
  const api=async(url,setter,transform)=>{
    try{const r=await fetch(url);if(r.ok){const d=await r.json();setter(transform?transform(d):d);}}catch(_){}
  };

  // ── incremental packet fetch (never loses data) ──────────────────────────────
  const fetchPackets=useCallback(async()=>{
    if(pktPaused)return;
    try{
      const r=await fetch(`/topo/packets?limit=5000&since_id=${lastPktId}`);
      if(!r.ok)return;
      const newPkts=await r.json();
      if(!newPkts.length)return;
      setAllPackets(prev=>{
        const combined=[...prev,...newPkts];
        // keep last 10000 in memory
        return combined.slice(-10000);
      });
      setLastPktId(newPkts[newPkts.length-1].id);
    }catch(_){}
  },[pktPaused,lastPktId]);

  // ── topology poll ────────────────────────────────────────────────────────────
  // ── SVG capture effect (saves topology for export from any tab) ─────────────
  useEffect(()=>{
    if(tab!=="TOPOLOGY")return;
    const timer=setTimeout(()=>{
      if(!svgRef.current)return;
      try{
        const clone=svgRef.current.cloneNode(true);
        clone.setAttribute("xmlns","http://www.w3.org/2000/svg");
        clone.setAttribute("style","background:#0d1117");
        setSvgData(new XMLSerializer().serializeToString(clone));
      }catch(_){}
    },300);
    return()=>clearTimeout(timer);
  },[tab,raw.switches,raw.links,raw.hosts]);

  const pollTopo=useCallback(async()=>{
    try{
      const r=await fetch("/topo/all");
      if(!r.ok){setConn(false);return;}
      const d=await r.json();setConn(true);
      const curr=new Map();
      (d.links||[]).forEach(l=>{curr.set(nId(l.src_dpid+":"+l.src_port,l.dst_dpid+":"+l.dst_port),l);});
      const prev=prevLinksRef.current;
      if(curr.size===0)stablePollRef.current=0;
      else if(prev.size===0)stablePollRef.current=1;
      else if(curr.size>=prev.size)stablePollRef.current=Math.min(stablePollRef.current+1,STABLE+1);
      else if(stablePollRef.current>=STABLE){
        prev.forEach((lnk,id)=>{
          if(!curr.has(id)&&!downRef.current[id]){
            downRef.current[id]={...lnk,status:"down"};
          }
        });
      }
      Object.keys(downRef.current).forEach(id=>{if(curr.has(id))delete downRef.current[id];});
      prevLinksRef.current=curr;setRaw(d);
    }catch(e){setConn(false);}
  },[]);

  const pollAlerts=useCallback(async()=>{
    try{
      const r=await fetch("/topo/alerts");if(!r.ok)return;
      const d=await r.json();setAlerts(d);
      const ac=d.filter(a=>a.active&&(a.severity==="critical"||a.severity==="high")).length;
      if(ac>lastAlertRef.current)setUnreadAlerts(u=>u+(ac-lastAlertRef.current));
      lastAlertRef.current=ac;
    }catch(_){}
  },[]);

  const pollCmdlog=useCallback(async()=>{
    try{
      const r=await fetch("/topo/cmdlog");if(!r.ok)return;
      const d=await r.json();
      setCmdlog(d);
      if(d.length>lastCmdRef.current)setUnreadCmds(u=>u+(d.length-lastCmdRef.current));
      lastCmdRef.current=d.length;
    }catch(_){}
  },[]);

  // ── main poll loop ────────────────────────────────────────────────────────────
  useEffect(()=>{
    pollTopo();pollAlerts();pollCmdlog();
    api("/topo/summary",setSummary);
    api("/topo/traffic",setTraffic);
    api("/topo/bandwidth",setBw);
    api("/topo/events",setEvents);

    const fast=setInterval(()=>{
      pollTopo();pollAlerts();
      api("/topo/traffic",setTraffic);
      api("/topo/bandwidth",setBw);
      api("/topo/summary",setSummary);
      api("/topo/events",setEvents);
      fetchPackets();
      api("/topo/packetstats",setPktStats);
    },2000);
    const slow=setInterval(()=>{
      api("/topo/flows",setFlows);
      api("/topo/connections?limit=300",setConnections);
      api("/topo/talkers?limit=50",setTalkers);
      api("/topo/hostintel",setHostIntel);
      api("/topo/alerttimeline",setAlertTimeline);
      api("/topo/portutil",setPortUtil);
      api("/topo/swuptime",setSwUptime);
      api("/topo/bwhistory",setBwh);
      api("/topo/ctrlstats",setCtrlStats);
      pollCmdlog();
    },4000);
    return()=>{clearInterval(fast);clearInterval(slow);};
  },[pollTopo,pollAlerts,pollCmdlog,fetchPackets]);

  // layout recalc only when nodes change
  useEffect(()=>{
    const nk=(raw.switches||[]).map(s=>s.dpid).join(",")+"|"+(raw.hosts||[]).map(h=>h.mac).join(",");
    if(nk!==prevNodeRef.current){
      prevNodeRef.current=nk;
      Object.assign(posRef.current,buildLayout(raw.switches||[],raw.links||[],raw.hosts||[]));
    }
  },[raw,buildLayout]);

  // ── BFS path ─────────────────────────────────────────────────────────────────
  const bfsPath=(src,dst)=>{
    const adj={};
    [...(raw.switches||[]).map(s=>s.dpid),...(raw.hosts||[]).map(h=>h.mac)].forEach(n=>{adj[n]=new Set();});
    const edges=[...(raw.links||[]),...Object.values(downRef.current)];
    edges.filter(e=>e.status!=="down").forEach(e=>{
      adj[e.src_dpid]&&adj[e.src_dpid].add(e.dst_dpid);
      adj[e.dst_dpid]&&adj[e.dst_dpid].add(e.src_dpid);
    });
    (raw.hosts||[]).forEach(h=>{
      adj[h.mac]=adj[h.mac]||new Set();adj[h.dpid]=adj[h.dpid]||new Set();
      adj[h.mac].add(h.dpid);adj[h.dpid].add(h.mac);
    });
    const q=[[src]];const vis=new Set([src]);
    while(q.length){
      const p=q.shift();const c=p[p.length-1];
      if(c===dst)return p;
      (adj[c]||new Set()).forEach(n=>{if(!vis.has(n)){vis.add(n);q.push([...p,n]);}});
    }
    return[];
  };

  // ── derived values ────────────────────────────────────────────────────────────
  const swBwTotal={};
  Object.entries(bw).forEach(([d,ports])=>{
    swBwTotal[d]=Object.values(ports).reduce((s,v)=>s+v.rate_tx+v.rate_rx,0);
  });
  const maxSwBw=Math.max(...Object.values(swBwTotal),1);
  const heatColor=d=>{const r=(swBwTotal[d]||0)/maxSwBw;return r>.7?C.red:r>.4?C.orange:r>.15?C.yellow:C.green;};
  const now2=Date.now()/1000;
  const edges=[...(raw.links||[]),...Object.values(downRef.current)];
  const activeAlerts=alerts.filter(a=>a.active);

  // ── filtered packets ─────────────────────────────────────────────────────────
  const filteredPkts=allPackets.filter(p=>{
    if(pktFilter.proto&&p.proto!==pktFilter.proto)return false;
    if(pktFilter.search){
      const s=pktFilter.search.toLowerCase();
      return p.src_ip?.includes(s)||p.dst_ip?.includes(s)||
             p.src_mac?.includes(s)||p.dst_mac?.includes(s)||
             p.info?.toLowerCase().includes(s)||
             String(p.sp).includes(s)||String(p.dp).includes(s);
    }
    return true;
  });

  // ── zoom/pan handlers ────────────────────────────────────────────────────────
  const onWheel=e=>{
    e.preventDefault();
    setZoom(z=>Math.max(0.3,Math.min(3,z-(e.deltaY*0.001))));
  };
  const onMouseDown=e=>{
    if(e.button===1||(e.button===0&&e.altKey)){
      setIsPanning(true);
      panStart.current={x:e.clientX-pan.x,y:e.clientY-pan.y};
    }
  };
  const onMouseMove=e=>{
    if(isPanning&&panStart.current){
      setPan({x:e.clientX-panStart.current.x,y:e.clientY-panStart.current.y});
    }
  };
  const onMouseUp=()=>{setIsPanning(false);panStart.current=null;};

  // ──────────────────────────────────────────────────────────────────────────────
  // TAB: TOPOLOGY canvas
  // ──────────────────────────────────────────────────────────────────────────────
  const handleNodeClick=id=>{
    if(pathMode){
      if(!pathSrc){setPathSrc(id);return;}
      setActivePath(bfsPath(pathSrc,id));setPathMode(false);setPathSrc(null);return;
    }
    setSelected(id);
  };

  const renderCanvas=()=>{
    const pos=posRef.current;
    const sw=raw.switches||[];const hosts=raw.hosts||[];
    const swNums={};
    [...sw].sort((a,b)=>a.dpid.localeCompare(b.dpid)).forEach((s,i)=>{swNums[s.dpid]=i+1;});
    return(
      <div ref={svgContainerRef} style={{overflow:"hidden",borderRadius:8,border:`1px solid ${C.border}`,background:C.bg,cursor:isPanning?"grabbing":"default",userSelect:"none"}}
        onWheel={onWheel} onMouseDown={onMouseDown} onMouseMove={onMouseMove} onMouseUp={onMouseUp} onMouseLeave={onMouseUp}>
        <svg ref={svgRef} width={SVG_W} height={SVG_H} style={{display:"block",transform:`scale(${zoom}) translate(${pan.x/zoom}px,${pan.y/zoom}px)`,transformOrigin:"0 0",transition:isPanning?"none":"transform .1s"}}>
          <defs>
            <filter id="glow"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
            <filter id="glow2"><feGaussianBlur stdDeviation="7" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
          </defs>
          {/* Layer labels */}
          {["CORE","AGGREGATION","ACCESS","HOSTS"].map((l,i)=>(
            <text key={l} x={10} y={[95,225,365,495][i]} fontSize={8} fill={C.muted} fontFamily="monospace" opacity={.4}>{l}</text>
          ))}
          {/* host—switch lines */}
          {hosts.map((h,i)=>{const a=pos[h.mac],b=pos[h.dpid];if(!a||!b)return null;
            return<line key={"hl"+i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={C.border} strokeWidth={1} opacity={.4}/>;
          })}
          {/* switch—switch links */}
          {edges.map((l,i)=>{
            const a=pos[l.src_dpid],b=pos[l.dst_dpid];if(!a||!b)return null;
            const isDown=l.status==="down";
            const inPath=activePath.length>1&&activePath.includes(l.src_dpid)&&activePath.includes(l.dst_dpid);
            const inAttack=attackViz&&attackViz.includes(l.src_dpid)&&attackViz.includes(l.dst_dpid);
            const hasTraffic=traffic[l.src_dpid]&&(now2-traffic[l.src_dpid])<5;
            const bwVal=(bw[l.src_dpid]?.[l.src_port]?.rate_tx||0)+(bw[l.src_dpid]?.[l.src_port]?.rate_rx||0);
            const mx=(a.x+b.x)/2,my=(a.y+b.y)/2;
            const stroke=inAttack?C.red:isDown?C.red:inPath?C.yellow:hasTraffic?C.cyan:C.border;
            return(<g key={"lk"+i}>
              {(inPath||inAttack)&&<line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={inAttack?C.red:C.yellow} strokeWidth={8} opacity={.2} filter="url(#glow2)"/>}
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={stroke}
                strokeWidth={inPath||inAttack?3:hasTraffic?2:1.5}
                strokeDasharray={isDown?"6,3":"none"}
                filter={hasTraffic&&!isDown?"url(#glow)":"none"}
                style={{cursor:"pointer"}} onClick={()=>setSelected({type:"link",...l})}/>
              {bwVal>500&&!isDown&&<text x={mx} y={my-5} fontSize={8} fill={C.muted} textAnchor="middle" fontFamily="monospace">{fB(bwVal)}</text>}
              {isDown&&<text x={mx} y={my-5} fontSize={9} fill={C.red} textAnchor="middle" fontWeight={700}>DOWN</text>}
            </g>);
          })}
          {/* switches */}
          {sw.map(s=>{
            const p=pos[s.dpid];if(!p)return null;
            const hc=heatColor(s.dpid);
            const isSel=selected===s.dpid||selected?.dpid===s.dpid;
            const num=swNums[s.dpid]||"?";
            return(<g key={s.dpid} style={{cursor:"pointer"}} onClick={()=>handleNodeClick(s.dpid)}>
              {isSel&&<rect x={p.x-28} y={p.y-22} width={56} height={44} rx={8} fill="none" stroke={C.accent} strokeWidth={2}/>}
              <rect x={p.x-22} y={p.y-16} width={44} height={32} rx={5} fill={C.navy} stroke={hc} strokeWidth={2}/>
              <text x={p.x} y={p.y-2} textAnchor="middle" fontSize={10} fill={C.text} fontFamily="monospace" fontWeight={700}>s{num}</text>
              <text x={p.x} y={p.y+10} textAnchor="middle" fontSize={7} fill={C.muted} fontFamily="monospace">{s.dpid.slice(-4)}</text>
              <circle cx={p.x+18} cy={p.y-14} r={4} fill={hc}/>
            </g>);
          })}
          {/* hosts */}
          {hosts.map(h=>{
            const p=pos[h.mac];if(!p)return null;
            const isSel=selected===h.mac;
            const hi=hostIntel.find(x=>x.mac===h.mac);
            const ts=hi?.threat_score||0;
            const tc=ts>60?C.red:ts>30?C.orange:ts>10?C.yellow:C.green;
            const ip=h.ipAddresses?.[0]||"";
            const label=ip?ip.split(".").slice(-2).join("."):h.mac.slice(-5);
            return(<g key={h.mac} style={{cursor:"pointer"}} onClick={()=>handleNodeClick(h.mac)}>
              {isSel&&<circle cx={p.x} cy={p.y} r={18} fill="none" stroke={C.accent} strokeWidth={2}/>}
              {ts>30&&<circle cx={p.x} cy={p.y} r={14} fill={tc} opacity={.15} filter="url(#glow)"/>}
              <circle cx={p.x} cy={p.y} r={11} fill={C.dark} stroke={tc} strokeWidth={1.5}/>
              <text x={p.x} y={p.y+4} textAnchor="middle" fontSize={7} fill={tc} fontFamily="monospace">{label}</text>
            </g>);
          })}
          {pathSrc&&posRef.current[pathSrc]&&
            <circle cx={posRef.current[pathSrc].x} cy={posRef.current[pathSrc].y} r={24} fill="none" stroke={C.yellow} strokeWidth={2} strokeDasharray="5,3"/>}
        </svg>
      </div>
    );
  };

  // ── TAB: TOPOLOGY ──────────────────────────────────────────────────────────
  const renderTopo=()=>{
    const downCount=Object.keys(downRef.current).length;
    const swNums={};
    [...(raw.switches||[])].sort((a,b)=>a.dpid.localeCompare(b.dpid)).forEach((s,i)=>{swNums[s.dpid]=i+1;});
    return(
      <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
        <div style={{flex:"0 0 auto"}}>
          {renderCanvas()}
          {/* zoom controls */}
          <div style={{display:"flex",gap:6,marginTop:8,alignItems:"center",flexWrap:"wrap"}}>
            <button onClick={()=>setZoom(z=>Math.min(3,z+0.2))} style={{...S.btn,padding:"4px 12px",fontSize:14}}>+</button>
            <button onClick={()=>setZoom(z=>Math.max(0.3,z-0.2))} style={{...S.btn,padding:"4px 12px",fontSize:14}}>-</button>
            <button onClick={()=>{setZoom(1);setPan({x:0,y:0});}} style={{...S.btn,fontSize:11}}>Reset View</button>
            <span style={{color:C.muted,fontSize:11}}>{Math.round(zoom*100)}%  (scroll/alt+drag to zoom/pan)</span>
            <button onClick={()=>{setPathMode(m=>!m);setPathSrc(null);setActivePath([]);}}
              style={{...S.btn,background:pathMode?C.yellow:C.navy,color:pathMode?"#000":C.text}}>
              {pathMode?"Cancel Path":"Find Path"}
            </button>
            {pathMode&&<span style={{color:C.yellow,fontSize:11}}>{pathSrc?"Click destination":"Click source node"}</span>}
            {activePath.length>0&&<button onClick={()=>setActivePath([])} style={S.btn}>Clear Path</button>}
          </div>
        </div>
        <div style={{flex:1,minWidth:220,...S.col}}>
          <div style={S.card}>
            <div style={S.title}>Network Stats</div>
            {[["Switches",(raw.switches||[]).length,C.accent],["Hosts",(raw.hosts||[]).length,C.green],
              ["Links UP",edges.filter(e=>e.status!=="down").length,C.green],
              ["Links DOWN",downCount,downCount>0?C.red:C.muted],
              ["Active Alerts",activeAlerts.length,activeAlerts.length>0?C.red:C.green],
              ["Packets",pktStats.total,C.purple],
              ["Controller PacketIn",(summary?.ctrl_packetin||0),C.cyan]].map(([l,v,c])=>(
              <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"4px 0",borderBottom:`1px solid ${C.border}15`}}>
                <span style={{color:C.muted,fontSize:12}}>{l}</span>
                <span style={{color:c,fontSize:13,fontWeight:700,fontFamily:"monospace"}}>{typeof v==="number"?v.toLocaleString():v}</span>
              </div>
            ))}
          </div>
          {downCount>0&&<div style={{...S.card,border:`1px solid ${C.red}`}}>
            <div style={{...S.title,color:C.red}}>Down Links ({downCount})</div>
            {Object.values(downRef.current).map((l,i)=>(
              <div key={i} style={{fontSize:11,color:C.red,padding:"2px 0"}}>s{swNums[l.src_dpid]||"?"} &harr; s{swNums[l.dst_dpid]||"?"}</div>
            ))}
          </div>}
          <div style={S.card}>
            <div style={S.title}>Switch Legend</div>
            {(raw.switches||[]).sort((a,b)=>a.dpid.localeCompare(b.dpid)).map((s,i)=>(
              <div key={s.dpid} style={{display:"flex",justifyContent:"space-between",padding:"3px 0",borderBottom:`1px solid ${C.border}15`,fontSize:11}}>
                <span style={{color:C.accent,fontFamily:"monospace"}}>s{i+1} = {s.dpid}</span>
                <span style={{color:heatColor(s.dpid),fontWeight:700}}>{fB(swBwTotal[s.dpid]||0)}</span>
              </div>
            ))}
          </div>
          {activePath.length>0&&<div style={{...S.card,border:`1px solid ${C.yellow}`}}>
            <div style={{...S.title,color:C.yellow}}>Path — {activePath.length-1} hops</div>
            <div style={{fontSize:11,lineHeight:1.8}}>
              {activePath.map((n,i)=><span key={i}>
                <span style={{color:C.text,fontFamily:"monospace"}}>{swNums[n]?"s"+swNums[n]:n.slice(-8)}</span>
                {i<activePath.length-1&&<span style={{color:C.yellow}}> → </span>}
              </span>)}
            </div>
          </div>}
          {selected&&<div style={S.card}>
            <div style={S.title}>Selected Node</div>
            <pre style={{fontSize:10,color:C.muted,whiteSpace:"pre-wrap",margin:0,maxHeight:160,overflowY:"auto"}}>
              {JSON.stringify(typeof selected==="string"?
                (raw.switches||[]).find(s=>s.dpid===selected)||
                (raw.hosts||[]).find(h=>h.mac===selected)||{}
                :selected,null,2)}
            </pre>
          </div>}
          <div style={S.card}>
            <div style={S.title}>Heatmap Legend</div>
            {[["Low traffic",C.green],["Medium",C.yellow],["High",C.orange],["Critical load",C.red]].map(([l,c])=>(
              <div key={l} style={{display:"flex",alignItems:"center",gap:6,marginBottom:3}}>
                <div style={{width:10,height:10,borderRadius:"50%",background:c}}/>
                <span style={{fontSize:11,color:C.muted}}>{l}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  // ── TAB: DASHBOARD ─────────────────────────────────────────────────────────
  const renderDashboard=()=>{
    const s=summary||{};const al=s.alerts||{};
    const protos=["arp","icmp","tcp","udp","other"];
    const totalPkts=pktStats.total||1;
    const now=Date.now()/1000;
    const buckets=Array(12).fill(0);
    alertTimeline.forEach(a=>{if(a.ts){const age=now-a.ts;if(age<720){const b=Math.floor(age/60);if(b<12)buckets[11-b]++;}}});
    const topSw=Object.entries(swBwTotal).sort((a,b)=>b[1]-a[1]).slice(0,5);
    return(
      <div style={S.col}>
        <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
          <KPI label="Switches" value={s.switches||0} color={C.accent}/>
          <KPI label="Hosts" value={s.hosts||0} color={C.green}/>
          <KPI label="Active Alerts" value={al.active||0} color={al.active>0?C.red:C.green} sub={al.critical>0?`${al.critical} CRITICAL`:"clean"}/>
          <KPI label="Packets" value={(s.packets_total||0).toLocaleString()} color={C.purple}/>
          <KPI label="Bandwidth" value={fB(s.total_bandwidth||0)} color={C.cyan}/>
          <KPI label="Sessions" value={s.active_connections||0} color={C.orange}/>
          <KPI label="PKT-IN (ctrl)" value={(s.ctrl_packetin||0).toLocaleString()} color={C.teal}/>
          <KPI label="Uptime" value={fAge(s.uptime||0)} color={C.muted}/>
        </div>
        <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
          <div style={{...S.card,flex:"0 0 210px"}}>
            <div style={S.title}>Protocol Mix</div>
            {protos.map(p=>{const c=pktStats[p]||0;const pc=Math.round(c/totalPkts*100);return(
              <div key={p} style={{marginBottom:5}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:11,marginBottom:2}}>
                  <span style={{color:PROTO[p],fontWeight:700}}>{p.toUpperCase()}</span>
                  <span style={{color:C.muted}}>{c.toLocaleString()} ({pc}%)</span>
                </div>
                <Bar value={c} max={totalPkts} color={PROTO[p]}/>
              </div>
            );})}
            <div style={{color:C.muted,fontSize:10,marginTop:6,borderTop:`1px solid ${C.border}`,paddingTop:4}}>
              Total: {pktStats.total.toLocaleString()} packets
            </div>
          </div>
          <div style={{...S.card,flex:1,minWidth:240}}>
            <div style={S.title}>Alert Frequency (last 12 min)</div>
            <div style={{display:"flex",gap:3,alignItems:"flex-end",height:80}}>
              {buckets.map((v,i)=>{
                const maxB=Math.max(...buckets,1);const h=Math.max(3,v/maxB*76);
                return<div key={i} style={{flex:1,height:h,background:v>3?C.red:v>0?C.orange:C.border,borderRadius:"2px 2px 0 0",transition:"height .3s"}} title={`${v} alerts at -${12-i}min`}/>;
              })}
            </div>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:9,color:C.muted,marginTop:4}}>
              <span>-12m</span><span>-6m</span><span>now</span>
            </div>
          </div>
          <div style={{...S.card,flex:"0 0 200px"}}>
            <div style={S.title}>Top Switches BW</div>
            {topSw.map(([d,bwv])=>(
              <div key={d} style={{marginBottom:6}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:11,marginBottom:2}}>
                  <span style={{color:C.accent,fontFamily:"monospace"}}>{d.slice(-8)}</span>
                  <span style={{color:C.muted}}>{fB(bwv)}</span>
                </div>
                <Bar value={bwv} max={maxSwBw} color={heatColor(d)}/>
              </div>
            ))}
            {topSw.length===0&&<div style={{color:C.muted,fontSize:11}}>No traffic yet</div>}
          </div>
        </div>
        <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
          <div style={{...S.card,flex:1,minWidth:280}}>
            <div style={{...S.title,display:"flex",justifyContent:"space-between"}}>
              Live Alerts <span style={{color:C.red}}>{activeAlerts.length} active</span>
            </div>
            <div style={{maxHeight:180,overflowY:"auto"}}>
              {activeAlerts.slice(0,12).map(a=>(
                <div key={a.id} style={{display:"flex",gap:6,alignItems:"center",padding:"3px 0",borderBottom:`1px solid ${C.border}15`}}>
                  <div style={{width:7,height:7,borderRadius:"50%",background:SEV[a.severity],flexShrink:0}}/>
                  <span style={{color:SEV[a.severity],fontSize:10,fontWeight:700,width:80,flexShrink:0}}>{a.type.replace(/_/g," ")}</span>
                  <span style={{color:C.muted,fontSize:10,flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.msg}</span>
                  <span style={{color:C.muted,fontSize:9,flexShrink:0}}>{new Date(a.ts*1000).toLocaleTimeString()}</span>
                </div>
              ))}
              {activeAlerts.length===0&&<div style={{color:C.green,fontSize:12,padding:16,textAlign:"center"}}>No active alerts</div>}
            </div>
          </div>
          <div style={{...S.card,flex:"0 0 260px"}}>
            <div style={S.title}>Top Talkers</div>
            {talkers.slice(0,8).map((t,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",padding:"3px 0",borderBottom:`1px solid ${C.border}15`,fontSize:11}}>
                <span style={{color:C.accent,fontFamily:"monospace",flex:1,overflow:"hidden",textOverflow:"ellipsis"}}>{t.src}<span style={{color:C.muted}}> → </span>{t.dst}</span>
                <span style={{color:C.muted,flexShrink:0,marginLeft:6}}>{fS(t.bytes)}</span>
              </div>
            ))}
            {talkers.length===0&&<div style={{color:C.muted,fontSize:11}}>No traffic yet</div>}
          </div>
          <div style={{...S.card,flex:"0 0 220px"}}>
            <div style={S.title}>Threat Scores</div>
            {hostIntel.filter(h=>h.threat_score>0).slice(0,6).map((h,i)=>(
              <div key={i} style={{marginBottom:5}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:11,marginBottom:2}}>
                  <span style={{color:C.text,fontFamily:"monospace"}}>{h.ip||h.mac?.slice(-8)}</span>
                  <span style={{color:h.threat_score>60?C.red:h.threat_score>30?C.orange:C.yellow,fontWeight:700}}>{h.threat_score}</span>
                </div>
                <Bar value={h.threat_score} max={100} color={h.threat_score>60?C.red:h.threat_score>30?C.orange:C.yellow} height={4}/>
              </div>
            ))}
            {hostIntel.filter(h=>h.threat_score>0).length===0&&<div style={{color:C.green,fontSize:11}}>All hosts clean</div>}
          </div>
        </div>
        {/* Controller traffic monitor */}
        <div style={S.card}>
          <div style={S.title}>POX Controller Traffic Monitor</div>
          <div style={{display:"flex",gap:16,flexWrap:"wrap"}}>
            <div>
              <div style={{color:C.muted,fontSize:11}}>Total PacketIn events</div>
              <div style={{color:C.cyan,fontSize:20,fontWeight:800,fontFamily:"monospace"}}>{(ctrlStats.packetin_count||0).toLocaleString()}</div>
            </div>
            <div>
              <div style={{color:C.muted,fontSize:11}}>Total bytes to controller</div>
              <div style={{color:C.purple,fontSize:20,fontWeight:800,fontFamily:"monospace"}}>{fS(ctrlStats.total_bytes||0)}</div>
            </div>
            {Object.entries(ctrlStats.per_dpid||{}).map(([d,v])=>(
              <div key={d}>
                <div style={{color:C.muted,fontSize:10}}>{d.slice(-8)}</div>
                <div style={{color:C.accent,fontSize:14,fontWeight:700,fontFamily:"monospace"}}>{v.count.toLocaleString()} pkt / {fS(v.bytes)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  // ── TAB: ALERTS ─────────────────────────────────────────────────────────────
  const renderAlerts=()=>{
    const dismiss=async id=>{await fetch("/topo/alerts/dismiss",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});pollAlerts();};
    const clearAll=async()=>{await fetch("/topo/alerts/clear",{method:"POST"});pollAlerts();setUnreadAlerts(0);};
    const blockFromAlert=async(ip)=>{
      if(!ip||!ip.includes("."))return;
      await fetch("/topo/block/host",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip})});
      setBlockMsg("Block rule installed for "+ip);setTimeout(()=>setBlockMsg(""),4000);
    };
    return(
      <div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,flexWrap:"wrap",gap:8}}>
          <span style={{color:C.text,fontWeight:700,fontSize:14}}>{activeAlerts.length} Active Alerts</span>
          <div style={{display:"flex",gap:8}}>
            {blockMsg&&<span style={{color:C.green,fontSize:12}}>{blockMsg}</span>}
            {activeAlerts.length>0&&<button onClick={clearAll} style={{...S.btn,background:C.red}}>Clear All</button>}
          </div>
        </div>
        {activeAlerts.length===0&&<div style={{color:C.green,textAlign:"center",padding:48,fontSize:14}}>No active alerts — network is clean</div>}
        {["critical","high","medium","low"].map(sev=>{
          const sa=activeAlerts.filter(a=>a.severity===sev);if(!sa.length)return null;
          return<div key={sev} style={{marginBottom:16}}>
            <div style={{color:SEV[sev],fontWeight:700,fontSize:12,letterSpacing:1,marginBottom:6}}>{sev.toUpperCase()} ({sa.length})</div>
            {sa.map(a=>(
              <div key={a.id} style={{...S.card,border:`1px solid ${SEV[a.severity]}40`,marginBottom:8}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",flexWrap:"wrap",gap:6}}>
                  <div style={{flex:1}}>
                    <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                      <span style={{color:SEV[a.severity],fontWeight:700,fontSize:13}}>{a.type.replace(/_/g," ").toUpperCase()}</span>
                      {a.count>1&&<span style={{...S.pill,background:C.navy,color:C.muted}}>x{a.count}</span>}
                    </div>
                    {a.mitre&&<div style={{marginTop:4,display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                      <span style={{color:C.purple,fontSize:11,fontWeight:700}}>{a.mitre_id}</span>
                      <span style={{color:C.muted,fontSize:11}}>{a.mitre_desc}</span>
                      {a.mitre_url&&<a href={a.mitre_url} target="_blank" rel="noreferrer"
                        style={{color:C.accent,fontSize:10,textDecoration:"none"}}>MITRE ATT&CK ↗</a>}
                    </div>}
                    <div style={{color:C.text,fontSize:12,marginTop:6}}>{a.msg}</div>
                    <div style={{display:"flex",gap:16,marginTop:4,flexWrap:"wrap",fontSize:11}}>
                      <span style={{color:C.muted}}>SRC: <span style={{color:C.accent}}>{a.src}</span></span>
                      <span style={{color:C.muted}}>DST: <span style={{color:C.accent}}>{a.dst}</span></span>
                      <span style={{color:C.muted}}>{new Date(a.ts*1000).toLocaleTimeString()}</span>
                    </div>
                  </div>
                  <div style={{display:"flex",gap:6,flexShrink:0,alignItems:"flex-start"}}>
                    {a.src&&a.src.includes(".")&&
                      <button onClick={()=>blockFromAlert(a.src)} style={{...S.btn,padding:"3px 8px",fontSize:10,background:"#3d1414",color:C.red}}>Block</button>}
                    <button onClick={()=>dismiss(a.id)} style={{...S.btn,padding:"3px 8px",fontSize:10}}>Dismiss</button>
                  </div>
                </div>
              </div>
            ))}
          </div>;
        })}
        {alerts.filter(a=>!a.active).length>0&&<div>
          <div style={{color:C.muted,fontSize:11,marginBottom:6,marginTop:8}}>RESOLVED ({alerts.filter(a=>!a.active).length})</div>
          {alerts.filter(a=>!a.active).slice(-20).map(a=>(
            <div key={a.id} style={{...S.card,opacity:.45,marginBottom:4,fontSize:11,color:C.muted}}>
              [{a.severity}] {a.type} — {a.msg}
            </div>
          ))}
        </div>}
      </div>
    );
  };

  // ── TAB: THREATS ─────────────────────────────────────────────────────────────
  const MITRE_DESCRIPTIONS={
    "T1046":  "The attacker discovers services running on remote hosts by probing ports.",
    "T1498":  "The attacker overwhelms network infrastructure with flood traffic.",
    "T1557":  "The attacker positions themselves between communicating hosts.",
    "T1557.002": "ARP spoofing to redirect traffic to attacker-controlled host.",
    "T1498.001": "Direct flood attack saturating network bandwidth.",
    "T1071.004": "Using DNS protocol for C2 communication or data exfiltration.",
    "T1018":  "Attacker discovers hosts on the network through ICMP/sweep scans.",
    "T1040":  "Passively capturing network traffic or active traceroute probing.",
    "T1030":  "Adversary limits data transfer size to avoid detection thresholds.",
  };
  const renderThreats=()=>{
    const byType={};
    alerts.forEach(a=>{if(!byType[a.type])byType[a.type]={type:a.type,total:0,active:0,
      mitre:a.mitre||"",mitre_id:a.mitre_id||"",mitre_desc:a.mitre_desc||"",mitre_url:a.mitre_url||""};
      byType[a.type].total+=a.count;if(a.active)byType[a.type].active++;});
    const typeList=Object.values(byType).sort((a,b)=>b.total-a.total);
    const threatened=hostIntel.filter(h=>h.threat_score>0).sort((a,b)=>b.threat_score-a.threat_score);
    return(
      <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
        <div style={{flex:1,minWidth:300,...S.col}}>
          <div style={S.card}>
            <div style={S.title}>Detected Threat Types</div>
            {typeList.length===0&&<div style={{color:C.green,fontSize:12,padding:16,textAlign:"center"}}>No threats detected</div>}
            {typeList.map(t=>(
              <div key={t.type} style={{borderBottom:`1px solid ${C.border}`,padding:"10px 0"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                  <div>
                    <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                      <span style={{color:C.orange,fontWeight:700,fontSize:12}}>{t.type.replace(/_/g," ").toUpperCase()}</span>
                      {t.active>0&&<Pill label={`${t.active} active`} color={C.red}/>}
                    </div>
                    {t.mitre_id&&<div style={{display:"flex",gap:8,alignItems:"center",marginTop:4,flexWrap:"wrap"}}>
                      <span style={{color:C.purple,fontSize:11,fontWeight:700}}>{t.mitre_id}</span>
                      <span style={{color:C.muted,fontSize:11}}>{t.mitre_desc}</span>
                      {t.mitre_url&&<a href={t.mitre_url} target="_blank" rel="noreferrer"
                        style={{color:C.accent,fontSize:10,textDecoration:"none"}}>MITRE ↗</a>}
                    </div>}
                    {t.mitre_id&&MITRE_DESCRIPTIONS[t.mitre_id]&&
                      <div style={{color:C.muted,fontSize:10,marginTop:3,maxWidth:400}}>{MITRE_DESCRIPTIONS[t.mitre_id]}</div>}
                  </div>
                  <span style={{color:C.muted,fontSize:12,flexShrink:0,marginLeft:8}}>{t.total}×</span>
                </div>
              </div>
            ))}
          </div>
          <div style={S.card}>
            <div style={S.title}>Alert Timeline (last 10 min)</div>
            <div style={{display:"flex",gap:2,flexWrap:"wrap"}}>
              {Array.isArray(alertTimeline)&&alertTimeline.slice(-100).reverse().map((a,i)=>(
                <div key={i} title={`${a.type||""} @ ${a.ts?new Date(a.ts*1000).toLocaleTimeString():""}`}
                  style={{width:10,height:10,borderRadius:2,background:SEV[a.severity]||C.muted,cursor:"pointer"}}
                  onClick={()=>{const al=alerts.find(x=>Math.abs(x.ts-(a.ts||0))<1&&x.type===a.type);if(al)setTab("ALERTS");}}/>
              ))}
              {(!alertTimeline||alertTimeline.length===0)&&<div style={{color:C.muted,fontSize:11}}>No alert history</div>}
            </div>
            <div style={{display:"flex",gap:8,marginTop:6,flexWrap:"wrap"}}>
              {Object.entries(SEV).map(([k,c])=>(
                <div key={k} style={{display:"flex",alignItems:"center",gap:3,fontSize:10,color:C.muted}}>
                  <div style={{width:8,height:8,borderRadius:2,background:c}}/>{k}
                </div>
              ))}
            </div>
          </div>
        </div>
        <div style={{flex:"0 0 280px",...S.col}}>
          <div style={S.card}>
            <div style={S.title}>Host Threat Scores</div>
            {threatened.slice(0,10).map(h=>(
              <div key={h.mac} style={{borderBottom:`1px solid ${C.border}`,padding:"8px 0"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <div>
                    <div style={{color:C.text,fontSize:12,fontFamily:"monospace"}}>{h.ip||h.mac}</div>
                    <div style={{color:C.muted,fontSize:10}}>{h.dpid?.slice(-8)} p{h.port}</div>
                  </div>
                  <div style={{textAlign:"right"}}>
                    <div style={{color:h.threat_score>60?C.red:h.threat_score>30?C.orange:C.yellow,fontSize:20,fontWeight:800}}>{h.threat_score}</div>
                    <div style={{color:C.muted,fontSize:10}}>{h.alert_count} alerts</div>
                  </div>
                </div>
                <Bar value={h.threat_score} max={100} color={h.threat_score>60?C.red:h.threat_score>30?C.orange:C.yellow} height={4}/>
                <div style={{display:"flex",gap:3,marginTop:4,flexWrap:"wrap"}}>
                  {(h.protocols||[]).map(p=><Pill key={p} label={p.toUpperCase()} color={PROTO[p]}/>)}
                </div>
              </div>
            ))}
            {threatened.length===0&&<div style={{color:C.green,fontSize:12,textAlign:"center",padding:16}}>All hosts clean</div>}
          </div>
          <div style={S.card}>
            <div style={S.title}>Block a Host (Drop Rule)</div>
            <input placeholder="IP to block (e.g. 10.0.0.1)" value={blockIp} onChange={e=>setBlockIp(e.target.value)} style={{...S.inp,width:"100%",boxSizing:"border-box",marginBottom:8}}/>
            <button onClick={async()=>{
              if(!blockIp)return;
              const r=await fetch("/topo/block/host",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip:blockIp})});
              const d=await r.json();
              setBlockMsg(d.ok?`Blocked on ${d.switches_affected} switches`:"Error: "+(d.error||"?"));
              setTimeout(()=>setBlockMsg(""),4000);
            }} style={{...S.btn,background:C.red,width:"100%"}}>Install Drop Rule</button>
            {blockMsg&&<div style={{color:C.green,fontSize:12,marginTop:6}}>{blockMsg}</div>}
          </div>
        </div>
      </div>
    );
  };

  // ── TAB: PACKETS ─────────────────────────────────────────────────────────────
  const renderPackets=()=>{
    const total=pktStats.total||1;
    const protos=["arp","icmp","tcp","udp","other"];
    const displayPkts=filteredPkts.slice(-pktPageSize).reverse();
    return(
      <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
        <div style={{width:210,flexShrink:0,...S.col}}>
          <div style={S.card}>
            <div style={{...S.title,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              Stats
              <div style={{display:"flex",gap:4}}>
                <select value={pktPageSize} onChange={e=>setPktPageSize(Number(e.target.value))}
                  style={{...S.inp,padding:"1px 4px",fontSize:10,width:70}}>
                  {[100,250,500,1000,2000,5000].map(n=><option key={n} value={n}>{n}</option>)}
                </select>
                <button onClick={async()=>{await fetch("/topo/packets/clear",{method:"POST"});setAllPackets([]);setLastPktId(0);}} style={{...S.btn,padding:"1px 6px",fontSize:10,background:C.red}}>Clear</button>
              </div>
            </div>
            {protos.map(p=>{const c=pktStats[p]||0;const pc=Math.round(c/total*100);return(
              <div key={p} style={{marginBottom:5}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:11,marginBottom:2}}>
                  <span style={{color:PROTO[p],fontWeight:700}}>{p.toUpperCase()}</span>
                  <span style={{color:C.muted}}>{c.toLocaleString()} ({pc}%)</span>
                </div>
                <Bar value={c} max={total} color={PROTO[p]}/>
              </div>
            );})}
            <div style={{color:C.muted,fontSize:10,marginTop:6,borderTop:`1px solid ${C.border}`,paddingTop:4}}>
              Buffered: {allPackets.length.toLocaleString()} | Filtered: {filteredPkts.length.toLocaleString()} | Showing: {Math.min(pktPageSize,filteredPkts.length).toLocaleString()}
            </div>
          </div>
          <div style={S.card}>
            <div style={S.title}>Top Hosts</div>
            {(pktStats.top_hosts||[]).slice(0,8).map((h,i)=>(
              <div key={i} style={{borderBottom:`1px solid ${C.border}10`,padding:"3px 0"}}>
                <div style={{color:C.accent,fontSize:10,fontFamily:"monospace"}}>{h.ip||h.mac}</div>
                <div style={{display:"flex",gap:8,fontSize:10}}>
                  <span style={{color:C.green}}>↑{fS(h.tx_bytes)}</span>
                  <span style={{color:C.orange}}>↓{fS(h.rx_bytes)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div style={{flex:1,minWidth:0}}>
          <div style={{display:"flex",gap:8,marginBottom:8,flexWrap:"wrap",alignItems:"center"}}>
            <select value={pktFilter.proto} onChange={e=>setPktFilter(f=>({...f,proto:e.target.value}))} style={{...S.inp,width:88}}>
              <option value="">All protos</option>
              {protos.map(p=><option key={p} value={p}>{p.toUpperCase()}</option>)}
            </select>
            <input placeholder="Search IP / MAC / port / info..." value={pktFilter.search}
              onChange={e=>setPktFilter(f=>({...f,search:e.target.value}))} style={{...S.inp,flex:1}}/>
            <button onClick={()=>setPktPaused(p=>!p)}
              style={{...S.btn,background:pktPaused?C.green:C.navy,color:pktPaused?"#000":C.text}}>
              {pktPaused?"▶ Resume":"⏸ Pause"}
            </button>
            <span style={{color:C.muted,fontSize:11}}>Showing last {Math.min(pktPageSize,displayPkts.length)}</span>
          </div>
          <div style={{overflowX:"auto",fontSize:11,fontFamily:"monospace"}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead>
                <tr style={{background:C.navy,position:"sticky",top:0}}>
                  {["#","Time","Proto","Src","Dst","Len","Flags","Info"].map(h=>(
                    <th key={h} style={{textAlign:"left",padding:"5px 8px",color:C.muted,borderBottom:`1px solid ${C.border}`,whiteSpace:"nowrap"}}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayPkts.map((p,i)=>(
                  <>
                    <tr key={p.id} onClick={()=>setPktExpanded(pktExpanded===p.id?null:p.id)}
                      style={{background:pktExpanded===p.id?C.navy:i%2===0?"transparent":C.card+"80",cursor:"pointer",borderBottom:`1px solid ${C.border}10`}}>
                      <td style={{padding:"3px 8px",color:C.muted}}>{p.id}</td>
                      <td style={{padding:"3px 8px",color:C.muted,whiteSpace:"nowrap"}}>{fT(p.ts)}</td>
                      <td style={{padding:"3px 8px"}}>
                        <span style={{...S.pill,background:(PROTO[p.proto]||C.muted)+"25",color:PROTO[p.proto]||C.muted}}>{p.proto?.toUpperCase()}</span>
                      </td>
                      <td style={{padding:"3px 8px",color:C.text,whiteSpace:"nowrap"}}>{p.src_ip||p.src_mac}</td>
                      <td style={{padding:"3px 8px",color:C.text,whiteSpace:"nowrap"}}>{p.dst_ip||p.dst_mac}</td>
                      <td style={{padding:"3px 8px",color:C.muted}}>{p.len}</td>
                      <td style={{padding:"3px 8px",color:C.yellow,fontWeight:700,fontFamily:"monospace"}}>{p.flags||""}</td>
                      <td style={{padding:"3px 8px",color:C.muted,maxWidth:220,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{p.info}</td>
                    </tr>
                    {pktExpanded===p.id&&(
                      <tr key={"exp"+p.id}>
                        <td colSpan={8} style={{background:C.navy,padding:"10px 16px"}}>
                          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:6,fontSize:11}}>
                            {[["Packet ID",p.id],["Timestamp",fT(p.ts)],["Switch",p.sw],["In Port",p.port],
                              ["Src MAC",p.src_mac],["Dst MAC",p.dst_mac],["Src IP",p.src_ip||"—"],["Dst IP",p.dst_ip||"—"],
                              ["Protocol",p.proto?.toUpperCase()],["Length",p.len+" bytes"],
                              ["Src Port",p.sp||"—"],["Dst Port",p.dp||"—"],
                              ["TCP Flags",p.flags||"—"],["TTL",p.ttl||"—"],
                              ["IP Proto",p.ip_proto||"—"],["Info",p.info]].map(([k,v])=>(
                              <div key={k}><span style={{color:C.muted}}>{k}: </span><span style={{color:C.text,fontFamily:"monospace"}}>{v||"—"}</span></div>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
            {displayPkts.length===0&&<div style={{color:C.muted,textAlign:"center",padding:40,fontSize:13}}>
              No packets{pktFilter.proto?` matching proto=${pktFilter.proto}`:""}{pktFilter.search?` matching "${pktFilter.search}"`:""}<br/>
              <span style={{fontSize:11}}>Run <code style={{color:C.accent}}>pingall</code> in Mininet terminal</span>
            </div>}
          </div>
        </div>
      </div>
    );
  };

  // ── TAB: SESSIONS ───────────────────────────────────────────────────────────
  const renderConnections=()=>{
    const filtered=connections.filter(c=>{
      if(!connFilter)return true;
      const s=connFilter.toLowerCase();
      return c.src_ip?.includes(s)||c.dst_ip?.includes(s)||String(c.dst_port).includes(s)||c.proto?.includes(s);
    });
    const byState={};connections.forEach(c=>{byState[c.state]=(byState[c.state]||0)+1;});
    return(
      <div>
        <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
          {Object.entries(byState).map(([st,n])=>(
            <div key={st} style={{...S.card,padding:"5px 12px",display:"flex",gap:6,alignItems:"center"}}>
              <span style={{color:st==="ESTAB"?C.green:st==="CLOSED"?C.muted:C.yellow,fontWeight:700,fontSize:11}}>{st}</span>
              <span style={{color:C.text,fontSize:14,fontWeight:800}}>{n}</span>
            </div>
          ))}
          <div style={{...S.card,padding:"5px 12px",display:"flex",gap:6,alignItems:"center"}}>
            <span style={{color:C.accent,fontWeight:700,fontSize:11}}>TOTAL BW</span>
            <span style={{color:C.text,fontSize:13,fontWeight:800}}>{fS(connections.reduce((s,c)=>s+(c.bytes||0),0))}</span>
          </div>
          <input placeholder="Filter IP / port / proto..." value={connFilter} onChange={e=>setConnFilter(e.target.value)} style={{...S.inp,flex:1}}/>
          <button onClick={async()=>{await fetch("/topo/connections/clear",{method:"POST"});}} style={{...S.btn,background:C.red}}>Clear</button>
          <span style={{color:C.muted,fontSize:12}}>{filtered.length} sessions</span>
        </div>
        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:11,fontFamily:"monospace"}}>
            <thead>
              <tr style={{background:C.navy}}>
                {["State","Proto","Src IP","Sport","Dst IP","Dport","Bytes","Pkts","Duration"].map(h=>(
                  <th key={h} style={{textAlign:"left",padding:"5px 8px",color:C.muted,borderBottom:`1px solid ${C.border}`,whiteSpace:"nowrap"}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0,300).map((c,i)=>(
                <tr key={i} style={{background:i%2===0?"transparent":C.card+"80",borderBottom:`1px solid ${C.border}10`}}>
                  <td style={{padding:"4px 8px"}}>
                    <span style={{...S.pill,background:(c.state==="ESTAB"?C.green:c.state==="CLOSED"?C.muted:C.yellow)+"25",
                      color:c.state==="ESTAB"?C.green:c.state==="CLOSED"?C.muted:C.yellow}}>{c.state}</span>
                  </td>
                  <td style={{padding:"4px 8px",color:PROTO[c.proto]||C.muted}}>{c.proto?.toUpperCase()}</td>
                  <td style={{padding:"4px 8px",color:C.text}}>{c.src_ip}</td>
                  <td style={{padding:"4px 8px",color:C.muted}}>{c.src_port}</td>
                  <td style={{padding:"4px 8px",color:C.text}}>{c.dst_ip}</td>
                  <td style={{padding:"4px 8px",color:C.accent}}>{c.dst_port}</td>
                  <td style={{padding:"4px 8px",color:C.muted}}>{fS(c.bytes||0)}</td>
                  <td style={{padding:"4px 8px",color:C.muted}}>{c.pkts}</td>
                  <td style={{padding:"4px 8px",color:C.muted}}>{fAge(c.duration)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length===0&&<div style={{color:C.muted,textAlign:"center",padding:32}}>No TCP/UDP sessions — run iperf or wget in Mininet</div>}
        </div>
      </div>
    );
  };

  // ── TAB: HOSTS ──────────────────────────────────────────────────────────────
  const renderHosts=()=>{
    const htopo=raw.hosts||[];
    // merge hostIntel with topo data (IP from topo is more reliable)
    const merged=hostIntel.filter(h=>{
      if(!hostFilter)return true;
      const s=hostFilter.toLowerCase();
      return h.mac?.includes(s)||h.ip?.includes(s)||h.dpid?.includes(s);
    }).map(h=>{
      const t=htopo.find(x=>x.mac===h.mac);
      const ip=(t?.ipAddresses?.[0])||h.ip||"";
      return {...h,ip,sw_num:t?.sw_num||0,ipAddresses:t?.ipAddresses||[]};
    });
    // add topo hosts that have no intel yet
    htopo.forEach(t=>{
      if(!merged.find(h=>h.mac===t.mac)){
        const ip=t.ipAddresses?.[0]||"";
        if(hostFilter){
          const s=hostFilter.toLowerCase();
          if(!t.mac?.includes(s)&&!ip?.includes(s))return;
        }
        merged.push({mac:t.mac,ip,dpid:t.dpid,port:t.port,sw_num:t.sw_num,
          tx_bytes:0,rx_bytes:0,tx_pkts:0,rx_pkts:0,protocols:[],threat_score:0,alert_count:0});
      }
    });
    return(
      <div>
        <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
          <input placeholder="Filter by MAC / IP / switch..." value={hostFilter}
            onChange={e=>setHostFilter(e.target.value)} style={{...S.inp,flex:1}}/>
          <button onClick={async()=>{await fetch("/topo/hostintel/reset",{method:"POST"});}}
            style={{...S.btn,background:C.red}}>Reset Intel</button>
          <span style={{color:C.muted,fontSize:12}}>{merged.length} hosts</span>
        </div>
        <div style={{display:"flex",flexWrap:"wrap",gap:10}}>
          {merged.slice(0,50).map(h=>{
            const ts=h.threat_score||0;
            const tc=ts>60?C.red:ts>30?C.orange:ts>10?C.yellow:C.green;
            const hasIp=!!(h.ip);
            return(
              <div key={h.mac} style={{...S.card,width:220,border:`1px solid ${ts>30?tc:C.border}`}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:6}}>
                  <div>
                    <div style={{color:hasIp?C.accent:C.muted,fontSize:13,fontWeight:700,fontFamily:"monospace"}}>
                      {hasIp?h.ip:"(no IP yet)"}
                    </div>
                    <div style={{color:C.muted,fontSize:9,fontFamily:"monospace"}}>{h.mac}</div>
                  </div>
                  <div style={{textAlign:"right"}}>
                    <div style={{color:tc,fontSize:18,fontWeight:800}}>{ts}</div>
                    <div style={{color:C.muted,fontSize:9}}>risk</div>
                  </div>
                </div>
                <Bar value={ts} max={100} color={tc} height={3}/>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:3,marginTop:8,fontSize:10}}>
                  <div><span style={{color:C.muted}}>Switch: </span>
                    <span style={{color:C.accent,fontFamily:"monospace"}}>
                      {h.sw_num?`s${h.sw_num}`:(h.dpid?h.dpid.slice(-6):"—")}
                    </span>
                  </div>
                  <div><span style={{color:C.muted}}>Port: </span><span style={{color:C.text}}>{h.port||"—"}</span></div>
                  <div><span style={{color:C.muted}}>TX: </span><span style={{color:C.green}}>{fS(h.tx_bytes||0)}</span></div>
                  <div><span style={{color:C.muted}}>RX: </span><span style={{color:C.orange}}>{fS(h.rx_bytes||0)}</span></div>
                  <div><span style={{color:C.muted}}>Pkts: </span><span style={{color:C.text}}>{((h.tx_pkts||0)+(h.rx_pkts||0)).toLocaleString()}</span></div>
                  <div><span style={{color:C.muted}}>Alerts: </span><span style={{color:h.alert_count>0?C.red:C.muted}}>{h.alert_count||0}</span></div>
                  {h.first_seen&&<div style={{gridColumn:"1/-1"}}><span style={{color:C.muted}}>First: </span><span style={{color:C.text,fontSize:9}}>{new Date(h.first_seen*1000).toLocaleTimeString()}</span></div>}
                  {h.last_seen&&<div style={{gridColumn:"1/-1"}}><span style={{color:C.muted}}>Last: </span><span style={{color:C.text,fontSize:9}}>{new Date(h.last_seen*1000).toLocaleTimeString()}</span></div>}
                </div>
                <div style={{display:"flex",gap:3,flexWrap:"wrap",marginTop:5}}>
                  {(h.protocols||[]).map(p=><Pill key={p} label={p.toUpperCase()} color={PROTO[p]}/>)}
                </div>
                <div style={{display:"flex",gap:4,marginTop:6}}>
                  {h.ip&&<button onClick={async()=>{
                    setPktFilter({proto:"",search:h.ip});setTab("PACKETS");
                  }} style={{...S.btn,padding:"2px 6px",fontSize:9}}>Trace</button>}
                  {h.ip&&<button onClick={async()=>{
                    const r=await fetch("/topo/block/host",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip:h.ip})});
                    const d=await r.json();
                    setBlockMsg(d.ok?`Blocked ${h.ip} on ${d.switches_affected} switches`:"Error");
                    setTimeout(()=>setBlockMsg(""),4000);
                  }} style={{...S.btn,padding:"2px 6px",fontSize:9,background:"#2d1414",color:C.red}}>Block</button>}
                </div>
              </div>
            );
          })}
          {merged.length===0&&<div style={{color:C.muted,fontSize:13,textAlign:"center",padding:48,width:"100%"}}>
            No host intel — run <code style={{color:C.accent}}>pingall</code> in Mininet
          </div>}
        </div>
      </div>
    );
  };

  // ── TAB: FLOWS ───────────────────────────────────────────────────────────────
  const dpidsList=Object.keys(flows);
  const activeDpid=flowDpid||dpidsList[0]||"";
  const activeFlows=flows[activeDpid]||[];
  const deleteFlow=async(dpid,f)=>{
    await fetch("/topo/flows/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({dpid,...f})});
    setTimeout(()=>api("/topo/flows",setFlows),600);
  };
  const addFlow=async()=>{
    const body={...newFlow};Object.keys(body).forEach(k=>{if(!body[k])delete body[k];});
    await fetch("/topo/flows/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    setShowAddFlow(false);setTimeout(()=>api("/topo/flows",setFlows),600);
  };
  const renderFlows=()=>(
    <div>
      <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
        <select value={activeDpid} onChange={e=>setFlowDpid(e.target.value)} style={S.inp}>
          {dpidsList.map(d=><option key={d} value={d}>{d}</option>)}
        </select>
        <button onClick={()=>setShowAddFlow(s=>!s)} style={{...S.btn,background:C.green}}>+ Add Rule</button>
        <button onClick={()=>api("/topo/flows",setFlows)} style={S.btn}>Refresh</button>
        <span style={{color:C.muted,fontSize:12}}>{activeFlows.length} rules</span>
      </div>
      {showAddFlow&&(
        <div style={{...S.card,border:`1px solid ${C.green}`,marginBottom:12}}>
          <div style={{...S.title,color:C.green}}>Add Flow Rule</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8,marginBottom:10}}>
            {[["Switch DPID","dpid"],["Priority","priority"],["In Port","in_port"],["Src MAC","dl_src"],
              ["Dst MAC","dl_dst"],["Src IP","nw_src"],["Dst IP","nw_dst"],["IP Proto","nw_proto"],
              ["Dst Port","tp_dst"],["Action port (blank=drop)","action_port"],["Idle Timeout","idle_timeout"],["Hard Timeout","hard_timeout"]].map(([label,key])=>(
              <div key={key}>
                <div style={{color:C.muted,fontSize:10,marginBottom:2}}>{label}</div>
                <input value={newFlow[key]||""} onChange={e=>setNewFlow(f=>({...f,[key]:e.target.value}))}
                  placeholder={key==="dpid"&&dpidsList[0]?dpidsList[0]:""} style={{...S.inp,width:"100%",boxSizing:"border-box"}}/>
              </div>
            ))}
          </div>
          <div style={{display:"flex",gap:8}}>
            <button onClick={addFlow} style={{...S.btn,background:C.green}}>Install Rule</button>
            <button onClick={()=>setShowAddFlow(false)} style={S.btn}>Cancel</button>
          </div>
        </div>
      )}
      <div style={{overflowX:"auto"}}>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:11,fontFamily:"monospace"}}>
          <thead>
            <tr style={{background:C.navy}}>
              {["Pri","In","Src IP","Dst IP","NW","Dport","Actions","Pkts","Bytes","Age",""].map(h=>(
                <th key={h} style={{textAlign:"left",padding:"5px 8px",color:C.muted,borderBottom:`1px solid ${C.border}`,whiteSpace:"nowrap"}}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {activeFlows.map((f,i)=>(
              <tr key={i} style={{background:i%2===0?"transparent":C.card+"80",borderBottom:`1px solid ${C.border}10`}}>
                <td style={{padding:"4px 8px",color:C.yellow}}>{f.priority}</td>
                <td style={{padding:"4px 8px",color:C.muted}}>{f.in_port||"*"}</td>
                <td style={{padding:"4px 8px",color:C.text}}>{f.nw_src||"*"}</td>
                <td style={{padding:"4px 8px",color:C.text}}>{f.nw_dst||"*"}</td>
                <td style={{padding:"4px 8px",color:C.muted}}>{f.nw_proto||"*"}</td>
                <td style={{padding:"4px 8px",color:C.muted}}>{f.tp_dst||"*"}</td>
                <td style={{padding:"4px 8px",color:C.green}}>{f.actions}</td>
                <td style={{padding:"4px 8px",color:C.muted}}>{(f.packet_count||0).toLocaleString()}</td>
                <td style={{padding:"4px 8px",color:C.muted}}>{fS(f.byte_count||0)}</td>
                <td style={{padding:"4px 8px",color:C.muted}}>{f.duration_sec}s</td>
                <td style={{padding:"4px 8px"}}>
                  <button onClick={()=>deleteFlow(activeDpid,f)} style={{...S.btn,padding:"2px 6px",fontSize:10,background:"#2d1a1a",color:C.red}}>Del</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {activeFlows.length===0&&<div style={{color:C.muted,textAlign:"center",padding:32}}>No flows — select a switch above</div>}
      </div>
    </div>
  );

  // ── TAB: QoS ─────────────────────────────────────────────────────────────────
  const DSCP_PRESETS=[
    {label:"Voice (EF 46)",  dscp:"46",queue:"1",proto:"17",port:"5060",desc:"VoIP/RTP — lowest latency, highest priority"},
    {label:"Video (AF41 34)",dscp:"34",queue:"2",proto:"17",port:"",  desc:"Video conferencing streams"},
    {label:"Signal (CS3 24)",dscp:"24",queue:"2",proto:"17",port:"5060",desc:"SIP signalling & VoIP control"},
    {label:"Interac (AF21 18)",dscp:"18",queue:"3",proto:"6",port:"22",desc:"SSH / interactive sessions"},
    {label:"Bulk (CS1 8)",   dscp:"8", queue:"4",proto:"6",port:"",  desc:"File transfers, backups"},
    {label:"Best Effort",    dscp:"0", queue:"-1",proto:"",port:"",  desc:"Default — no QoS marking"},
  ];
  const applyQos=async()=>{
    const body={dpid:qosForm.dpid,dscp:parseInt(qosForm.dscp),queue_id:parseInt(qosForm.queue_id),
      priority:parseInt(qosForm.priority),out_port:parseInt(qosForm.out_port)||65533,
      idle_timeout:parseInt(qosForm.idle_timeout),match:{}};
    if(qosForm.nw_src)body.match.nw_src=qosForm.nw_src;
    if(qosForm.nw_dst)body.match.nw_dst=qosForm.nw_dst;
    if(qosForm.nw_proto)body.match.nw_proto=parseInt(qosForm.nw_proto);
    if(qosForm.tp_dst)body.match.tp_dst=parseInt(qosForm.tp_dst);
    try{
      const r=await fetch("/topo/qos/set",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
      const d=await r.json();
      const rule={...qosForm,ts:new Date().toLocaleTimeString(),ok:d.ok};
      setQosRules(prev=>[rule,...prev.slice(0,19)]);
      setQosMsg(d.ok?"Rule installed!":"Error: "+(d.error||"?"));
    }catch(e){setQosMsg("Request failed");}
    setTimeout(()=>setQosMsg(""),5000);
  };
  const renderQos=()=>(
    <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
      <div style={{flex:1,minWidth:280,...S.col}}>
        <div style={S.card}>
          <div style={S.title}>QoS Rule Builder</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
            {[["Switch DPID (required)","dpid"],["Src IP (blank=any)","nw_src"],["Dst IP (blank=any)","nw_dst"],
              ["IP Proto (6=TCP 17=UDP)","nw_proto"],["Dst Port (blank=any)","tp_dst"],
              ["DSCP value (0-63)","dscp"],["Queue ID (-1=no queue)","queue_id"],
              ["Priority (higher=first)","priority"],["Out Port (65533=normal)","out_port"],
              ["Idle Timeout (0=forever)","idle_timeout"]].map(([label,key])=>(
              <div key={key}>
                <div style={{color:C.muted,fontSize:10,marginBottom:2}}>{label}</div>
                <input value={qosForm[key]||""} onChange={e=>setQosForm(f=>({...f,[key]:e.target.value}))}
                  style={{...S.inp,width:"100%",boxSizing:"border-box"}}/>
              </div>
            ))}
          </div>
          <button onClick={applyQos} style={{...S.btn,background:C.accent,color:"#000",fontWeight:700,width:"100%"}}>Apply QoS Rule</button>
          {qosMsg&&<div style={{marginTop:8,color:qosMsg.startsWith("Error")||qosMsg.startsWith("Request")?C.red:C.green,fontSize:12}}>{qosMsg}</div>}
        </div>
        <div style={{...S.card,border:`1px solid ${C.teal}`}}>
          <div style={{...S.title,color:C.teal}}>How to Test QoS</div>
          <div style={{fontSize:11,color:C.muted,lineHeight:1.7}}>
            <div style={{color:C.text,fontWeight:700,marginBottom:4}}>Step 1 — Apply a rule (example: prioritize ICMP)</div>
            <div>Set: DSCP=46, NW Proto=1 (ICMP), Priority=300, click Apply</div>
            <div style={{color:C.text,fontWeight:700,margin:"8px 0 4px"}}>Step 2 — Verify in Flows tab</div>
            <div>Go to Flows tab, select the switch — you should see your new rule.</div>
            <div style={{color:C.text,fontWeight:700,margin:"8px 0 4px"}}>Step 3 — Generate traffic in Mininet</div>
            <code style={{display:"block",background:C.dark,padding:6,borderRadius:4,color:C.cyan,marginTop:4}}>mininet&gt; h1 ping -c 20 h2</code>
            <code style={{display:"block",background:C.dark,padding:6,borderRadius:4,color:C.cyan,marginTop:4}}>mininet&gt; h1 iperf -s &amp; h2 iperf -c 10.0.0.1</code>
            <div style={{color:C.text,fontWeight:700,margin:"8px 0 4px"}}>Step 4 — Check Packets tab</div>
            <div>Filter by ICMP — confirm packets show up. In a real setup with OVS queues, use:</div>
            <code style={{display:"block",background:C.dark,padding:6,borderRadius:4,color:C.cyan,marginTop:4}}>sudo ovs-appctl qos/show s1</code>
            <div style={{color:C.text,fontWeight:700,margin:"8px 0 4px"}}>Note on queues</div>
            <div>Queue IDs require OVS queue config. Without queues, DSCP marking still works for downstream routers. Set Queue=-1 for marking-only mode.</div>
          </div>
        </div>
        <div style={{...S.card,overflowX:"auto"}}>
          <div style={S.title}>Applied QoS Rules (this session)</div>
          {qosRules.length===0&&<div style={{color:C.muted,fontSize:11}}>No rules applied yet</div>}
          {qosRules.map((r,i)=>(
            <div key={i} style={{borderBottom:`1px solid ${C.border}10`,padding:"4px 0",fontSize:11,display:"flex",gap:12,flexWrap:"wrap"}}>
              <span style={{color:C.muted}}>{r.ts}</span>
              <span style={{color:r.ok?C.green:C.red}}>{r.ok?"OK":"FAIL"}</span>
              <span style={{color:C.accent}}>{r.dpid?.slice(-8)||"?"}</span>
              <span style={{color:C.yellow}}>DSCP={r.dscp}</span>
              <span style={{color:C.muted}}>Q={r.queue_id}</span>
              {r.nw_src&&<span>src={r.nw_src}</span>}
              {r.nw_dst&&<span>dst={r.nw_dst}</span>}
            </div>
          ))}
        </div>
      </div>
      <div style={{width:260,...S.col}}>
        <div style={S.card}>
          <div style={S.title}>Traffic Class Presets</div>
          {DSCP_PRESETS.map(pr=>(
            <button key={pr.label} onClick={()=>setQosForm(f=>({...f,dscp:pr.dscp,queue_id:pr.queue,nw_proto:pr.proto,tp_dst:pr.port}))}
              style={{...S.btn,display:"block",width:"100%",marginBottom:6,textAlign:"left",padding:"8px 12px"}}>
              <div style={{fontWeight:700,fontSize:12}}>{pr.label}</div>
              <div style={{color:C.muted,fontSize:10,marginTop:2}}>{pr.desc}</div>
            </button>
          ))}
        </div>
        <div style={S.card}>
          <div style={S.title}>DSCP Quick Reference</div>
          {[["EF (46)","Expedited Fwd — VoIP"],["AF41 (34)","Assured Fwd — video"],
            ["CS3 (24)","Class Sel — signalling"],["AF21 (18)","Assured Fwd — interactive"],
            ["CS1 (8)", "Scavenger / bulk"],["BE (0)",  "Best effort — default"]].map(([code,desc])=>(
            <div key={code} style={{borderBottom:`1px solid ${C.border}15`,padding:"4px 0",fontSize:11}}>
              <span style={{color:C.accent,fontFamily:"monospace",marginRight:8}}>{code}</span>
              <span style={{color:C.muted}}>{desc}</span>
            </div>
          ))}
        </div>
        <div style={S.card}>
          <div style={S.title}>Port Utilization</div>
          {Object.entries(portUtil).map(([d,ports])=>(
            <div key={d} style={{marginBottom:8}}>
              <div style={{color:C.accent,fontSize:10,fontFamily:"monospace",marginBottom:3}}>{d}</div>
              {Object.entries(ports).map(([p,v])=>(
                <div key={p} style={{marginBottom:4}}>
                  <div style={{display:"flex",justifyContent:"space-between",fontSize:10}}>
                    <span style={{color:C.muted}}>Port {p}</span>
                    <span style={{color:v.util>80?C.red:v.util>50?C.orange:C.green}}>{v.util}%</span>
                  </div>
                  <Bar value={v.util} max={100} color={v.util>80?C.red:v.util>50?C.orange:C.green} height={4}/>
                </div>
              ))}
            </div>
          ))}
          {Object.keys(portUtil).length===0&&<div style={{color:C.muted,fontSize:11}}>No port stats yet</div>}
        </div>
      </div>
    </div>
  );

  // ── TAB: GRAPHS ──────────────────────────────────────────────────────────────
  const renderGraphs=()=>{
    const dpids=Object.keys(bwh);
    const selDpid=graphDpid||dpids[0]||"";
    const ports=Object.keys(bwh[selDpid]||{});
    const selPort=graphPort||ports[0]||"";
    const hist=Array.from(bwh[selDpid]?.[selPort]||[]);
    const cw=680,ch=200,pad=40;
    const maxVal=Math.max(...hist.map(d=>Math.max(d.rate_tx||0,d.rate_rx||0)),1);
    const xs=i=>pad+(i/Math.max(hist.length-1,1))*(cw-2*pad);
    const ys=v=>ch-pad-(v/maxVal)*(ch-2*pad);
    // Host BW from pkt stats
    const hostBwData=(pktStats.top_hosts||[]).slice(0,8);
    const maxHostBw=Math.max(...hostBwData.map(h=>h.tx_bytes+h.rx_bytes),1);
    // Controller sparkline
    const ctrlPerDpid=Object.entries(ctrlStats.per_dpid||{});
    return(
      <div style={S.col}>
        <div style={{display:"flex",gap:8,marginBottom:4,flexWrap:"wrap",alignItems:"center"}}>
          <select value={selDpid} onChange={e=>{setGraphDpid(e.target.value);setGraphPort("");}} style={S.inp}>
            {dpids.map(d=><option key={d} value={d}>{d}</option>)}
          </select>
          <select value={selPort} onChange={e=>setGraphPort(e.target.value)} style={S.inp}>
            {ports.map(p=><option key={p} value={p}>Port {p}</option>)}
          </select>
          <span style={{color:C.muted,fontSize:12}}>{hist.length} samples (~{Math.round(hist.length*3/60)}min)</span>
        </div>
        {/* Main BW chart */}
        <div style={S.card}>
          <div style={S.title}>Bandwidth — {selDpid.slice(-8)} Port {selPort}</div>
          {hist.length>1?(
            <>
              <svg width={cw} height={ch} style={{background:C.bg,borderRadius:6,display:"block",maxWidth:"100%"}}>
                {[0,.25,.5,.75,1].map((f,i)=>{const v=Math.round(maxVal*f/1000);const y=ys(maxVal*f);return(
                  <g key={i}><line x1={pad} y1={y} x2={cw-pad} y2={y} stroke={C.border} strokeDasharray="3,3" opacity={.4}/>
                    <text x={pad-4} y={y+4} fontSize={9} fill={C.muted} textAnchor="end">{v}K</text></g>
                );})}
                <polyline points={hist.map((d,i)=>`${xs(i)},${ys(d.rate_tx||0)}`).join(" ")} fill="none" stroke={C.green} strokeWidth={2}/>
                <polyline points={hist.map((d,i)=>`${xs(i)},${ys(d.rate_rx||0)}`).join(" ")} fill="none" stroke={C.orange} strokeWidth={2}/>
                <g transform={`translate(${cw-90},10)`}>
                  <rect width={10} height={10} fill={C.green}/><text x={14} y={9} fontSize={10} fill={C.text}>TX</text>
                  <rect y={16} width={10} height={10} fill={C.orange}/><text x={14} y={25} fontSize={10} fill={C.text}>RX</text>
                </g>
              </svg>
              <div style={{display:"flex",gap:24,marginTop:6,flexWrap:"wrap"}}>
                <span style={{color:C.green,fontSize:13}}>TX: {fB(hist[hist.length-1]?.rate_tx||0)}</span>
                <span style={{color:C.orange,fontSize:13}}>RX: {fB(hist[hist.length-1]?.rate_rx||0)}</span>
                <span style={{color:C.muted,fontSize:12}}>Util: {hist[hist.length-1]?.util||0}%</span>
              </div>
            </>
          ):<div style={{color:C.muted,padding:24,textAlign:"center"}}>No history — run traffic in Mininet</div>}
        </div>
        {/* ALL switches sparklines */}
        <div style={S.card}>
          <div style={S.title}>All Switches — Bandwidth Sparklines</div>
          <div style={{display:"flex",flexWrap:"wrap",gap:12}}>
            {dpids.map(d=>{
              const allPorts=Object.values(bwh[d]||{});
              const merged=[];
              const maxLen=Math.max(...allPorts.map(p=>Array.from(p).length),0);
              for(let i=0;i<maxLen;i++){
                let sum=0;
                allPorts.forEach(p=>{const arr=Array.from(p);if(arr[i])sum+=(arr[i].rate_tx||0)+(arr[i].rate_rx||0);});
                merged.push(sum);
              }
              return(
                <div key={d} style={{...S.card,padding:8,minWidth:170}}>
                  <div style={{display:"flex",justifyContent:"space-between",marginBottom:2}}>
                    <span style={{color:C.accent,fontSize:10,fontFamily:"monospace"}}>{d.slice(-8)}</span>
                    <span style={{color:heatColor(d),fontSize:10}}>{fB(swBwTotal[d]||0)}</span>
                  </div>
                  <SparkLine data={merged} color={heatColor(d)} width={165} height={40}/>
                </div>
              );
            })}
            {dpids.length===0&&<div style={{color:C.muted,fontSize:11}}>No bandwidth history yet</div>}
          </div>
        </div>
        {/* Hosts traffic chart */}
        <div style={S.card}>
          <div style={S.title}>Hosts — Total Traffic (TX+RX)</div>
          <div style={{display:"flex",flexWrap:"wrap",gap:12}}>
            {hostBwData.map((h,i)=>(
              <div key={i} style={{minWidth:180}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:10,marginBottom:3}}>
                  <span style={{color:C.accent,fontFamily:"monospace"}}>{h.ip||h.mac?.slice(-8)}</span>
                  <span style={{color:C.muted}}>{fS(h.tx_bytes+h.rx_bytes)}</span>
                </div>
                <div style={{display:"flex",gap:4,marginBottom:2}}>
                  <div style={{flex:h.tx_bytes||1,height:6,background:C.green,borderRadius:3,minWidth:2}}/>
                  <div style={{flex:h.rx_bytes||1,height:6,background:C.orange,borderRadius:3,minWidth:2}}/>
                </div>
                <div style={{display:"flex",gap:8,fontSize:9,color:C.muted}}>
                  <span style={{color:C.green}}>↑TX {fS(h.tx_bytes)}</span>
                  <span style={{color:C.orange}}>↓RX {fS(h.rx_bytes)}</span>
                </div>
              </div>
            ))}
            {hostBwData.length===0&&<div style={{color:C.muted,fontSize:11}}>No host traffic yet</div>}
          </div>
        </div>
        {/* Controller traffic per switch */}
        <div style={S.card}>
          <div style={S.title}>POX Controller — PacketIn per Switch</div>
          <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
            {ctrlPerDpid.map(([d,v])=>(
              <div key={d} style={{...S.card,padding:8,minWidth:160}}>
                <div style={{color:C.accent,fontSize:10,fontFamily:"monospace",marginBottom:4}}>{d.slice(-8)}</div>
                <div style={{color:C.cyan,fontSize:16,fontWeight:800,fontFamily:"monospace"}}>{v.count.toLocaleString()}</div>
                <div style={{color:C.muted,fontSize:10}}>PacketIn events</div>
                <div style={{color:C.purple,fontSize:12,fontFamily:"monospace"}}>{fS(v.bytes)}</div>
                <div style={{color:C.muted,fontSize:10}}>to controller</div>
              </div>
            ))}
            {ctrlPerDpid.length===0&&<div style={{color:C.muted,fontSize:11}}>No controller stats yet</div>}
          </div>
        </div>
        {/* Alert frequency histogram */}
        <div style={S.card}>
          <div style={S.title}>Alert Frequency — last 60 min</div>
          {(()=>{
            const now=Date.now()/1000;
            const bkts=Array(60).fill(0);
            (Array.isArray(alertTimeline)?alertTimeline:[]).forEach(a=>{
              if(a.ts){const age=now-a.ts;if(age<3600){const b=Math.floor(age/60);if(b<60)bkts[59-b]++;}}
            });
            const maxB=Math.max(...bkts,1);
            return<div>
              <div style={{display:"flex",gap:1,alignItems:"flex-end",height:60}}>
                {bkts.map((v,i)=><div key={i} style={{flex:1,height:Math.max(2,v/maxB*56),
                  background:v>5?C.red:v>2?C.orange:v>0?C.yellow:C.border,
                  borderRadius:"2px 2px 0 0"}} title={`${v} alerts at -${60-i}min`}/>)}
              </div>
              <div style={{display:"flex",justifyContent:"space-between",fontSize:9,color:C.muted,marginTop:4}}>
                <span>-60m</span><span>-30m</span><span>now</span>
              </div>
            </div>;
          })()}
        </div>
      </div>
    );
  };

  // ── TAB: TESTS ───────────────────────────────────────────────────────────────
  const TEST_TYPES=[
    {id:"ping",        label:"Ping",          icon:"🏓", desc:"ICMP echo — basic connectivity test"},
    {id:"ping_flood",  label:"Ping Flood",    icon:"💥", desc:"100 rapid pings — stress test / triggers ICMP flood alert"},
    {id:"traceroute",  label:"Traceroute",    icon:"🗺", desc:"Discover hop-by-hop path (triggers TTL anomaly alerts)"},
    {id:"iperf_tcp",   label:"iPerf TCP",     icon:"📶", desc:"TCP bandwidth test between two hosts"},
    {id:"iperf_udp",   label:"iPerf UDP",     icon:"📡", desc:"UDP bandwidth test at 10Mbps for 5s"},
    {id:"hping_syn",   label:"hping SYN scan",icon:"🔍", desc:"SYN scan on port 80 — triggers port scan alert"},
    {id:"hping_icmp",  label:"hping ICMP",    icon:"📨", desc:"100 ICMP packets via hping3"},
    {id:"nmap",        label:"Nmap Scan",     icon:"🔭", desc:"Service version scan ports 1-100"},
    {id:"nmap_ping",   label:"Nmap Ping",     icon:"📍", desc:"Ping sweep of target"},
    {id:"arp_scan",    label:"ARP Scan",      icon:"🔗", desc:"Discover all hosts via ARP"},
    {id:"dns",         label:"DNS Lookup",    icon:"🌐", desc:"nslookup — triggers DNS traffic"},
    {id:"wget",        label:"HTTP GET",      icon:"📥", desc:"wget HTTP request to target"},
    {id:"http_server",  label:"HTTP Server",   icon:"🖥", desc:"Start SimpleHTTPServer on source host (port 8080)"},
    {id:"http_client",  label:"HTTP Client",   icon:"🌐", desc:"curl HTTP request from src to dst:8080"},
    {id:"hping_udp",    label:"hping UDP",     icon:"💣", desc:"UDP flood attack via hping3"},
    {id:"hping_rand",   label:"hping Rand-Src",icon:"🎭", desc:"SYN flood with randomized source IPs (DDoS simulation)"},
    {id:"hping_land",   label:"hping LAND",    icon:"💥", desc:"LAND attack - src=dst spoofing"},
    {id:"hping_rst",    label:"hping RST",     icon:"❌",     desc:"TCP RST flood to disrupt sessions"},
    {id:"hping_xmas",   label:"hping Xmas",    icon:"🎄", desc:"Christmas tree scan (FIN+URG+PSH flags)"},
    {id:"tcp_connect",  label:"TCP Connect",   icon:"🔌", desc:"nc TCP connection test to port 80"},
    {id:"udp_flood",    label:"UDP Flood",     icon:"🌊", desc:"High-rate UDP flood for bandwidth stress"},
    {id:"arping",       label:"ARP Ping",      icon:"📡", desc:"Layer-2 ARP ping to discover host"},
    {id:"slowloris",    label:"Slowloris",     icon:"🐌", desc:"Slow HTTP attack simulation with hping3"},
    {id:"ssh_scan",     label:"SSH Scan",      icon:"🔑", desc:"Nmap SSH service detection scan"},
    {id:"port_sweep",   label:"Port Sweep",    icon:"🧹", desc:"Full port sweep 1-1024 with nmap"},
    {id:"os_detect",    label:"OS Detect",     icon:"💻", desc:"Nmap OS fingerprinting scan"},
    {id:"iperf_bidir",  label:"iPerf Bidir",   icon:"⇄",     desc:"Bidirectional bandwidth test"},
    {id:"packet_loss",  label:"Packet Loss",   icon:"📊", desc:"Ping with statistics to measure packet loss"},
    {id:"mtr",          label:"MTR Trace",     icon:"🗺", desc:"Network path trace with statistics (mtr)"},
  ];
  const runTest=async()=>{
    if(!testSrc||!testDst){setTestResult({error:"Set both source and destination"});return;}
    const r=await fetch(`/topo/test/run?type=${testType}&src=${encodeURIComponent(testSrc)}&dst=${encodeURIComponent(testDst)}&extra=${encodeURIComponent(testExtra)}`);
    const d=await r.json();
    setTestResult(d);
    setTestHistory(h=>[{...d,src:testSrc,dst:testDst,type:testType,ts:Date.now()/1000},...h.slice(0,19)]);
  };
  const renderTests=()=>{
    const hostList=raw.hosts||[];
    return(
      <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
        <div style={{flex:1,minWidth:300,...S.col}}>
          <div style={S.card}>
            <div style={S.title}>Network Test Launcher</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
              <div>
                <div style={{color:C.muted,fontSize:10,marginBottom:2}}>Source host name</div>
                <input placeholder="e.g. h1" value={testSrc} onChange={e=>setTestSrc(e.target.value)} style={{...S.inp,width:"100%",boxSizing:"border-box"}}/>
                <div style={{display:"flex",gap:3,marginTop:4,flexWrap:"wrap"}}>
                  {hostList.map(h=>{const hn=h.name||(h.ip?`h${h.ip.split(".").pop()}`:`h${h.sw_num||1}`);return<button key={h.mac} onClick={()=>setTestSrc(hn)} style={{...S.btn,padding:"1px 6px",fontSize:10}}>{hn}</button>;})}
                </div>
              </div>
              <div>
                <div style={{color:C.muted,fontSize:10,marginBottom:2}}>Destination host/IP</div>
                <input placeholder="e.g. h2 or 10.0.0.2" value={testDst} onChange={e=>setTestDst(e.target.value)} style={{...S.inp,width:"100%",boxSizing:"border-box"}}/>
                <div style={{display:"flex",gap:3,marginTop:4,flexWrap:"wrap"}}>
                  {hostList.map(h=>{const hn=h.name||(h.ip?`h${h.ip.split(".").pop()}`:`h${h.sw_num||1}`);return<button key={h.mac} onClick={()=>setTestDst(hn)} style={{...S.btn,padding:"1px 6px",fontSize:10}}>{hn}</button>;})}
                </div>
              </div>
            </div>
            <div style={{color:C.muted,fontSize:10,marginBottom:4}}>Test Type</div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:12}}>
              {TEST_TYPES.map(t=>(
                <button key={t.id} onClick={()=>setTestType(t.id)}
                  style={{...S.btn,background:testType===t.id?C.accent:C.navy,color:testType===t.id?"#000":C.text,padding:"5px 10px",fontSize:11}}>
                  {t.icon} {t.label}
                </button>
              ))}
            </div>
            {TEST_TYPES.find(t=>t.id===testType)&&(
              <div style={{color:C.muted,fontSize:11,marginBottom:8,fontStyle:"italic"}}>
                {TEST_TYPES.find(t=>t.id===testType).desc}
              </div>
            )}
            {(testType==="hping_syn"||testType==="hping_udp"||testType==="hping_rst"||testType==="tcp_connect"||testType==="ssh_scan"||testType==="dns"||testType==="http_server"||testType==="http_client")&&(
              <div style={{marginBottom:8}}>
                <div style={{color:C.muted,fontSize:10,marginBottom:2}}>
                  {testType==="dns"?"Domain to lookup":
                   testType==="http_server"?"Port (default 8080)":
                   testType==="http_client"?"Port on dst (default 8080)":
                   "Target port (default 80)"}
                </div>
                <input value={testExtra} onChange={e=>setTestExtra(e.target.value)}
                  placeholder={testType==="dns"?"google.com":testType==="http_server"||testType==="http_client"?"8080":"80"}
                  style={{...S.inp,width:200,boxSizing:"border-box"}}/>
              </div>
            )}
            <button onClick={runTest} style={{...S.btn,background:C.accent,color:"#000",fontWeight:700,padding:"8px 20px"}}>
              Run Test
            </button>
            {testResult&&(
              <div style={{...S.card,marginTop:12,border:`1px solid ${testResult.error?C.red:C.green}`}}>
                <div style={{color:testResult.error?C.red:C.green,fontWeight:700,marginBottom:6}}>
                  {testResult.error?"Error":"Command Ready"}
                </div>
                {testResult.error&&<div style={{color:C.red,fontSize:12}}>{testResult.error}</div>}
                {testResult.full_cmd&&(
                  <>
                    <div style={{color:C.muted,fontSize:11,marginBottom:4}}>Run this in Mininet terminal:</div>
                    <div style={{background:C.dark,borderRadius:6,padding:"6px 10px",marginBottom:4}}>
                      <span style={{color:C.muted,fontSize:11,userSelect:"none",marginRight:6}}>mininet&gt;</span>
                      <code style={{color:C.cyan,fontSize:12,wordBreak:"break-all"}}>{testResult.full_cmd}</code>
                    </div>
                    {testResult.note&&<div style={{color:C.muted,fontSize:10,marginTop:4}}>{testResult.note}</div>}
                    <div style={{display:"flex",gap:6,marginTop:6,flexWrap:"wrap"}}>
                      <button onClick={()=>navigator.clipboard?.writeText(testResult.full_cmd)}
                        style={{...S.btn,fontSize:11,background:C.accent,color:"#000"}}>&#128203; Copy Command</button>
                      {testResult.setup_cmds&&testResult.setup_cmds.map((sc,i)=>(
                        <button key={i} onClick={()=>navigator.clipboard?.writeText(sc)}
                          style={{...S.btn,fontSize:11,background:C.purple}}>Copy Setup {i+1}</button>
                      ))}
                    </div>
                    {testResult.setup_cmds&&(
                      <div style={{marginTop:8}}>
                        <div style={{color:C.yellow,fontSize:10,marginBottom:4}}>Setup commands (run first):</div>
                        {testResult.setup_cmds.map((sc,i)=>(
                          <div key={i} style={{background:C.dark,borderRadius:4,padding:"4px 8px",marginBottom:3}}>
                            <span style={{color:C.muted,fontSize:11,userSelect:"none",marginRight:6}}>mininet&gt;</span>
                            <code style={{color:C.yellow,fontSize:11}}>{sc}</code>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </div>
        <div style={{flex:"0 0 300px",...S.col}}>
          <div style={S.card}>
            <div style={S.title}>Test History</div>
            {testHistory.length===0&&<div style={{color:C.muted,fontSize:11}}>No tests run yet</div>}
            {testHistory.map((t,i)=>(
              <div key={i} style={{borderBottom:`1px solid ${C.border}10`,padding:"6px 0"}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:2}}>
                  <span style={{color:C.accent,fontWeight:700,fontSize:11}}>{TEST_TYPES.find(x=>x.id===t.type)?.icon} {t.type}</span>
                  <span style={{color:C.muted,fontSize:10}}>{new Date(t.ts*1000).toLocaleTimeString()}</span>
                </div>
                <div style={{color:C.muted,fontSize:10}}>{t.src} → {t.dst}</div>
                <code style={{display:"block",background:C.dark,color:C.cyan,padding:"3px 6px",borderRadius:4,fontSize:10,marginTop:3,wordBreak:"break-all"}}>{t.full_cmd}</code>
              </div>
            ))}
          </div>
          <div style={S.card}>
            <div style={S.title}>What Each Test Triggers</div>
            <div style={{fontSize:11,color:C.muted,lineHeight:1.7}}>
              {[["Ping","→ ICMP in Packets tab"],["Ping Flood","→ ICMP flood alert"],
                ["Traceroute","→ TTL anomaly alerts"],["iPerf TCP","→ TCP sessions"],
                ["iPerf UDP","→ UDP bandwidth burst"],["hping SYN","→ Port scan alert"],
                ["hping ICMP","→ ICMP storm"],["hping UDP","→ UDP flood alert"],
                ["hping Rand-Src","→ DDoS simulation"],["hping LAND","→ LAND attack"],
                ["hping RST","→ TCP RST flood"],["hping Xmas","→ Xmas tree scan"],
                ["Nmap","→ Port scan alert"],["OS Detect","→ Fingerprint probe"],
                ["ARP Scan","→ ARP flood alert"],["Slowloris","→ HTTP slow attack"],
                ["HTTP Server","→ starts web server on host"],
                ["HTTP Client","→ HTTP GET request"],
                ["UDP Flood","→ bandwidth saturation"],
                ["Packet Loss","→ link quality stats"]
              ].map(([k,v])=>(
                <div key={k} style={{borderBottom:`1px solid ${C.border}18`,padding:"2px 0"}}><span style={{color:C.text,fontWeight:700}}>{k}</span> <span>{v}</span></div>
              ))}
            </div>
          </div>
          <div style={S.card}>
            <div style={S.title}>📚 Mininet Service Cheatsheet</div>
            <div style={{fontSize:11,color:C.muted,lineHeight:1.8}}>
              <div style={{color:C.yellow,fontWeight:700,marginBottom:4}}>HTTP Server on a host:</div>
              <code style={{display:"block",background:C.dark,color:C.cyan,padding:"4px 8px",borderRadius:4,marginBottom:8,fontSize:11}}>h1 python3 -m http.server 8080 &</code>
              <code style={{display:"block",background:C.dark,color:C.cyan,padding:"4px 8px",borderRadius:4,marginBottom:8,fontSize:11}}>h2 curl http://10.0.0.1:8080/</code>
              <div style={{color:C.yellow,fontWeight:700,marginBottom:4}}>iPerf Server+Client:</div>
              <code style={{display:"block",background:C.dark,color:C.cyan,padding:"4px 8px",borderRadius:4,marginBottom:8,fontSize:11}}>h1 iperf -s &amp;  h2 iperf -c 10.0.0.1</code>
              <div style={{color:C.yellow,fontWeight:700,marginBottom:4}}>Stop background services:</div>
              <code style={{display:"block",background:C.dark,color:C.cyan,padding:"4px 8px",borderRadius:4,marginBottom:8,fontSize:11}}>h1 kill %1</code>
              <div style={{color:C.yellow,fontWeight:700,marginBottom:4}}>Open host terminal:</div>
              <code style={{display:"block",background:C.dark,color:C.cyan,padding:"4px 8px",borderRadius:4,marginBottom:8,fontSize:11}}>xterm h1</code>
              <div style={{color:C.yellow,fontWeight:700,marginBottom:4}}>netcat listener/sender:</div>
              <code style={{display:"block",background:C.dark,color:C.cyan,padding:"4px 8px",borderRadius:4,marginBottom:4,fontSize:11}}>h1 nc -l 9999 &amp;  h2 echo "hello" | nc 10.0.0.1 9999</code>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // ── TAB: CMDLOG ──────────────────────────────────────────────────────────────
  const renderCmdlog=()=>(
    <div>
      <div style={{display:"flex",justifyContent:"space-between",marginBottom:12,alignItems:"center",flexWrap:"wrap",gap:8}}>
        <span style={{color:C.text,fontWeight:700}}>{cmdlog.length} logged commands</span>
        <div style={{display:"flex",gap:8}}>
          <button onClick={async()=>{
            const cmd=prompt("Enter command to log manually:");
            if(cmd){await fetch("/topo/cmdlog/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cmd,source:"manual"})});pollCmdlog();}
          }} style={S.btn}>+ Add Manual</button>
          <button onClick={async()=>{await fetch("/topo/cmdlog/clear",{method:"POST"});setCmdlog([]);lastCmdRef.current=0;}} style={{...S.btn,background:C.red}}>Clear</button>
        </div>
      </div>
      <div style={{...S.card,marginBottom:12,padding:8}}>
        <div style={{color:C.muted,fontSize:11,marginBottom:6}}>
          <strong style={{color:C.yellow}}>About command monitoring:</strong> This log captures:
          (1) OpenFlow events — switch connections, flow installs/deletions,
          (2) Operator actions — QoS rules, block-host, flow additions,
          (3) Test launcher commands you generate above,
          (4) Manual entries. To monitor real Mininet commands, pipe them via the REST API
          or use the "Add Manual" button.
        </div>
        <code style={{fontSize:11,color:C.cyan,background:C.dark,padding:6,borderRadius:4,display:"block"}}>
          # To auto-log Mininet commands, add to your custom topo:<br/>
          # import requests; requests.post("http://localhost:8000/topo/cmdlog/add", json={"{"}cmd": cmd, "source": "mininet"{"}"})
        </code>
      </div>
      <div style={{fontFamily:"monospace",fontSize:11}}>
        {[...cmdlog].reverse().map((c,i)=>(
          <div key={i} style={{display:"flex",gap:10,padding:"4px 0",borderBottom:`1px solid ${C.border}10`,alignItems:"flex-start"}}>
            <span style={{color:C.muted,flexShrink:0,width:70}}>{new Date(c.ts*1000).toLocaleTimeString()}</span>
            <span style={{...S.pill,flexShrink:0,
              background:(c.source==="controller"?C.accent:c.source==="operator"?C.orange:c.source==="test-tool"?C.purple:C.muted)+"25",
              color:c.source==="controller"?C.accent:c.source==="operator"?C.orange:c.source==="test-tool"?C.purple:C.muted}}>
              {c.source}
            </span>
            <span style={{color:C.text,flex:1,wordBreak:"break-all"}}>{c.cmd}</span>
          </div>
        ))}
        {cmdlog.length===0&&<div style={{color:C.muted,textAlign:"center",padding:32}}>No commands logged yet</div>}
      </div>
    </div>
  );

  // ── TAB: EVENTS ──────────────────────────────────────────────────────────────
  const renderEvents=()=>(
    <div>
      <div style={{display:"flex",justifyContent:"space-between",marginBottom:8,alignItems:"center"}}>
        <span style={{color:C.text,fontWeight:700}}>{events.length} Events</span>
        <button onClick={()=>setEvents([])} style={S.btn}>Clear</button>
      </div>
      <div style={{maxHeight:640,overflowY:"auto",fontFamily:"monospace",fontSize:11}}>
        {[...events].reverse().map((e,i)=>(
          <div key={i} style={{display:"flex",gap:8,padding:"4px 0",borderBottom:`1px solid ${C.border}10`}}>
            <span style={{color:C.muted,flexShrink:0}}>{new Date(e.ts*1000).toLocaleTimeString()}</span>
            <span style={{...S.pill,flexShrink:0,
              background:(e.level==="warn"?C.orange:e.level==="error"?C.red:C.green)+"20",
              color:e.level==="warn"?C.orange:e.level==="error"?C.red:C.green}}>{e.level||"info"}</span>
            <span style={{color:e.level==="warn"?C.orange:e.level==="error"?C.red:C.text,flex:1}}>{e.msg}</span>
          </div>
        ))}
        {events.length===0&&<div style={{color:C.muted,textAlign:"center",padding:32}}>No events yet</div>}
      </div>
    </div>
  );

  // ── TAB: REPORTS ─────────────────────────────────────────────────────────────
  const generateReport=()=>{
    const now=Date.now()/1000;const cutoff=now-reportRange;
    const recent=alerts.filter(a=>a.ts>=cutoff);
    const s=summary||{};const al=s.alerts||{};
    const byType={};recent.forEach(a=>{byType[a.type]=(byType[a.type]||0)+a.count;});
    const topThreat=hostIntel.filter(h=>h.threat_score>0).sort((a,b)=>b.threat_score-a.threat_score).slice(0,5);
    const topTalk=talkers.slice(0,8);
    const protoPct=p=>pktStats.total?Math.round((pktStats[p]||0)/pktStats.total*100):0;
    const period=[[300,"5 min"],[900,"15 min"],[3600,"1 hour"],[21600,"6 hours"],[86400,"24 hours"]].find(([v])=>v===reportRange);
    const lines=[
      "=".repeat(65),
      "  SDN NETWORK SECURITY & PERFORMANCE REPORT",
      "  Generated : "+new Date().toLocaleString(),
      "  Period    : "+( period?period[1]:"custom"),
      "  Platform  : POX OpenFlow Controller + Mininet",
      "=".repeat(65),"",
      "1. NETWORK OVERVIEW",
      "-".repeat(50),
      "  Active Switches    : "+(s.switches||0),
      "  Active Hosts       : "+(s.hosts||0),
      "  Links UP           : "+edges.filter(e=>e.status!=="down").length,
      "  Links DOWN         : "+Object.keys(downRef.current).length,
      "  Module Uptime      : "+fAge(s.uptime||0),
      "  Total Packets Seen : "+((s.packets_total||0).toLocaleString()),
      "  Current Bandwidth  : "+fB(s.total_bandwidth||0),
      "  Active TCP/UDP Sess: "+(s.active_connections||0),
      "  Ctrl PacketIn count: "+((s.ctrl_packetin||0).toLocaleString()),
      "  Ctrl Bytes to ctrl : "+fS(s.ctrl_total_bytes||0),
      "",
      "2. ALERT SUMMARY (period: "+( period?period[1]:"custom")+")",
      "-".repeat(50),
      "  Total Alerts    : "+recent.length,
      "  Critical        : "+recent.filter(a=>a.severity==="critical").length,
      "  High            : "+recent.filter(a=>a.severity==="high").length,
      "  Medium          : "+recent.filter(a=>a.severity==="medium").length,
      "  Low             : "+recent.filter(a=>a.severity==="low").length,
      "  Currently Active: "+activeAlerts.length,
      "",
      "3. ALERT BREAKDOWN BY TYPE",
      "-".repeat(50),
      ...Object.entries(byType).sort((a,b)=>b[1]-a[1]).map(([t,c])=>`  ${t.replace(/_/g," ").padEnd(24)} ${c.toString().padStart(5)} occurrences`),
      byType&&Object.keys(byType).length===0?"  None in period":"",
      "",
      "4. TOP THREAT HOSTS",
      "-".repeat(50),
      ...topThreat.map(h=>`  ${(h.ip||h.mac||"?").padEnd(20)} Score:${String(h.threat_score||0).padStart(3)}  Alerts:${h.alert_count||0}  Protocols:${(h.protocols||[]).join(",")}`),
      topThreat.length===0?"  No threat hosts detected":"",
      "",
      "5. RECENT CRITICAL ALERTS",
      "-".repeat(50),
      ...recent.filter(a=>a.severity==="critical").slice(0,15).map(a=>
        `  [${new Date(a.ts*1000).toLocaleTimeString()}] ${a.type}: ${a.msg}\n`+
        `    MITRE: ${a.mitre||"N/A"}  URL: ${a.mitre_url||"N/A"}`
      ),
      recent.filter(a=>a.severity==="critical").length===0?"  None":"",
      "",
      "6. PROTOCOL DISTRIBUTION",
      "-".repeat(50),
      ...["arp","icmp","tcp","udp","other"].map(p=>`  ${p.toUpperCase().padEnd(8)} ${String(pktStats[p]||0).padStart(8)} pkts  (${protoPct(p)}%)`),
      `${"  TOTAL".padEnd(17)} ${String(pktStats.total||0).padStart(8)} pkts`,
      "",
      "7. TOP TALKERS",
      "-".repeat(50),
      ...topTalk.map((t,i)=>`  ${i+1}. ${t.src.padEnd(16)} -> ${t.dst.padEnd(16)} ${fS(t.bytes).padStart(10)}  ${t.pkts} pkts`),
      topTalk.length===0?"  No traffic recorded":"",
      "",
      "8. SWITCH STATUS",
      "-".repeat(50),
      ...(raw.switches||[]).map((sw,i)=>`  s${i+1} ${sw.dpid.padEnd(20)} uptime:${fAge(swUptime[sw.dpid]?.uptime_secs||0).padStart(8)}  BW:${fB(swBwTotal[sw.dpid]||0).padStart(10)}  flows:${sw.flow_count||0}`),
      "",
      "9. PORT UTILIZATION",
      "-".repeat(50),
      ...Object.entries(portUtil).map(([d,ports])=>
        `  ${d}:\n`+Object.entries(ports).map(([p,v])=>`    Port ${p}: ${v.util}% util  TX:${fB(v.rate_tx)}  RX:${fB(v.rate_rx)}  drop:${v.rx_drop}`).join("\n")
      ),
      "",
      "10. ACTIVE SESSIONS SUMMARY",
      "-".repeat(50),
      "  Total sessions    : "+connections.length,
      "  ESTABLISHED       : "+connections.filter(c=>c.state==="ESTAB").length,
      "  SYN (half-open)   : "+connections.filter(c=>c.state==="SYN").length,
      "  CLOSED            : "+connections.filter(c=>c.state==="CLOSED").length,
      "  Total bytes       : "+fS(connections.reduce((s,c)=>s+(c.bytes||0),0)),
      "",
      "=".repeat(65),
      "  END OF REPORT",
      "  SDN Topology Visualizer  |  POX Controller  |  Mininet",
      "=".repeat(65),
    ];
    setReportText(lines.join("\n"));
  };
  const renderReports=()=>(
    <div>
      <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
        <select value={reportRange} onChange={e=>setReportRange(Number(e.target.value))} style={S.inp}>
          {[[300,"Last 5 min"],[900,"Last 15 min"],[3600,"Last 1 hour"],[21600,"Last 6 hours"],[86400,"Last 24 hours"]].map(([v,l])=>(
            <option key={v} value={v}>{l}</option>
          ))}
        </select>
        <button onClick={generateReport} style={{...S.btn,background:C.accent,color:"#000",fontWeight:700}}>Generate Report</button>
        {reportText&&<button onClick={()=>navigator.clipboard?.writeText(reportText)} style={S.btn}>Copy</button>}
        {reportText&&<button onClick={()=>{
          const blob=new Blob([reportText],{type:"text/plain"});
          const url=URL.createObjectURL(blob);const a=document.createElement("a");
          a.href=url;a.download=`sdn-report-${Date.now()}.txt`;a.click();URL.revokeObjectURL(url);
        }} style={{...S.btn,background:C.green}}>Download .txt</button>}
        {reportText&&<button onClick={()=>{
          // Simple HTML report for printing
          const html=`<!DOCTYPE html><html><head><title>SDN Report</title><style>body{font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px;white-space:pre}</style></head><body>${reportText}</body></html>`;
          const w=window.open("","_blank");if(w){w.document.write(html);w.document.close();}
        }} style={{...S.btn,background:C.purple}}>Print View</button>}
      </div>
      {reportText?(
        <pre style={{...S.card,fontSize:11,fontFamily:"monospace",whiteSpace:"pre",overflowX:"auto",
          color:C.text,lineHeight:1.6,maxHeight:700,overflowY:"auto",background:C.dark,border:`1px solid ${C.border}`}}>
          {reportText}
        </pre>
      ):<div style={{...S.card,color:C.muted,textAlign:"center",padding:48,fontSize:13}}>
        Click "Generate Report" to create a full security &amp; performance report
      </div>}
    </div>
  );

  // ── TAB: EXPORT ──────────────────────────────────────────────────────────────
  const renderExport=()=>{
    const download=(data,fname,type)=>{
      const blob=new Blob([typeof data==="string"?data:JSON.stringify(data,null,2)],{type});
      const url=URL.createObjectURL(blob);
      const a=document.createElement("a");a.href=url;a.download=fname;
      document.body.appendChild(a);a.click();
      document.body.removeChild(a);URL.revokeObjectURL(url);
    };
    const exportCSV=(rows,headers,fname)=>{
      const lines=[headers.join(","),...rows.map(r=>headers.map(h=>`"${String(r[h]||"").replace(/"/g,'""')}"`).join(","))];
      download(lines.join("\n"),fname,"text/csv");
    };
    const exportSVG=()=>{
      let content=null;
      if(svgRef.current){
        try{
          const clone=svgRef.current.cloneNode(true);
          clone.setAttribute("xmlns","http://www.w3.org/2000/svg");
          clone.setAttribute("style","background:#0d1117");
          content=new XMLSerializer().serializeToString(clone);
          setSvgData(content);
        }catch(_){}
      }else{
        content=svgData;
      }
      if(!content){alert("Topology SVG not captured yet \u2014 open the Topology tab for a few seconds first");return;}
      const svgBlob=new Blob([content],{type:"image/svg+xml;charset=utf-8"});
      const url=URL.createObjectURL(svgBlob);
      const a=document.createElement("a");a.href=url;a.download=`topology-${Date.now()}.svg`;
      document.body.appendChild(a);a.click();
      document.body.removeChild(a);URL.revokeObjectURL(url);
    };
    const exports=[
      {label:"Topology JSON",     desc:"Switches + links + hosts snapshot",         color:C.accent,
        fn:()=>download({switches:raw.switches,links:raw.links,hosts:raw.hosts,ts:Date.now()/1000},"topology.json","application/json")},
      {label:"Topology SVG",      desc:"Canvas vector image (auto-captured when Topology tab opened)",color:C.cyan, fn:exportSVG},
      {label:"Alerts JSON",       desc:"All alerts with MITRE ATT&CK tags",          color:C.red,
        fn:()=>download(alerts,"alerts.json","application/json")},
      {label:"Packets CSV",       desc:"All captured packets as CSV",                color:C.orange,
        fn:()=>{
        const hdrs=["id","ts","proto","src_ip","dst_ip","src_mac","dst_mac","len","flags","ttl","sp","dp","sw","port","info"];const csvLines=[hdrs.join(","),...allPackets.map(r=>hdrs.map(h=>`"${String(r[h]||"").replace(/"/g,'""')}"`).join(","))];const blob=new Blob([csvLines.join("\n")],{type:"text/csv"});
        const url=URL.createObjectURL(blob);const a=document.createElement("a");
        a.href=url;a.download=`packets-all-${allPackets.length}-${Date.now()}.csv`;
        document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
      }},
      {label:"Flows JSON",        desc:"OpenFlow rules from all switches",           color:C.green,
        fn:()=>download(flows,"flows.json","application/json")},
      {label:"Sessions CSV",      desc:"Active TCP/UDP sessions",                    color:C.purple,
        fn:()=>exportCSV(connections,["state","proto","src_ip","src_port","dst_ip","dst_port","bytes","pkts","duration"],"sessions.csv")},
      {label:"Host Intel JSON",   desc:"Per-host stats & threat scores",             color:C.yellow,
        fn:()=>download(hostIntel,"hostintel.json","application/json")},
      {label:"Command Log CSV",   desc:"All logged controller/operator commands",    color:C.teal,
        fn:()=>exportCSV(cmdlog,["ts","source","cmd"],"cmdlog.csv")},
      {label:"Alert Timeline",    desc:"Alert history for timeline analysis",        color:C.pink,
        fn:()=>download(alertTimeline,"alert-timeline.json","application/json")},
      {label:"Top Talkers JSON",  desc:"Source-destination traffic pairs",           color:C.muted,
        fn:()=>download(talkers,"talkers.json","application/json")},
      {label:"Full Snapshot JSON",desc:"Complete state snapshot for analysis",       color:C.text,
        fn:()=>download({topology:raw,alerts,packets:allPackets.slice(-500),flows,connections,talkers,hostIntel,summary,cmdlog,ctrlStats,ts:Date.now()/1000},"full-snapshot.json","application/json")},
    ];
    return(
      <div>
        <div style={{...S.card,marginBottom:12,border:`1px solid ${C.teal}`}}>
          <div style={{color:C.teal,fontWeight:700,marginBottom:4}}>SVG Export Note</div>
          <div style={{color:C.muted,fontSize:11}}>For Topology SVG to work, visit the Topology tab first so the SVG canvas renders, then come back here and click Download.</div>
        </div>
        <div style={{display:"flex",flexWrap:"wrap",gap:10}}>
          {exports.map(({label,desc,color,fn})=>(
            <div key={label} style={{...S.card,width:195}}>
              <div style={{color,fontWeight:700,marginBottom:4,fontSize:12}}>{label}</div>
              <div style={{color:C.muted,fontSize:10,marginBottom:10}}>{desc}</div>
              <button onClick={fn} style={{...S.btn,background:color,
                color:(color===C.yellow||color===C.text||color===C.cyan)?"#000":"#fff",
                fontWeight:700,width:"100%",padding:"6px"}}>Download</button>
            </div>
          ))}
        </div>
      </div>
    );
  };

  // ── TAB BAR + ROOT RENDER ───────────────────────────────────────────────────
// ── TAB: SIMULATE ────────────────────────────────────────────────────────────
  const renderSimulate=()=>{
    const scenarios=[
      {id:"ddos",     icon:"💣", label:"DDoS Simulation",    color:"#f85149",
       steps:["h3 hping3 --rand-source -S -p 80 --flood h1",
               "h4 hping3 --rand-source -S -p 80 --flood h1",
               "h5 hping3 --rand-source -S -p 80 --flood h1"],
       desc:"Three hosts flood a target with spoofed SYN packets. Triggers port-scan + flood alerts.",
       observe:"ALERTS tab: SYN flood  |  PACKETS: TCP spike  |  THREATS: h1 score rises"},
      {id:"portscan", icon:"🔍", label:"Port Scan Attack",   color:"#f0883e",
       steps:["h2 nmap -sV -p 1-1024 h1"],
       desc:"Comprehensive service version scan. Triggers port scan SIEM alert.",
       observe:"ALERTS: port-scan high  |  FLOWS: new block rule  |  THREATS: h2 flagged"},
      {id:"mitm",     icon:"🕵", label:"ARP Poisoning Sim",  color:"#bc8cff",
       steps:["h2 arp-scan --localnet","h2 hping3 --icmp h1 -c 50"],
       desc:"ARP sweep + ICMP flood simulating man-in-the-middle setup steps.",
       observe:"ALERTS: ARP flood  |  PACKETS: ARP burst  |  SESSIONS: suspicious flows"},
      {id:"slowloris",icon:"🐌", label:"Slowloris HTTP",     color:"#e3b341",
       steps:["h1 python3 -m http.server 8080 &",
               "h2 hping3 -S --flood -p 8080 h1"],
       desc:"Start HTTP server then overwhelm with SYN packets on HTTP port.",
       observe:"ALERTS: flood + port-scan  |  QoS: port 8080 saturation"},
      {id:"reconn",   icon:"🧭", label:"Reconnaissance",     color:"#39d353",
       steps:["h3 nmap -sn 10.0.0.0/24","h3 nmap -O h1","h3 traceroute h1"],
       desc:"Network mapping, OS detection, and path trace from h3.",
       observe:"ALERTS: port-scan  |  HOSTS: h3 threat score rises"},
      {id:"bwtest",   icon:"📈", label:"Bandwidth Stress",   color:"#58a6ff",
       steps:["h1 iperf -s &","h2 iperf -c h1 -P 4 -t 30",
               "h3 iperf -c h1 -u -b 50M -t 30"],
       desc:"Parallel TCP + UDP bandwidth stress test against h1.",
       observe:"GRAPHS: bandwidth spike  |  QoS: congestion  |  SESSIONS: large flows"},
      {id:"exfil",    icon:"📤", label:"Data Exfil Sim",     color:"#ff7b72",
       steps:["h1 python3 -m http.server 8080 &",
               "h2 wget -q -O /dev/null http://10.0.0.1:8080/",
               "h2 wget -q --tries=20 -O /dev/null http://10.0.0.1:8080/"],
       desc:"Simulate data exfiltration with repeated large HTTP transfers.",
       observe:"SESSIONS: large TCP flow  |  HOSTS: high TX bytes  |  THREATS: h2 risk"},
    ];
    const sel=scenarios.find(s=>s.id===simSel);
    return(
      <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
        <div style={{flex:1,minWidth:300}}>
          <div style={S.card}>
            <div style={S.title}>🎯 Attack & Test Scenarios</div>
            <div style={{fontSize:11,color:C.muted,marginBottom:10}}>Select a scenario to see step-by-step Mininet commands. All commands use host names (h1-h8).</div>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {scenarios.map(sc=>(
                <div key={sc.id} onClick={()=>setSimSel(sc.id===simSel?null:sc.id)}
                  style={{...S.card,cursor:"pointer",border:`1px solid ${simSel===sc.id?sc.color:C.border}`,
                    background:simSel===sc.id?sc.color+"15":C.card}}>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <span style={{fontSize:18}}>{sc.icon}</span>
                    <span style={{color:sc.color,fontWeight:700,fontSize:12}}>{sc.label}</span>
                    <span style={{color:C.muted,fontSize:10,marginLeft:"auto"}}>{sc.steps.length} step{sc.steps.length!==1?"s":""}</span>
                  </div>
                  {simSel===sc.id&&(
                    <div style={{marginTop:8}}>
                      <div style={{color:C.muted,fontSize:11,marginBottom:6,fontStyle:"italic"}}>{sc.desc}</div>
                      {sc.steps.map((step,i)=>(
                        <div key={i} style={{marginBottom:6}}>
                          <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:2}}>
                            <span style={{color:sc.color,fontSize:10,fontWeight:700}}>Step {i+1}</span>
                            <button onClick={e=>{e.stopPropagation();navigator.clipboard?.writeText(step);}}
                              style={{...S.btn,padding:"1px 8px",fontSize:10,background:sc.color,color:"#000"}}>Copy</button>
                          </div>
                          <div style={{background:C.dark,borderRadius:4,padding:"5px 10px"}}>
                            <span style={{color:C.muted,fontSize:11,marginRight:6,userSelect:"none"}}>mininet&gt;</span>
                            <code style={{color:C.cyan,fontSize:11}}>{step}</code>
                          </div>
                        </div>
                      ))}
                      <div style={{marginTop:8,background:sc.color+"10",border:`1px solid ${sc.color}30`,
                        borderRadius:6,padding:8}}>
                        <div style={{color:sc.color,fontSize:10,fontWeight:700,marginBottom:2}}>📊 What to observe:</div>
                        <div style={{color:C.muted,fontSize:11}}>{sc.observe}</div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
        <div style={{flex:"0 0 280px",display:"flex",flexDirection:"column",gap:12}}>
          <div style={S.card}>
            <div style={S.title}>⚠️ Before Running Attacks</div>
            <div style={{fontSize:11,color:C.muted,lineHeight:1.8}}>
              <div style={{color:C.yellow,fontWeight:700,marginBottom:6}}>ℹ️ Safety Notes</div>
              {["Run only in isolated Mininet environment","hping3 must be installed: apt install hping3",
                "nmap must be installed: apt install nmap","For HTTP tests: python3 available by default",
                "Kill background services: h1 kill %1","Reset network: sudo mn -c",
                "Monitor ALERTS tab during attacks"].map((n,i)=>(
                <div key={i} style={{padding:"2px 0",borderBottom:`1px solid ${C.border}18`}}>
                  • {n}
                </div>
              ))}
            </div>
          </div>
          <div style={S.card}>
            <div style={S.title}>🔧 Quick Reset Commands</div>
            {[["Flush flows","sh ovs-ofctl del-flows s1"],
              ["Kill iperf","h1 kill %1"],
              ["Stop HTTP srv","h1 kill %1"],
              ["Full reset","exit (then sudo mn -c)"],
              ["Clear ARP","h1 ip neigh flush all"]
            ].map(([label,cmd])=>(
              <div key={label} style={{display:"flex",justifyContent:"space-between",alignItems:"center",
                borderBottom:`1px solid ${C.border}18`,padding:"4px 0"}}>
                <span style={{color:C.muted,fontSize:10}}>{label}</span>
                <div style={{display:"flex",alignItems:"center",gap:4}}>
                  <code style={{color:C.cyan,fontSize:10}}>{cmd}</code>
                  <button onClick={()=>navigator.clipboard?.writeText(cmd)}
                    style={{...S.btn,padding:"1px 6px",fontSize:9}}>⧉</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  // ── TAB: NET CALCULATOR ───────────────────────────────────────────────────────
  const renderNetCalc=()=>{
    const calcSubnet=()=>{
      try{
        const [ip,prefix]=cidr.split("/");
        const pLen=parseInt(prefix);
        if(isNaN(pLen)||pLen<0||pLen>32)throw new Error("Invalid prefix");
        const parts=ip.split(".").map(Number);
        if(parts.length!==4||parts.some(p=>isNaN(p)||p<0||p>255))throw new Error("Invalid IP");
        const mask=(pLen===0)?0:(0xFFFFFFFF<<(32-pLen))>>>0;
        const ipInt=((parts[0]<<24)|(parts[1]<<16)|(parts[2]<<8)|parts[3])>>>0;
        const network=(ipInt&mask)>>>0;
        const broadcast=(network|(~mask>>>0))>>>0;
        const toIP=n=>[(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join(".");
        const hosts=pLen>=31?pLen===32?1:2:Math.pow(2,32-pLen)-2;
        setCalcResult({
          network:toIP(network)+"/"+pLen,
          mask:toIP(mask),
          broadcast:toIP(broadcast),
          first:pLen<31?toIP(network+1):toIP(network),
          last:pLen<31?toIP(broadcast-1):toIP(broadcast),
          hosts:hosts.toLocaleString(),
          wildcard:toIP(~mask>>>0),
          pLen,
          ipClass:parts[0]<128?"A":parts[0]<192?"B":parts[0]<224?"C":"D/E"
        });
      }catch(e){setCalcResult({error:e.message});}
    };
    return(
      <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
        <div style={{flex:1,minWidth:280}}>
          <div style={S.card}>
            <div style={S.title}>🖧 Subnet Calculator</div>
            <div style={{display:"flex",gap:8,marginBottom:12,alignItems:"center"}}>
              <input value={cidr} onChange={e=>setCidr(e.target.value)} placeholder="10.0.0.0/24"
                style={{...S.inp,flex:1}} onKeyDown={e=>e.key==="Enter"&&calcSubnet()}/>
              <button onClick={calcSubnet} style={{...S.btn,background:C.accent,color:"#000",fontWeight:700}}>Calculate</button>
            </div>
            {calcResult&&!calcResult.error&&(
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
                {[["Network",calcResult.network],["Subnet Mask",calcResult.mask],
                  ["Broadcast",calcResult.broadcast],["Wildcard Mask",calcResult.wildcard],
                  ["First Host",calcResult.first],["Last Host",calcResult.last],
                  ["Usable Hosts",calcResult.hosts],["IP Class",calcResult.ipClass]
                ].map(([k,v])=>(
                  <div key={k} style={{background:C.dark,borderRadius:4,padding:"6px 8px"}}>
                    <div style={{color:C.muted,fontSize:9,textTransform:"uppercase",letterSpacing:0.5}}>{k}</div>
                    <div style={{color:C.accent,fontSize:13,fontFamily:"monospace",fontWeight:700}}>{v}</div>
                  </div>
                ))}
              </div>
            )}
            {calcResult?.error&&<div style={{color:C.red,fontSize:12}}>⚠️ {calcResult.error}</div>}
            <div style={{marginTop:12}}>
              <div style={{color:C.muted,fontSize:10,marginBottom:6}}>Common subnets:</div>
              <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
                {["/8","/16","/24","/25","/26","/28","/30","/32"].map(p=>(
                  <button key={p} onClick={()=>{const base=cidr.split("/")[0];setCidr(base+p);}}
                    style={{...S.btn,padding:"2px 8px",fontSize:10}}>{p}</button>
                ))}
              </div>
            </div>
          </div>
        </div>
        <div style={{flex:1,minWidth:280}}>
          <div style={S.card}>
            <div style={S.title}>📖 Mininet IP Reference</div>
            <div style={{fontSize:11,color:C.muted,lineHeight:1.9}}>
              <div style={{color:C.yellow,fontWeight:700,marginBottom:4}}>Default IP Assignment</div>
              {(raw.hosts||[]).slice(0,12).map((h,i)=>(
                <div key={i} style={{display:"flex",justifyContent:"space-between",
                  borderBottom:`1px solid ${C.border}18`,padding:"2px 0"}}>
                  <span style={{color:C.accent,fontFamily:"monospace"}}>
                    h{h.ip?h.ip.split(".").pop():h.sw_num||i+1}
                  </span>
                  <span style={{color:C.text,fontFamily:"monospace"}}>{h.ip||"?"}</span>
                  <span style={{color:C.muted,fontSize:10}}>{h.mac}</span>
                </div>
              ))}
              {!(raw.hosts||[]).length&&<div style={{color:C.muted}}>No hosts detected — start Mininet</div>}
            </div>
          </div>
          <div style={{...S.card,marginTop:12}}>
            <div style={S.title}>📋 OpenFlow Port Reference</div>
            <div style={{fontSize:11,lineHeight:1.9}}>
              {[["OFPP_IN_PORT","65528","Forward to input port"],
                ["OFPP_TABLE","65529","Submit to flow table"],
                ["OFPP_NORMAL","65530","Normal L2/L3 switching"],
                ["OFPP_FLOOD","65531","Flood to all non-source ports"],
                ["OFPP_ALL","65532","All ports including source"],
                ["OFPP_CONTROLLER","65533","Send to controller"],
                ["OFPP_LOCAL","65534","Local switch port"],
                ["OFPP_NONE","65535","No port / drop"]
              ].map(([name,val,desc])=>(
                <div key={name} style={{display:"flex",gap:6,borderBottom:`1px solid ${C.border}18`,padding:"2px 0"}}>
                  <span style={{color:C.purple,fontFamily:"monospace",fontSize:10,minWidth:160}}>{name}</span>
                  <span style={{color:C.yellow,fontFamily:"monospace",fontSize:10,minWidth:50}}>{val}</span>
                  <span style={{color:C.muted,fontSize:10}}>{desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  };

  const TABS=[
    {id:"DASHBOARD", label:"Dashboard"},
    {id:"TOPOLOGY",  label:"Topology"},
    {id:"ALERTS",    label:"Alerts",   badge:unreadAlerts,   bcolor:C.red},
    {id:"THREATS",   label:"Threats",  badge:hostIntel.filter(h=>h.threat_score>30).length, bcolor:C.orange},
    {id:"PACKETS",   label:"Packets",  badge:0},
    {id:"SESSIONS",  label:"Sessions"},
    {id:"HOSTS",     label:"Hosts"},
    {id:"FLOWS",     label:"Flows"},
    {id:"QOS",       label:"QoS"},
    {id:"GRAPHS",    label:"Graphs"},
    {id:"TESTS",     label:"Tests"},
    {id:"CMDLOG",    label:"Cmd Log",  badge:unreadCmds,     bcolor:C.teal},
    {id:"EVENTS",    label:"Events",   badge:unreadEvents,   bcolor:C.muted},
    {id:"REPORTS",   label:"Reports"},
    {id:"EXPORT",    label:"Export"},
    {id:"SIMULATE",  label:"Simulate"},
    {id:"NETCALC",   label:"Net Calc"},
  ];

  return(
    <div style={{minHeight:"100vh",background:C.bg,color:C.text,fontFamily:"'SF Mono',monospace,sans-serif",padding:16}}>
      {/* Header */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,flexWrap:"wrap",gap:8}}>
        <div>
          <span style={{fontSize:16,fontWeight:800,letterSpacing:-0.5}}>SDN Topology Visualizer</span>
          <span style={{fontSize:10,color:C.muted,marginLeft:10}}>SIEM + EDR + Wireshark + Flow Manager + QoS + Threat Intel</span>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
          {activeAlerts.filter(a=>a.severity==="critical").length>0&&(
            <div style={{background:"#2d1414",border:`1px solid ${C.red}`,borderRadius:6,padding:"3px 10px",fontSize:11,color:C.red,fontWeight:700,cursor:"pointer"}}
              onClick={()=>setTab("ALERTS")}>
              CRITICAL {activeAlerts.filter(a=>a.severity==="critical").length} ALERT{activeAlerts.filter(a=>a.severity==="critical").length!==1?"S":""}
            </div>
          )}
          <div style={{display:"flex",alignItems:"center",gap:5}}>
            <div style={{width:8,height:8,borderRadius:"50%",background:connected?C.green:C.red}}/>
            <span style={{fontSize:11,color:connected?C.green:C.red}}>{connected?"POX Connected":"Disconnected"}</span>
          </div>
          {summary&&<span style={{fontSize:10,color:C.muted}}>up {fAge(summary.uptime||0)}</span>}
        </div>
      </div>
      {/* Tab bar */}
      <div style={{display:"flex",gap:2,marginBottom:14,flexWrap:"wrap",borderBottom:`1px solid ${C.border}`,paddingBottom:8}}>
        {TABS.map(t=>(
          <button key={t.id}
            onClick={()=>{setTab(t.id);if(t.id==="ALERTS")setUnreadAlerts(0);if(t.id==="EVENTS")setUnreadEvents(0);if(t.id==="CMDLOG")setUnreadCmds(0);}}
            style={{...S.btn,
              background:tab===t.id?C.accent:"transparent",
              color:tab===t.id?"#000":C.muted,
              fontWeight:tab===t.id?700:400,
              border:tab===t.id?"none":`1px solid ${C.border}`,
              padding:"5px 12px"}}>
            {t.label}{t.badge>0&&<Badge n={t.badge} color={t.bcolor||C.red}/>}
          </button>
        ))}
      </div>
      {/* Content */}
      {tab==="DASHBOARD"  && renderDashboard()}
      {tab==="TOPOLOGY"   && renderTopo()}
      {tab==="ALERTS"     && renderAlerts()}
      {tab==="THREATS"    && renderThreats()}
      {tab==="PACKETS"    && renderPackets()}
      {tab==="SESSIONS"   && renderConnections()}
      {tab==="HOSTS"      && renderHosts()}
      {tab==="FLOWS"      && renderFlows()}
      {tab==="QOS"        && renderQos()}
      {tab==="GRAPHS"     && renderGraphs()}
      {tab==="TESTS"      && renderTests()}
      {tab==="CMDLOG"     && renderCmdlog()}
      {tab==="EVENTS"     && renderEvents()}
      {tab==="REPORTS"    && renderReports()}
      {tab==="EXPORT"     && renderExport()}
      {tab==="SIMULATE"  && renderSimulate()}
      {tab==="NETCALC"   && renderNetCalc()}
    </div>
  );
}
