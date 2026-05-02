# SDN Network Topology Visualizer — M3

> **v1.1.0** — Complete UI redesign + security upgrades + 15-protocol detection

A live browser-based SDN monitoring dashboard built from scratch with **POX OpenFlow controller**, **Mininet**, and **React.js 18**. Detects cyberattacks in real time, tags them with MITRE ATT&CK techniques, and gives you full visibility over your virtual network from a single browser window.

![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-1.1.0-brightgreen)
![Python](https://img.shields.io/badge/python-2.7-yellow)
![React](https://img.shields.io/badge/react-18-61DAFB)
![POX](https://img.shields.io/badge/controller-POX%200.3.0-orange)
![Platform](https://img.shields.io/badge/platform-Ubuntu%2022.04-E95420)

---

## What's New in v1.1.0

| Area | Change |
|------|--------|
| **UI** | Complete redesign — sidebar navigation, M3 gradient logo, toast notifications, smooth animations |
| **Alerts** | Split into 3 sub-tabs: Active (by severity) / Blocked / Dismissed |
| **Stats Bar** | Live data — packets from capture buffer, bandwidth from port stats, threats from scoring engine |
| **Detection** | 15 protocols now detected: HTTP, HTTPS, DNS, SSH, DHCP, FTP, OpenFlow, SNMP, NTP, SIP, RIP |
| **Events** | Link up/down changes now logged automatically |
| **Blocked Hosts** | Persistent tracking with one-click Unblock button |
| **Dismissed Alerts** | Stored as false-positive audit trail with timestamps |
| **Bug Fixes** | BW sparkline crash, Playbook input disappearing, React hooks rules violation |

---

## Screenshots

> Add your screenshots here after taking them with the dashboard running.

— Dashboard with live KPIs
(/docs/screenshots/Dashboard.png)   
— Topology map with switches and hosts
docs/screenshots/Topo.png     
— Alerts tab showing severity groups
docs/screenshots/Alerts.png       
— Threats tab showing detected threats tybe
docs/screenshots/Threats.png      
— A Wiresharke style sheet 
docs/screenshots/all packets.png    
— TCP/UDP communications sessions
docs/screenshots/Sessions.png     
— Isolate and Restore hosts, Clear all Alerts and QOS limit
docs/screenshots/PlayBook.png     



---

## Features

### 📊 Monitor Group
| Tab | Description |
|-----|-------------|
| **Dashboard** | Live KPI cards — switches, hosts, packets, bandwidth, alerts, threats |
| **Topology** | Interactive SVG network map — zoom, pan, drag nodes, path trace |
| **RT Monitor** | Real-time traffic monitoring with live graphs |
| **Graphs** | Per-switch bandwidth sparklines, alert timeline histogram |

### 🛡 Security Group
| Tab | Description |
|-----|-------------|
| **Alerts** | SIEM alerts grouped by severity — Critical / High / Medium / Low. Block hosts, dismiss false positives. All logged to Events |
| **Threats** | Per-host risk scores (0–100) with auto-decay. Search by IP, MAC, or protocol |
| **Packets** | Wireshark-style capture — 10,000 packets buffered, filter by protocol or IP, export all as CSV |
| **Sessions** | Active TCP/UDP session tracker with state, bytes, and duration |
| **Events** | POX system event log — info / warn / error. Includes link up/down events |

### ⚙ Manage Group
| Tab | Description |
|-----|-------------|
| **Hosts** | Host intel — MAC, IP, connected switch, TX/RX bytes, active protocols |
| **Flows** | OpenFlow flow table — view, add, and delete rules on any switch |
| **QoS** | Bandwidth limiting and DSCP marking per flow via REST |
| **Cmd Log** | Timeline of all controller and operator commands |

### 🔧 Tools Group
| Tab | Description |
|-----|-------------|
| **Tests** | 30 test types with correct Mininet host-name commands |
| **Simulate** | 7 attack scenarios with step-by-step commands and "what to observe" guide |
| **Playbook** | SOC response playbooks — Isolate Host, Flush Flows, Force Relearn, Baseline Capture |
| **Net Calc** | CIDR subnet calculator + OpenFlow reserved port reference |
| **Reports** | Auto-generated security and performance report |
| **Export** | Download everything — JSON, CSV, SVG, TXT |

---

## SIEM Detection Rules

| Rule | Threshold | Severity | MITRE |
|------|-----------|----------|-------|
| SYN Flood | >200 SYN/5s from one source | Critical | T1498 |
| ICMP Flood | >100 ICMP/5s | High | T1498.001 |
| Port Scan | >20 distinct ports/5s | High | T1046 |
| ARP Flood | >150 ARP/5s | Medium | T1557 |
| MAC Spoofing | Same IP on two MACs | Critical | T1557.002 |
| UDP Flood | >500 UDP/5s | High | T1498 |
| SSH Brute Force | >5 connections to port 22/5s | High | T1110 |
| DNS Amplification | UDP >512 bytes on port 53 | Medium | T1071.004 |
| Large Packet | Single packet >9000 bytes | Low | — |
| Unusual Protocol | Non TCP/UDP/ICMP/ARP | Low | — |

---

## Protocol Detection

The dashboard detects and color-codes 15 protocols:

`ARP` `ICMP` `TCP` `UDP` `HTTP` `HTTPS` `DNS` `SSH` `FTP` `DHCP` `OpenFlow` `SNMP` `NTP` `SIP` `RIP`

Port-based detection happens automatically on every packet — no configuration needed.

---

## Architecture

```
Mininet virtual network  (OVS switches + Linux hosts)
        |
        |  OpenFlow 1.0 packets
        v
POX 0.3.0 controller  +  topology_api.py  (~1,100 lines)
        |
        |  REST API  — ~30 endpoints on port 8000
        v
React.js 18 dashboard  (App.js ~2,900 lines)
        |
        |  HTTP polling every 1–5 seconds
        v
Browser at http://localhost:3000
```

The React app proxies all `/topo/` requests to port 8000 via the `proxy` setting in `package.json`.

---

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| OS | Ubuntu 22.04 LTS | VirtualBox VM works fine — 2 GB RAM minimum |
| Python | **2.7.x** | Required by POX — do NOT use Python 3 |
| POX | 0.3.0 (dart) | `git clone https://github.com/noxrepo/pox` |
| Node.js | 16+ (v20 recommended) | Install via nvm |
| Mininet | 2.x | `sudo apt install mininet` |
| Open vSwitch | Any | `sudo apt install openvswitch-switch` |
| hping3 | Any | `sudo apt install hping3` |
| nmap | Any | `sudo apt install nmap` |
| arp-scan | Any | `sudo apt install arp-scan` |

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/Khaledak74/SDN_Topology_Visualizer.git
cd SDN_Topology_Visualizer
```

### 2. Install system dependencies
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3 nmap arp-scan
```

### 3. Install the POX controller
```bash
cd ~
git clone https://github.com/noxrepo/pox.git
```

### 4. Copy the controller module
```bash
cp controller/topology_api.py ~/pox/pox/topology_api.py
```

### 5. Install Node.js via nvm
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install 20
nvm use 20
```

### 6. Install React dependencies
```bash
cd dashboard
npm install
```

---

## Running

Open **three separate terminals** and run one command in each.

### Terminal 1 — Start POX
```bash
cd ~/pox
./pox.py forwarding.l2_learning \
         openflow.discovery \
         openflow.spanning_tree --no-flood --hold-down \
         host_tracker \
         web.webcore \
         topology_api \
         samples.pretty_log \
         log.level --DEBUG
```

Wait for this line before continuing:
```
INFO:topology_api:topology_api ready  http://0.0.0.0:8000/topo/all
```

### Terminal 2 — Start Mininet
```bash
sudo mn --topo tree,depth=2,fanout=3 \
        --controller=remote,ip=127.0.0.1,port=6633 \
        --switch=ovs,protocols=OpenFlow10
```

Then generate traffic to populate the dashboard:
```bash
mininet> pingall
mininet> h1 iperf -s &
mininet> h2 iperf -c h1 -t 30
```

### Terminal 3 — Start Dashboard
```bash
cd dashboard
npm start
# Browser opens at http://localhost:3000
```

> ⚠️ **Order matters:** Always start POX before Mininet. Switches need the controller listening on port 6633 before they try to connect.

---

## Triggering Alerts (Quick Demo)

With the stack running, try these in the Mininet terminal to see the SIEM in action:

```bash
# SYN flood — triggers CRITICAL alert (T1498)
mininet> h2 hping3 -S -p 80 --flood h1

# Port scan — triggers HIGH alert (T1046)
mininet> h3 nmap -sV -p 1-100 h1

# ARP flood — triggers MEDIUM alert (T1557)
mininet> h2 arp-scan --localnet

# DDoS simulation with random source IPs
mininet> h3 hping3 --rand-source -S -p 80 --flood h1
```

Watch the **Alerts** tab in the dashboard — alerts appear within 3–5 seconds.

---

## API Reference

Base URL: `http://localhost:8000/topo/`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/all` | Topology: switches + links + hosts |
| GET | `/packets?limit=5000&since_id=0` | Incremental packet fetch |
| GET | `/alerts` | All SIEM alerts |
| GET | `/summary` | Combined health snapshot |
| GET | `/blocked/hosts` | Currently blocked host list |
| GET | `/alerts/dismissed` | Dismissed (false positive) alerts |
| GET | `/bw_history` | Per-switch bandwidth history |
| GET | `/port_util` | Per-port utilization |
| GET | `/host_intel` | Per-host threat scores |
| GET | `/flows` | OpenFlow flow tables |
| GET | `/test/run` | Generate Mininet test command |
| POST | `/block/host` | Install drop rule for an IP |
| POST | `/unblock/host` | Remove drop rule for an IP |
| POST | `/flow/add` | Add a new flow rule |
| POST | `/flow/delete` | Delete a flow rule by cookie |
| POST | `/alerts/dismiss` | Dismiss one alert |
| POST | `/alerts/clear` | Clear all alerts |
| POST | `/qos/apply` | Apply QoS rule |

---

## Project Structure

```
SDN_Topology_Visualizer/
├── README.md
├── LICENSE
├── CHANGELOG.md
├── .gitignore
│
├── controller/
│   ├── topology_api.py          ← POX REST module (~1,100 lines)
│   └── qos_topo.py              ← Custom Mininet topology (optional)
│
├── dashboard/
│   ├── package.json             ← Must contain "proxy": "http://localhost:8000"
│   ├── src/
│   │   └── App.js               ← React dashboard (~2,900 lines)
│   └── public/
│       ├── index.html
│       └── manifest.json
│
└── docs/
    └── screenshots/
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Dashboard shows **Disconnected** | Make sure POX is running. Check `proxy` in `package.json` points to `http://localhost:8000` |
| `SyntaxError: Non-ASCII character` in topology_api.py | Run: `python -c "open('topology_api.py','rb').read().decode('ascii')"` to find bad bytes |
| Mininet fails to start | Run `sudo mn -c` to clean up leftover state, then retry |
| `npm start` fails: Cannot find module | Run `cd dashboard && npm install` first |
| No hosts on the topology map | Run `pingall` in Mininet — hosts only appear after sending traffic |
| Port 6633 already in use | Run `sudo killall python2.7` then restart POX |
| Port 8000 already in use | Run `sudo lsof -i :8000` to find the process, then kill it |
| hping3 / nmap not found | Run `sudo apt install -y hping3 nmap arp-scan` |
| Stats bar shows 0 bandwidth | Wait 10 seconds after `pingall` — port stats are polled every 5 seconds |

---

## Changelog

### v1.1.0 — 2026-05-02
- Complete UI redesign: sidebar navigation, M3 gradient logo, toast system, animations
- Alerts split into Active / Blocked / Dismissed sub-tabs
- Live stats bar with clickable chips (packets from buffer, BW from port stats)
- Uptime with rainbow RGB gradient
- 15 protocol detection (HTTP, HTTPS, DNS, SSH, DHCP, FTP, OpenFlow, SNMP, NTP, SIP, RIP)
- Link up/down events logged to Events tab
- Blocked hosts tracked with Unblock button
- Dismissed alerts stored as false-positive audit trail
- Fixed: BW sparkline crash (TypeError: .slice is not a function)
- Fixed: Playbook input field disappearing on click
- Fixed: React hooks rules violation in renderPlaybook

### v1.0.0 — 2026-03-14
- Initial release
- 17-tab dashboard, SIEM with MITRE ATT&CK, flow table manager, QoS, export system

---

## Links

- 📘 **Technical writeup:** [Medium article](https://medium.com/@motaweak226/i-built-a-live-sdn-network-dashboard-with-pox-mininet-and-react-and-it-detects-cyberattacks-in-091e2ba58c75)
- ▶️ **Video walkthrough:** [YouTube](https://youtu.be/1UuCGPNN7gw?si=XuJ1Yc9lxOhEyNTr)
- 👤 **Author:** [Khaled Motawea](https://www.linkedin.com/in/khaled-motawea-0861b1265/)

---

## License

MIT License — free to use, modify, and distribute.
