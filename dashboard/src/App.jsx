import { useState, useEffect, useRef, useCallback } from "react";

const POX_HOST = "";
const POLL_INTERVAL = 2000;

// ── colour helpers ──────────────────────────────────────────────────────────
const STATUS = { UP: "up", DOWN: "down", UNKNOWN: "unknown" };
const NODE_COLOR = { switch: "#00e5ff", host: "#76ff03", controller: "#ff6d00" };
const LINK_COLOR = { up: "#00e5ff", down: "#ff1744", unknown: "#546e7a" };

// ── POX REST helpers ─────────────────────────────────────────────────────────
async function fetchPOX(path) {
  const r = await fetch(`${POX_HOST}${path}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function getTopology() {
  // POX openflow.discovery + host_tracker expose these endpoints
  const [switches, links, hosts] = await Promise.all([
    fetchPOX("/wm/core/controller/switches/json").catch(() => []),
    fetchPOX("/wm/topology/links/json").catch(() => []),
    fetchPOX("/wm/device/").catch(() => ({ devices: [] })),
  ]);
  return { switches, links, hosts: hosts.devices || [] };
}

// ── force-layout (simple spring) ────────────────────────────────────────────
function useForceLayout(nodes, edges, width, height) {
  const pos = useRef({});

  // seed positions for new nodes
  nodes.forEach((n) => {
    if (!pos.current[n.id]) {
      const angle = Math.random() * 2 * Math.PI;
      const r = Math.min(width, height) * 0.3;
      pos.current[n.id] = {
        x: width / 2 + r * Math.cos(angle),
        y: height / 2 + r * Math.sin(angle),
        vx: 0,
        vy: 0,
      };
    }
  });

  // remove stale nodes
  Object.keys(pos.current).forEach((id) => {
    if (!nodes.find((n) => n.id === id)) delete pos.current[id];
  });

  // run a few ticks
  for (let t = 0; t < 30; t++) {
    // repulsion
    nodes.forEach((a) => {
      nodes.forEach((b) => {
        if (a.id === b.id) return;
        const pa = pos.current[a.id], pb = pos.current[b.id];
        const dx = pa.x - pb.x, dy = pa.y - pb.y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = 4000 / (dist * dist);
        pa.vx += (dx / dist) * force;
        pa.vy += (dy / dist) * force;
      });
    });
    // attraction (edges)
    edges.forEach((e) => {
      const pa = pos.current[e.src], pb = pos.current[e.dst];
      if (!pa || !pb) return;
      const dx = pb.x - pa.x, dy = pb.y - pa.y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const force = (dist - 120) * 0.05;
      pa.vx += (dx / dist) * force;
      pa.vy += (dy / dist) * force;
      pb.vx -= (dx / dist) * force;
      pb.vy -= (dy / dist) * force;
    });
    // center gravity
    nodes.forEach((n) => {
      const p = pos.current[n.id];
      p.vx += (width / 2 - p.x) * 0.002;
      p.vy += (height / 2 - p.y) * 0.002;
      p.vx *= 0.85;
      p.vy *= 0.85;
      p.x = Math.max(40, Math.min(width - 40, p.x + p.vx));
      p.y = Math.max(40, Math.min(height - 40, p.y + p.vy));
    });
  }

  return { ...pos.current };
}

// ── main component ────────────────────────────────────────────────────────────
export default function TopologyViewer() {
  const [topo, setTopo] = useState({ switches: [], links: [], hosts: [] });
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [tick, setTick] = useState(0);
  const [poxHost, setPoxHost] = useState(POX_HOST);
  const [editHost, setEditHost] = useState(POX_HOST);
  const [showConfig, setShowConfig] = useState(false);
  const svgRef = useRef(null);
  const [svgSize, setSvgSize] = useState({ w: 900, h: 560 });

  // resize observer
  useEffect(() => {
    const obs = new ResizeObserver((entries) => {
      for (const e of entries) {
        setSvgSize({ w: e.contentRect.width, h: e.contentRect.height });
      }
    });
    if (svgRef.current) obs.observe(svgRef.current.parentElement);
    return () => obs.disconnect();
  }, []);

  // polling
  const poll = useCallback(async () => {
    try {
      const data = await getTopology();
      setTopo(data);
      setConnected(true);
      setError(null);
    } catch (e) {
      setConnected(false);
      setError(e.message);
    }
    setTick((t) => t + 1);
  }, [poxHost]);

  useEffect(() => {
    poll();
    const id = setInterval(poll, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [poll]);

  // build graph nodes/edges from topo
  const nodes = [];
  const edges = [];

  topo.switches.forEach((sw) => {
    const dpid = sw.dpid || sw.switchDPID || sw;
    nodes.push({ id: dpid, label: `SW\n${String(dpid).slice(-4)}`, type: "switch" });
  });

  topo.hosts.forEach((h) => {
    const id = h.mac?.[0] || JSON.stringify(h);
    if (!nodes.find((n) => n.id === id))
      nodes.push({ id, label: `H\n${String(id).slice(-5)}`, type: "host" });
  });

  topo.links.forEach((l) => {
    const src = l["src-switch"] || l.src_dpid || l.srcSwitch;
    const dst = l["dst-switch"] || l.dst_dpid || l.dstSwitch;
    if (src && dst)
      edges.push({ id: `${src}-${dst}`, src, dst, status: STATUS.UP });
  });

  // if no data yet, show a demo topology
  const demo = nodes.length === 0 && !connected;
  const displayNodes = demo
    ? [
        { id: "c0", label: "POX\nCtrl", type: "controller" },
        { id: "s1", label: "SW\n0001", type: "switch" },
        { id: "s2", label: "SW\n0002", type: "switch" },
        { id: "s3", label: "SW\n0003", type: "switch" },
        { id: "h1", label: "H\n00:01", type: "host" },
        { id: "h2", label: "H\n00:02", type: "host" },
        { id: "h3", label: "H\n00:03", type: "host" },
      ]
    : nodes;

  const displayEdges = demo
    ? [
        { id: "c0-s1", src: "c0", dst: "s1", status: STATUS.UP },
        { id: "s1-s2", src: "s1", dst: "s2", status: STATUS.UP },
        { id: "s2-s3", src: "s2", dst: "s3", status: STATUS.DOWN },
        { id: "s1-h1", src: "s1", dst: "h1", status: STATUS.UP },
        { id: "s2-h2", src: "s2", dst: "h2", status: STATUS.UP },
        { id: "s3-h3", src: "s3", dst: "h3", status: STATUS.UNKNOWN },
      ]
    : edges;

  const positions = useForceLayout(displayNodes, displayEdges, svgSize.w, svgSize.h);

  const selInfo = selected
    ? displayNodes.find((n) => n.id === selected) ||
      displayEdges.find((e) => e.id === selected)
    : null;

  return (
    <div style={{
      fontFamily: "'IBM Plex Mono', 'Courier New', monospace",
      background: "#050d1a",
      color: "#c9e8ff",
      minHeight: "100vh",
      display: "flex",
      flexDirection: "column",
    }}>
      {/* header */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "10px 20px",
        borderBottom: "1px solid #0d2a44",
        background: "#030a14",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 4,
            background: "linear-gradient(135deg,#00e5ff,#0077aa)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 16, fontWeight: "bold",
          }}>⬡</div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: 2, color: "#00e5ff" }}>
              POX TOPOLOGY INSPECTOR
            </div>
            <div style={{ fontSize: 10, color: "#456" }}>live network visualization</div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {/* status pill */}
          <div style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "4px 12px", borderRadius: 20,
            background: connected ? "#002a00" : "#2a0000",
            border: `1px solid ${connected ? "#00ff5588" : "#ff000088"}`,
            fontSize: 11,
          }}>
            <span style={{
              width: 8, height: 8, borderRadius: "50%",
              background: connected ? "#00e676" : "#ff1744",
              boxShadow: connected ? "0 0 6px #00e676" : "0 0 6px #ff1744",
              animation: connected ? "pulse 1.5s infinite" : "none",
            }}/>
            {connected ? "CONNECTED" : "DISCONNECTED"}
          </div>

          <button onClick={() => setShowConfig(!showConfig)} style={{
            background: "#0d2a44", border: "1px solid #1a4a6a",
            color: "#c9e8ff", padding: "4px 12px", borderRadius: 4,
            cursor: "pointer", fontSize: 11,
          }}>⚙ CONFIG</button>
        </div>
      </div>

      {/* config bar */}
      {showConfig && (
        <div style={{
          background: "#020c18", padding: "10px 20px",
          borderBottom: "1px solid #0d2a44",
          display: "flex", gap: 10, alignItems: "center",
        }}>
          <span style={{ fontSize: 11, color: "#456" }}>POX REST API:</span>
          <input
            value={editHost}
            onChange={e => setEditHost(e.target.value)}
            style={{
              background: "#0d2a44", border: "1px solid #1a4a6a",
              color: "#c9e8ff", padding: "4px 10px", borderRadius: 4,
              fontSize: 11, width: 240,
            }}
          />
          <button onClick={() => { setPoxHost(editHost); setShowConfig(false); }} style={{
            background: "#00e5ff22", border: "1px solid #00e5ff66",
            color: "#00e5ff", padding: "4px 12px", borderRadius: 4,
            cursor: "pointer", fontSize: 11,
          }}>Apply</button>
          <span style={{ fontSize: 10, color: "#456", marginLeft: 8 }}>
            Start POX with: <code style={{ color: "#00e5ff" }}>./pox.py openflow.discovery host_tracker web.webcore</code>
          </span>
        </div>
      )}

      {error && (
        <div style={{
          background: "#1a0000", borderBottom: "1px solid #ff174433",
          padding: "6px 20px", fontSize: 11, color: "#ff5252",
          display: "flex", alignItems: "center", gap: 8,
        }}>
          ⚠ {error} — showing demo topology. Connect POX controller at {poxHost}
        </div>
      )}

      {/* main area */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* canvas */}
        <div style={{ flex: 1, position: "relative" }}>
          <svg ref={svgRef} width="100%" height="100%" style={{ display: "block", minHeight: 500 }}>
            <defs>
              <marker id="arrow" markerWidth="8" markerHeight="8" refX="8" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill="#00e5ff44"/>
              </marker>
              <filter id="glow">
                <feGaussianBlur stdDeviation="3" result="blur"/>
                <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
              </filter>
            </defs>

            {/* grid */}
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M40 0L0 0 0 40" fill="none" stroke="#0d2a44" strokeWidth="0.5"/>
            </pattern>
            <rect width="100%" height="100%" fill="url(#grid)"/>

            {/* edges */}
            {displayEdges.map((e) => {
              const p1 = positions[e.src], p2 = positions[e.dst];
              if (!p1 || !p2) return null;
              const color = LINK_COLOR[e.status] || LINK_COLOR.unknown;
              const isSelected = selected === e.id;
              return (
                <g key={e.id} onClick={() => setSelected(isSelected ? null : e.id)} style={{ cursor: "pointer" }}>
                  {/* hit area */}
                  <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y}
                    stroke="transparent" strokeWidth={12}/>
                  {/* actual line */}
                  <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y}
                    stroke={color}
                    strokeWidth={isSelected ? 3 : e.status === STATUS.DOWN ? 1.5 : 2}
                    strokeDasharray={e.status === STATUS.DOWN ? "6 4" : e.status === STATUS.UNKNOWN ? "2 4" : "none"}
                    opacity={e.status === STATUS.DOWN ? 0.5 : 0.85}
                    filter={isSelected ? "url(#glow)" : "none"}
                  />
                  {/* packet animation on live links */}
                  {e.status === STATUS.UP && (
                    <circle r="3" fill={color} opacity={0.9} filter="url(#glow)">
                      <animateMotion dur="2s" repeatCount="indefinite"
                        path={`M${p1.x},${p1.y} L${p2.x},${p2.y}`}/>
                    </circle>
                  )}
                </g>
              );
            })}

            {/* nodes */}
            {displayNodes.map((n) => {
              const p = positions[n.id];
              if (!p) return null;
              const color = NODE_COLOR[n.type] || "#ccc";
              const isSelected = selected === n.id;
              const r = n.type === "controller" ? 24 : n.type === "switch" ? 20 : 16;
              const lines = n.label.split("\n");
              return (
                <g key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  onClick={() => setSelected(isSelected ? null : n.id)}
                  style={{ cursor: "pointer" }}>
                  {/* glow ring when selected */}
                  {isSelected && (
                    <circle r={r + 8} fill="none" stroke={color} strokeWidth={1.5} opacity={0.4}
                      style={{ animation: "spin 4s linear infinite" }}/>
                  )}
                  {/* node shape */}
                  {n.type === "switch" ? (
                    <rect x={-r} y={-r} width={r*2} height={r*2} rx={4}
                      fill="#050d1a" stroke={color} strokeWidth={isSelected ? 2.5 : 1.5}
                      filter={isSelected ? "url(#glow)" : "none"}/>
                  ) : n.type === "controller" ? (
                    <polygon
                      points={`0,${-r} ${r},${r/2} 0,${r} ${-r},${r/2}`}
                      fill="#050d1a" stroke={color} strokeWidth={isSelected ? 2.5 : 1.5}
                      filter="url(#glow)"/>
                  ) : (
                    <circle r={r} fill="#050d1a" stroke={color} strokeWidth={isSelected ? 2.5 : 1.5}
                      filter={isSelected ? "url(#glow)" : "none"}/>
                  )}
                  {/* label */}
                  {lines.map((l, i) => (
                    <text key={i} textAnchor="middle" y={i * 11 - (lines.length - 1) * 5.5}
                      fill={color} fontSize={9} fontFamily="IBM Plex Mono, monospace"
                      fontWeight="600">
                      {l}
                    </text>
                  ))}
                </g>
              );
            })}
          </svg>

          {/* demo badge */}
          {demo && (
            <div style={{
              position: "absolute", bottom: 16, left: 16,
              background: "#ff6d0022", border: "1px solid #ff6d0066",
              color: "#ff6d00", padding: "4px 10px", borderRadius: 4, fontSize: 10,
            }}>
              ◈ DEMO MODE — not connected to POX
            </div>
          )}

          {/* legend */}
          <div style={{
            position: "absolute", bottom: 16, right: 16,
            background: "#030a1499", backdropFilter: "blur(4px)",
            border: "1px solid #0d2a44", borderRadius: 6,
            padding: "8px 12px", fontSize: 10,
          }}>
            {[
              { color: NODE_COLOR.controller, label: "Controller ◆" },
              { color: NODE_COLOR.switch, label: "Switch ■" },
              { color: NODE_COLOR.host, label: "Host ●" },
              { color: LINK_COLOR.up, label: "── Link UP" },
              { color: LINK_COLOR.down, label: "╌╌ Link DOWN" },
              { color: LINK_COLOR.unknown, label: "·· Unknown" },
            ].map(({ color, label }) => (
              <div key={label} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                <span style={{ color, textShadow: `0 0 4px ${color}` }}>▮</span>
                <span style={{ color: "#789" }}>{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* side panel */}
        <div style={{
          width: 240, background: "#030a14",
          borderLeft: "1px solid #0d2a44",
          display: "flex", flexDirection: "column",
          fontSize: 11,
        }}>
          {/* stats */}
          <div style={{ padding: "12px 14px", borderBottom: "1px solid #0d2a44" }}>
            <div style={{ color: "#456", marginBottom: 8, fontSize: 10, letterSpacing: 1 }}>TOPOLOGY STATS</div>
            {[
              { label: "Switches", val: topo.switches.length || (demo ? 3 : 0), color: NODE_COLOR.switch },
              { label: "Hosts", val: topo.hosts.length || (demo ? 3 : 0), color: NODE_COLOR.host },
              { label: "Links", val: topo.links.length || (demo ? 6 : 0), color: "#00e5ff" },
              { label: "Active Links", val: displayEdges.filter(e => e.status === STATUS.UP).length, color: LINK_COLOR.up },
              { label: "Down Links", val: displayEdges.filter(e => e.status === STATUS.DOWN).length, color: LINK_COLOR.down },
            ].map(({ label, val, color }) => (
              <div key={label} style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                <span style={{ color: "#567" }}>{label}</span>
                <span style={{ color, fontWeight: 700 }}>{val}</span>
              </div>
            ))}
          </div>

          {/* selected info */}
          <div style={{ padding: "12px 14px", flex: 1, overflowY: "auto" }}>
            <div style={{ color: "#456", marginBottom: 8, fontSize: 10, letterSpacing: 1 }}>
              {selInfo ? "SELECTED ELEMENT" : "CLICK TO INSPECT"}
            </div>
            {selInfo ? (
              <div>
                {"type" in selInfo && selInfo.type !== undefined ? (
                  <>
                    <div style={{ color: NODE_COLOR[selInfo.type], marginBottom: 6, fontWeight: 700 }}>
                      {selInfo.type.toUpperCase()}
                    </div>
                    <div style={{ color: "#789", wordBreak: "break-all" }}>
                      <div style={{ marginBottom: 4 }}><span style={{ color: "#456" }}>ID: </span>{selInfo.id}</div>
                      <div><span style={{ color: "#456" }}>Label: </span>{selInfo.label.replace("\n", " ")}</div>
                    </div>
                  </>
                ) : (
                  <>
                    <div style={{ color: LINK_COLOR[selInfo.status] || "#ccc", marginBottom: 6, fontWeight: 700 }}>
                      LINK — {(selInfo.status || "unknown").toUpperCase()}
                    </div>
                    <div style={{ color: "#789" }}>
                      <div style={{ marginBottom: 4 }}><span style={{ color: "#456" }}>Src: </span>{selInfo.src}</div>
                      <div><span style={{ color: "#456" }}>Dst: </span>{selInfo.dst}</div>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div style={{ color: "#345", lineHeight: 1.6 }}>
                Click any node or link to inspect its details here.
              </div>
            )}
          </div>

          {/* poll status */}
          <div style={{
            padding: "8px 14px", borderTop: "1px solid #0d2a44",
            color: "#345", fontSize: 10,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span>Poll #{tick}</span>
              <span>every {POLL_INTERVAL / 1000}s</span>
            </div>
            <div style={{ marginTop: 4, color: "#456" }}>
              {new Date().toLocaleTimeString()}
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
      `}</style>
    </div>
  );
}
