import { useState, useEffect, useRef, useCallback } from "react";

const API = "http://localhost:8000";
const WS  = "ws://localhost:8000/ws";

// ── Design tokens ─────────────────────────────────────────────────────────────
const C = {
  bg:      "#07090e",
  surface: "#0f1318",
  card:    "#131a22",
  border:  "#1d2635",
  muted:   "#3d4f63",
  text:    "#c8d8e8",
  dim:     "#6b8099",
  red:     "#ff3355",
  orange:  "#ff8c00",
  yellow:  "#ffd000",
  green:   "#00d97e",
  blue:    "#3b9eff",
  purple:  "#a78bfa",
  cyan:    "#00d4ff",
};

function conf2color(c) {
  if (c >= 80) return C.red;
  if (c >= 65) return C.orange;
  if (c >= 40) return C.yellow;
  return C.green;
}

// ── Micro components ──────────────────────────────────────────────────────────
function Pill({ label, color }) {
  return (
    <span style={{
      fontSize: 9, fontWeight: 800, letterSpacing: 1.2, padding: "2px 8px",
      borderRadius: 3, background: color + "22", color, border: `1px solid ${color}55`,
    }}>{label}</span>
  );
}

function Bar({ value, color, height = 4 }) {
  return (
    <div style={{ flex: 1, height, background: "#1d2635", borderRadius: 2, overflow: "hidden" }}>
      <div style={{
        width: `${Math.min(value, 100)}%`, height: "100%",
        background: color || conf2color(value), borderRadius: 2,
        transition: "width 0.6s cubic-bezier(.4,0,.2,1)",
      }} />
    </div>
  );
}

function ConfRing({ value }) {
  const r = 22, circ = 2 * Math.PI * r;
  const col = conf2color(value);
  return (
    <svg width="56" height="56" style={{ flexShrink: 0 }}>
      <circle cx="28" cy="28" r={r} fill="none" stroke="#1d2635" strokeWidth="3.5" />
      <circle cx="28" cy="28" r={r} fill="none" stroke={col} strokeWidth="3.5"
        strokeDasharray={circ} strokeDashoffset={circ * (1 - value / 100)}
        strokeLinecap="round" transform="rotate(-90 28 28)"
        style={{ transition: "stroke-dashoffset 0.6s ease, stroke 0.3s" }} />
      <text x="28" y="33" textAnchor="middle" fill={col}
        fontSize="11" fontWeight="700" fontFamily="monospace">{Math.round(value)}%</text>
    </svg>
  );
}

function Stat({ label, value, color, glow }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`, borderRadius: 10,
      padding: "14px 18px", flex: "1 1 120px",
      boxShadow: glow ? `0 0 18px ${color}22` : "none",
    }}>
      <div style={{ fontSize: 26, fontWeight: 800, color: color || C.text, fontFamily: "monospace", lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 10, color: C.dim, marginTop: 4, letterSpacing: 1 }}>{label}</div>
    </div>
  );
}

function Pulse({ active }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10 }}>
      <span style={{
        width: 7, height: 7, borderRadius: "50%",
        background: active ? C.green : C.muted,
        boxShadow: active ? `0 0 10px ${C.green}` : "none",
        animation: active ? "pulse 1.8s infinite" : "none",
      }} />
      <span style={{ color: active ? C.green : C.muted }}>
        {active ? "LIVE" : "OFFLINE"}
      </span>
    </span>
  );
}

// ── Alert card ────────────────────────────────────────────────────────────────
function AlertCard({ alert, onBlock, onDisable }) {
  const [expanded, setExpanded] = useState(false);
  const isAttack = alert.label === "ATTACK";
  const isSusp   = alert.label === "SUSPICIOUS";
  const borderCol = isAttack ? C.red : isSusp ? C.orange : C.border;

  return (
    <div onClick={() => setExpanded(e => !e)} style={{
      background: C.card, borderRadius: 10,
      border: `1px solid ${borderCol}${isAttack ? "66" : isSusp ? "44" : ""}`,
      marginBottom: 6, cursor: "pointer",
      boxShadow: isAttack ? `0 0 20px ${C.red}15` : "none",
      animation: "slideIn 0.25s ease",
    }}>
      {/* Main row */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px" }}>
        <ConfRing value={alert.confidence || 0} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <Pill label={alert.label || "UNKNOWN"}
              color={isAttack ? C.red : isSusp ? C.orange : C.green} />
            <span style={{ fontSize: 10, color: C.dim }}>
              {alert.action?.replace(/_/g, " ")}
            </span>
            <span style={{ fontSize: 10, color: C.muted, marginLeft: "auto" }}>
              {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : ""}
            </span>
          </div>
          <div style={{ fontSize: 12, fontFamily: "monospace", display: "flex", gap: 6, flexWrap: "wrap" }}>
            <span style={{ color: C.orange }}>{alert.source_ip}</span>
            {alert.user && alert.user !== "unknown" && <>
              <span style={{ color: C.muted }}>→</span>
              <span style={{ color: C.blue }}>{alert.user}</span>
            </>}
            <span style={{ color: C.muted }}>·</span>
            <span style={{ color: C.text }}>{alert.event_type || alert.threat_type}</span>
          </div>
          {/* Score bars */}
          <div style={{ display: "flex", gap: 16, marginTop: 6 }}>
            {[["IsoForest", (alert.iforest_score || 0) * 100], ["LSTM", (alert.lstm_score || 0) * 100], ["Geo-Risk", (alert.geo_risk_score || 0) * 100]].map(([lbl, val]) => (
              <div key={lbl} style={{ display: "flex", alignItems: "center", gap: 5, flex: 1 }}>
                <span style={{ fontSize: 9, color: C.dim, width: 55 }}>{lbl}</span>
                <Bar value={val} />
                <span style={{ fontSize: 9, color: conf2color(val), width: 26, textAlign: "right" }}>{Math.round(val)}%</span>
              </div>
            ))}
          </div>
        </div>
        {/* Quick-action buttons */}
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }} onClick={e => e.stopPropagation()}>
          <button onClick={() => onBlock(alert.source_ip)} style={qbtn(C.red)}>Block IP</button>
          {alert.user && alert.user !== "unknown" &&
            <button onClick={() => onDisable(alert.user)} style={qbtn(C.orange)}>Disable User</button>}
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div style={{ padding: "0 14px 14px", borderTop: `1px solid ${C.border}`, marginTop: 0 }}>
          {alert.signals?.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 9, color: C.muted, letterSpacing: 1, marginBottom: 6 }}>DETECTION SIGNALS</div>
              {alert.signals.map((s, i) => (
                <div key={i} style={{ fontSize: 11, color: C.text, marginBottom: 3 }}>
                  <span style={{ color: C.red }}>▸</span> {s}
                </div>
              ))}
            </div>
          )}
          {alert.actions?.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 9, color: C.muted, letterSpacing: 1, marginBottom: 6 }}>RESPONSE ACTIONS</div>
              {alert.actions.map((a, i) => (
                <span key={i} style={{ fontSize: 11, color: C.cyan, marginRight: 14 }}>✓ {a}</span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function qbtn(color) {
  return {
    background: "transparent", border: `1px solid ${color}66`,
    color, padding: "3px 10px", borderRadius: 5, fontSize: 10,
    cursor: "pointer", fontFamily: "inherit", fontWeight: 700,
    letterSpacing: 0.5, whiteSpace: "nowrap",
  };
}

// ── Log terminal ──────────────────────────────────────────────────────────────
function LogTerminal({ logs }) {
  const [search, setSearch] = useState("");
  const filtered = logs.filter(l =>
    !search || [l.source_ip, l.event_type, l.action, l.user]
      .some(v => v?.toLowerCase().includes(search.toLowerCase()))
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <input value={search} onChange={e => setSearch(e.target.value)}
        placeholder="Filter by IP / event / user…"
        style={{
          padding: "8px 14px", background: C.surface, border: `1px solid ${C.border}`,
          borderRadius: 6, color: C.text, fontSize: 12, outline: "none", fontFamily: "monospace",
        }} />
      <div style={{ background: "#060809", borderRadius: 8, border: `1px solid ${C.border}`, overflow: "auto", maxHeight: "60vh" }}>
        <div style={{ display: "grid", gridTemplateColumns: "80px 140px 180px 65px 55px 1fr", padding: "7px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, letterSpacing: 1 }}>
          {["TIME","SOURCE IP","EVENT","SEV","CONF","DETAILS"].map(h => <span key={h}>{h}</span>)}
        </div>
        {filtered.slice(0, 200).map((l, i) => {
          const anomaly = l.analysis?.is_anomaly;
          const conf = l.analysis?.confidence || 0;
          return (
            <div key={l.id || i} style={{
              display: "grid", gridTemplateColumns: "80px 140px 180px 65px 55px 1fr",
              padding: "5px 12px", fontSize: 11, fontFamily: "monospace",
              borderBottom: `1px solid #0b0e13`,
              background: anomaly ? `${C.red}08` : "transparent",
            }}>
              <span style={{ color: "#2255aa" }}>{l.timestamp?.slice(11,19)}</span>
              <span style={{ color: anomaly ? C.orange : C.muted }}>{l.source_ip}</span>
              <span style={{ color: anomaly ? C.red : C.green }}>{l.event_type || l.action}</span>
              <span style={{ color: (l.severity||5) >= 7 ? C.red : (l.severity||5) >= 4 ? C.orange : C.muted }}>
                SEV-{l.severity || "?"}
              </span>
              <span style={{ color: conf2color(conf) }}>{conf > 0 ? `${Math.round(conf)}%` : "—"}</span>
              <span style={{ color: C.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {l.user && l.user !== "unknown" ? `user:${l.user} ` : ""}
                {l.details ? JSON.stringify(l.details).slice(0,70) : ""}
              </span>
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div style={{ textAlign: "center", padding: 40, color: C.muted, fontSize: 12 }}>
            No logs yet — run a simulation or send /ingest requests
          </div>
        )}
      </div>
    </div>
  );
}

// ── Blocked panel ─────────────────────────────────────────────────────────────
function BlockedPanel({ api, refreshKey }) {
  const [data, setData] = useState({ blocked_ips: [], disabled_users: [] });
  const load = useCallback(() =>
    fetch(`${api}/blocked`).then(r => r.json()).then(setData).catch(() => {}), [api]);

  useEffect(() => { load(); }, [load, refreshKey]);

  const unblock = async (entity) => {
    await fetch(`${api}/blocked/${entity}`, { method: "DELETE" });
    load();
  };

  const Section = ({ title, items, entityKey }) => (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 16 }}>
      <div style={{ fontSize: 10, color: C.dim, letterSpacing: 1, marginBottom: 12 }}>
        {title} <span style={{ color: C.red }}>{items.length}</span>
      </div>
      {items.length === 0 && <div style={{ color: C.muted, fontSize: 12, textAlign: "center", padding: 20 }}>None</div>}
      {items.map((item, i) => (
        <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
          <span style={{ color: C.red, fontFamily: "monospace", fontSize: 13, flex: 1 }}>
            {item[entityKey] || item.entity}
          </span>
          <span style={{ color: C.dim, fontSize: 10, flex: 2 }}>{item.reason}</span>
          <span style={{ color: C.muted, fontSize: 9, flex: 1 }}>
            {item.expires ? `Expires ${new Date(item.expires).toLocaleTimeString()}` : "Permanent"}
          </span>
          <button onClick={() => unblock(item[entityKey] || item.entity)} style={qbtn(C.green)}>
            Unblock
          </button>
        </div>
      ))}
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <Section title="BLOCKED IPs" items={data.blocked_ips} entityKey="entity" />
      <Section title="DISABLED USERS" items={data.disabled_users} entityKey="user" />
    </div>
  );
}

// ── Simulator panel ───────────────────────────────────────────────────────────
function SimPanel({ api }) {
  const [scenario, setScenario] = useState("brute_force");
  const [intensity, setIntensity] = useState("medium");
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState([]);

  const SCENARIOS = [
    { id: "brute_force",          label: "SSH Brute Force",         desc: "Rapid login failures, single IP" },
    { id: "port_scan",            label: "Port Scan + Exploit",      desc: "Recon then targeted exploit" },
    { id: "data_exfil",           label: "Data Exfiltration",        desc: "Insider threat, bulk transfer" },
    { id: "privilege_escalation", label: "Privilege Escalation",     desc: "Lateral movement to root" },
    { id: "mixed",                label: "APT Mixed Campaign",       desc: "Multi-vector coordinated attack" },
  ];

  const log = (msg, col = C.dim) =>
    setOutput(p => [`[${new Date().toISOString().slice(11,19)}] ${msg}`, ...p].slice(0, 100));

  const launch = async () => {
    setRunning(true);
    setOutput([]);
    log(`Launching ${scenario} (${intensity} intensity)…`, C.cyan);
    try {
      const r = await fetch(`${api}/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_type: scenario, intensity }),
      });
      if (r.ok) {
        log("Attack injected → pipeline processing…", C.green);
        log("Watch Alerts tab for auto-responses", C.cyan);
      } else {
        log(`HTTP ${r.status} — is backend running on localhost:8000?`, C.red);
      }
    } catch (e) {
      log(`Connection failed: ${e.message}`, C.red);
      log("Start backend: cd backend && python main_full.py", C.orange);
    }
    setTimeout(() => setRunning(false), 2000);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Scenario picker */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        {SCENARIOS.map(s => (
          <button key={s.id} onClick={() => setScenario(s.id)} style={{
            padding: "12px 14px", borderRadius: 8, cursor: "pointer", textAlign: "left",
            background: scenario === s.id ? `${C.cyan}18` : C.card,
            border: `1px solid ${scenario === s.id ? C.cyan : C.border}`,
            color: scenario === s.id ? C.cyan : C.dim,
            minWidth: 160, flex: "1 1 160px",
          }}>
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 3 }}>{s.label}</div>
            <div style={{ fontSize: 10 }}>{s.desc}</div>
          </button>
        ))}
      </div>

      {/* Intensity + launch */}
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontSize: 11, color: C.dim }}>Intensity:</span>
        {["low", "medium", "high"].map(i => (
          <button key={i} onClick={() => setIntensity(i)} style={{
            padding: "5px 14px", fontSize: 10, letterSpacing: 1, borderRadius: 5,
            background: intensity === i ? `${C.purple}22` : "transparent",
            border: `1px solid ${intensity === i ? C.purple : C.border}`,
            color: intensity === i ? C.purple : C.muted, cursor: "pointer", fontFamily: "inherit",
          }}>{i.toUpperCase()}</button>
        ))}
        <button onClick={launch} disabled={running} style={{
          marginLeft: "auto", padding: "9px 28px", fontSize: 13, fontWeight: 800,
          borderRadius: 7, cursor: running ? "wait" : "pointer", border: "none",
          background: running ? C.surface : `linear-gradient(135deg, ${C.cyan}, ${C.blue})`,
          color: running ? C.muted : "#000", letterSpacing: 0.5, fontFamily: "inherit",
        }}>
          {running ? "⚡ Running…" : "▶  Launch Attack"}
        </button>
      </div>

      {/* Output console */}
      <div style={{
        background: "#060809", borderRadius: 8, border: `1px solid ${C.border}`,
        padding: 14, minHeight: 280, fontFamily: "monospace", fontSize: 11,
      }}>
        <div style={{ fontSize: 9, color: C.muted, letterSpacing: 1, marginBottom: 8 }}>SIMULATOR OUTPUT</div>
        {output.length === 0 && <div style={{ color: C.muted }}>Select scenario and launch…</div>}
        {output.map((line, i) => (
          <div key={i} style={{
            color: line.includes("failed") || line.includes("Error") || line.includes("Connection") ? C.red
                 : line.includes("OK") || line.includes("injected") ? C.green
                 : line.includes("Watch") || line.includes("Start") ? C.cyan : C.dim,
            marginBottom: 2,
          }}>{line}</div>
        ))}
      </div>
    </div>
  );
}

// ── Response log ──────────────────────────────────────────────────────────────
function ResponseLog({ responses }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 16 }}>
      <div style={{ fontSize: 10, color: C.dim, letterSpacing: 1, marginBottom: 12 }}>AUTO-RESPONSE LOG</div>
      {responses.length === 0 && <div style={{ color: C.muted, textAlign: "center", padding: 24, fontSize: 12 }}>No responses yet</div>}
      {responses.map((r, i) => {
        const col = r.action === "AUTO_BLOCK" ? C.red : r.action === "ALERT_AND_TEMP_BLOCK" ? C.orange : C.blue;
        return (
          <div key={i} style={{
            padding: "8px 10px", marginBottom: 5, background: C.surface, borderRadius: 6,
            borderLeft: `3px solid ${col}`, fontSize: 11, fontFamily: "monospace",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
              <span style={{ color: col, fontWeight: 700 }}>{r.action}</span>
              <span style={{ color: C.muted, fontSize: 10 }}>{new Date(r.timestamp).toLocaleTimeString()}</span>
            </div>
            <div style={{ color: C.text }}>{r.result}</div>
            <div style={{ color: C.muted, marginTop: 2, fontSize: 10 }}>
              triggered by: {r.triggered_by}
              {r.confidence != null ? ` · conf: ${(r.confidence * 100).toFixed(0)}%` : ""}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab] = useState("dashboard");
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState({ total_logs:0, alerts_generated:0, auto_responses:0, ips_blocked:0, users_disabled:0, ml_ready:false });
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [responses, setResponses] = useState([]);
  const [filter, setFilter] = useState("ALL");
  const [blockedRefresh, setBlockedRefresh] = useState(0);
  const wsRef  = useRef(null);
  const pingRef = useRef(null);

  const fetchAll = useCallback(() => {
    fetch(`${API}/stats`).then(r=>r.json()).then(s => setStats({ ...s, ml_ready: s.ml_ready ?? false })).catch(()=>{});
    fetch(`${API}/alerts?limit=200`).then(r=>r.json()).then(d => setAlerts(d.alerts||[])).catch(()=>{});
    fetch(`${API}/logs?limit=300`).then(r=>r.json()).then(setLogs).catch(()=>{});
    fetch(`${API}/responses?limit=50`).then(r=>r.json()).then(d => setResponses(d.responses||[])).catch(()=>{});
  }, []);

  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === 1) return;
    try {
      const ws = new WebSocket(WS);
      wsRef.current = ws;
      ws.onopen = () => { setConnected(true); pingRef.current = setInterval(()=>ws.send("ping"),20000); };
      ws.onclose = () => { setConnected(false); clearInterval(pingRef.current); setTimeout(connectWS,3500); };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.stats) setStats(s => ({ ...s, ...msg.stats }));
        if (msg.type === "alert")
          setAlerts(prev => [msg.data, ...prev].slice(0,300));
        if (msg.type === "new_log")
          setLogs(prev => [msg.data, ...prev].slice(0,500));
        if (msg.type === "response")
          setResponses(prev => [msg.data, ...prev].slice(0,100));
        if (msg.type === "unblock" || msg.type === "response_update")
          setBlockedRefresh(n => n+1);
        if (msg.type === "cleared")
          setAlerts([]);
      };
    } catch { setTimeout(connectWS,3500); }
  }, []);

  useEffect(() => {
    connectWS();
    fetchAll();
    const t = setInterval(fetchAll, 8000);
    return () => { clearInterval(t); clearInterval(pingRef.current); wsRef.current?.close(); };
  }, [connectWS, fetchAll]);

  const handleBlock = async (ip) => {
    await fetch(`${API}/action`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({target_type:"ip",target:ip,action:"block",reason:"Manual — dashboard"})});
    fetchAll(); setBlockedRefresh(n=>n+1);
  };
  const handleDisable = async (user) => {
    await fetch(`${API}/action`, { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({target_type:"user",target:user,action:"disable",reason:"Manual — dashboard"})});
    fetchAll();
  };
  const handleClear = async () => {
    await fetch(`${API}/alerts/clear`, { method:"DELETE"}).catch(()=>{});
    setAlerts([]);
  };

  const filteredAlerts = filter==="ALL" ? alerts : alerts.filter(a => a.label===filter);

  const TABS = [
    { id:"dashboard", icon:"⬡", label:"Dashboard" },
    { id:"alerts",    icon:"△", label:"Alerts", badge: alerts.filter(a=>a.label==="ATTACK").length },
    { id:"logs",      icon:"≡", label:"Log Stream" },
    { id:"blocked",   icon:"⊘", label:"Blocked" },
    { id:"sim",       icon:"⚡", label:"Simulator" },
    { id:"responses", icon:"↩", label:"Responses" },
  ];

  return (
    <div style={{ display:"flex", height:"100vh", background:C.bg, color:C.text,
      fontFamily:"'JetBrains Mono','Fira Code','Courier New',monospace" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap');
        @keyframes slideIn { from{opacity:0;transform:translateY(-6px)} to{opacity:1;transform:none} }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.35} }
        ::-webkit-scrollbar{width:5px;height:5px}
        ::-webkit-scrollbar-track{background:${C.bg}}
        ::-webkit-scrollbar-thumb{background:${C.border};border-radius:3px}
        button:hover{filter:brightness(1.25)} * {box-sizing:border-box}
      `}</style>

      {/* ── Sidebar ── */}
      <aside style={{ width:210, borderRight:`1px solid ${C.border}`, display:"flex", flexDirection:"column", flexShrink:0 }}>
        {/* Logo */}
        <div style={{ padding:"18px 18px 14px", borderBottom:`1px solid ${C.border}` }}>
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
            <div style={{ width:30,height:30,borderRadius:7,background:`linear-gradient(135deg,${C.cyan},${C.blue})`,
              display:"flex",alignItems:"center",justifyContent:"center",fontSize:15 }}>⬡</div>
            <div>
              <div style={{ fontSize:13,fontWeight:800,color:"#fff",letterSpacing:1 }}>AutoSec AI</div>
              <div style={{ fontSize:9,color:C.muted,letterSpacing:2 }}>SOC PLATFORM</div>
            </div>
          </div>
          <Pulse active={connected} />
          <div style={{ marginTop:8,display:"flex",alignItems:"center",gap:6 }}>
            <span style={{ fontSize:9,color:C.muted }}>ML ENGINE</span>
            <span style={{ fontSize:9,color:stats.ml_ready?C.green:C.orange,fontWeight:700 }}>
              {stats.ml_ready?"● READY":"● HEURISTIC"}
            </span>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex:1, padding:"10px 0" }}>
          {TABS.map(t => (
            <button key={t.id} onClick={()=>setTab(t.id)} style={{
              width:"100%",display:"flex",alignItems:"center",gap:9,
              padding:"9px 18px",background:"transparent",
              borderTop:"none",borderBottom:"none",borderRight:"none",
              borderLeft:`2px solid ${tab===t.id?C.cyan:"transparent"}`,
              color: tab===t.id ? C.cyan : C.muted,
              cursor:"pointer",fontSize:11,letterSpacing:0.5,
              background: tab===t.id ? `${C.cyan}0d` : "transparent",
            }}>
              <span style={{fontSize:13}}>{t.icon}</span>
              <span style={{flex:1,textAlign:"left"}}>{t.label}</span>
              {t.badge>0 && (
                <span style={{background:C.red,color:"#fff",fontSize:8,padding:"1px 5px",borderRadius:8,fontWeight:800}}>
                  {t.badge}
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* Footer stats */}
        <div style={{ padding:"14px 18px", borderTop:`1px solid ${C.border}` }}>
          {[["THREATS",stats.alerts_generated||0,C.orange],["BLOCKED",stats.ips_blocked||0,C.red],["RESPONSES",stats.auto_responses||0,C.cyan]].map(([k,v,c])=>(
            <div key={k} style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
              <span style={{fontSize:9,color:C.muted,letterSpacing:1}}>{k}</span>
              <span style={{fontSize:12,color:c,fontWeight:800}}>{v}</span>
            </div>
          ))}
        </div>
      </aside>

      {/* ── Main content ── */}
      <main style={{ flex:1, overflow:"auto", padding:22 }}>

        {/* Dashboard */}
        {tab==="dashboard" && (
          <div>
            <div style={{marginBottom:20}}>
              <div style={{fontSize:17,fontWeight:800,color:"#fff"}}>Security Operations Center</div>
              <div style={{fontSize:10,color:C.dim,marginTop:3}}>Real-time anomaly detection · Automated threat response · ML confidence scoring</div>
            </div>
            <div style={{display:"flex",gap:10,flexWrap:"wrap",marginBottom:22}}>
              <Stat label="LOGS INGESTED"   value={stats.total_logs||0}        color={C.blue} />
              <Stat label="ALERTS RAISED"   value={stats.alerts_generated||0}  color={C.orange} glow />
              <Stat label="AUTO-RESPONSES"  value={stats.auto_responses||0}    color={C.red} glow />
              <Stat label="IPs BLOCKED"     value={stats.ips_blocked||0}       color={C.red} />
              <Stat label="USERS DISABLED"  value={stats.users_disabled||0}    color={C.purple} />
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
              <div>
                <div style={{fontSize:10,color:C.dim,letterSpacing:1,marginBottom:10}}>RECENT ALERTS</div>
                {alerts.slice(0,6).map((a,i)=><AlertCard key={a.id||i} alert={a} onBlock={handleBlock} onDisable={handleDisable}/>)}
                {alerts.length===0 && <div style={{color:C.muted,fontSize:12,textAlign:"center",padding:30}}>No alerts — run the Simulator</div>}
              </div>
              <div>
                <div style={{fontSize:10,color:C.dim,letterSpacing:1,marginBottom:10}}>LIVE LOG FEED</div>
                <div style={{background:"#060809",borderRadius:8,border:`1px solid ${C.border}`,padding:"8px 12px",fontFamily:"monospace",fontSize:10,maxHeight:400,overflow:"auto"}}>
                  {logs.slice(0,20).map((l,i)=>{
                    const a=l.analysis;
                    return <div key={l.id||i} style={{padding:"3px 0",borderBottom:`1px solid #0b0e13`,color:a?.is_anomaly?C.orange:C.muted}}>
                      <span style={{color:"#1d3a7a"}}>{l.timestamp?.slice(11,19)} </span>
                      <span style={{color:a?.is_anomaly?C.red:C.green}}>{(l.event_type||l.action||"").padEnd(22)}</span>
                      <span style={{color:C.muted}}>{l.source_ip}</span>
                      {a?.confidence>0&&<span style={{color:conf2color(a.confidence)}}> [{Math.round(a.confidence)}%]</span>}
                    </div>;
                  })}
                  {logs.length===0&&<div style={{color:C.muted}}>Waiting for logs…</div>}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Alerts */}
        {tab==="alerts" && (
          <div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
              <div>
                <div style={{fontSize:17,fontWeight:800,color:"#fff"}}>Alert Management</div>
                <div style={{fontSize:10,color:C.dim,marginTop:3}}>{alerts.length} total · click any alert to expand</div>
              </div>
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                {["ALL","ATTACK","SUSPICIOUS"].map(f=>(
                  <button key={f} onClick={()=>setFilter(f)} style={{
                    padding:"5px 12px",fontSize:9,letterSpacing:1,borderRadius:5,
                    background: filter===f ? (f==="ATTACK"?`${C.red}22`:f==="SUSPICIOUS"?`${C.orange}22`:`${C.cyan}22`) : "transparent",
                    border:`1px solid ${filter===f?(f==="ATTACK"?C.red:f==="SUSPICIOUS"?C.orange:C.cyan):C.border}`,
                    color: filter===f?(f==="ATTACK"?C.red:f==="SUSPICIOUS"?C.orange:C.cyan):C.muted,
                    cursor:"pointer",fontFamily:"inherit",fontWeight:700,
                  }}>{f}</button>
                ))}
                <button onClick={handleClear} style={{...qbtn(C.muted),fontSize:9,letterSpacing:1}}>CLEAR</button>
              </div>
            </div>
            <div style={{maxHeight:"calc(100vh - 140px)",overflowY:"auto"}}>
              {filteredAlerts.map((a,i)=><AlertCard key={a.id||i} alert={a} onBlock={handleBlock} onDisable={handleDisable}/>)}
              {filteredAlerts.length===0&&<div style={{textAlign:"center",padding:60,color:C.muted}}>
                <div style={{fontSize:36,marginBottom:12}}>🛡</div>
                <div>No alerts match this filter</div>
                <div style={{fontSize:10,marginTop:8}}>Run the Simulator to generate attacks</div>
              </div>}
            </div>
          </div>
        )}

        {tab==="logs"      && <><div style={{fontSize:17,fontWeight:800,color:"#fff",marginBottom:14}}>Live Log Stream</div><LogTerminal logs={logs}/></>}
        {tab==="blocked"   && <><div style={{fontSize:17,fontWeight:800,color:"#fff",marginBottom:14}}>Blocked Entities</div><BlockedPanel api={API} refreshKey={blockedRefresh}/></>}
        {tab==="sim"       && <><div style={{fontSize:17,fontWeight:800,color:"#fff",marginBottom:14}}>Attack Simulator</div><SimPanel api={API}/></>}
        {tab==="responses" && <><div style={{fontSize:17,fontWeight:800,color:"#fff",marginBottom:14}}>Auto-Response Log</div><ResponseLog responses={responses}/></>}
      </main>
    </div>
  );
}
