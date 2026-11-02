import React, { useEffect, useMemo, useRef, useState } from "react";
import { api, boot, login, logout } from "./api";
import { CityScene } from "./scene/CityScene";
import { scene } from "./scene/ref";
import { getState, setState, useStore, View } from "./store";
import { C } from "./palette";
import { Heartbeat, Ring, k, marksOn, riskColor } from "./components/Charts";
import { Box, Ic, Num, Stat } from "./components/ui";
import { ZeroDayView } from "./components/ZeroDay";
import { CityView, DefendView, FixView, PathView, ProofView, SafetyView } from "./components/Views";
import { LabView } from "./components/Lab";
import { LiveView } from "./components/Live";
import { HowView } from "./components/How";
import { WhyView } from "./components/Why";
import { PredictView } from "./components/Predict";
import { GraphPanel, IncidentCard, Legend, MapTitle, NodeCard, SelectedBar, Timeline } from "./components/Hud";
import { can, nameOf, statusOf } from "./components/status";
import { Move } from "./components/ui";
import { pickNode, showEdges } from "./focus";
import { toast } from "./store";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "city", label: "Overview", icon: "city" }, { id: "predict", label: "Predict", icon: "eye" }, { id: "path", label: "Paths", icon: "route" }, { id: "fix", label: "Fix", icon: "wrench" }, { id: "lab", label: "What-if", icon: "target" },
  { id: "defend", label: "Defend", icon: "shield" }, { id: "live", label: "Live", icon: "radio" }, { id: "zeroday", label: "Zero-day", icon: "bolt" }, { id: "proof", label: "Proof", icon: "chart" }, { id: "safety", label: "Safety", icon: "lock" },
  { id: "how", label: "How it works", icon: "play" }, { id: "why", label: "Why us", icon: "sparkle" },
];
const PANEL: Record<View, () => JSX.Element> = { city: CityView, predict: PredictView, path: PathView, fix: FixView, lab: LabView, defend: DefendView, live: LiveView, zeroday: ZeroDayView, proof: ProofView, safety: SafetyView, how: HowView, why: WhyView };

const Mark = ({ size = 30 }) => <img src="/athena-mark.png" alt="ATHENA" height={size} style={{ height: size, width: "auto", display: "block" }} />;

/* ------------------------------------------------------------------ login */
function Login() {
  const [u, setU] = useState("admin"), [p, setP] = useState(""), [c, setC] = useState(""), [err, setErr] = useState(""), [hint, setHint] = useState<any>(null), [busy, setBusy] = useState(false);
  useEffect(() => { fetch("/api/auth/hint").then((r) => (r.ok ? r.json() : null)).then(setHint).catch(() => {}); }, []);
  const go = async (e?: any) => {
    e?.preventDefault(); setBusy(true); setErr("");
    try {
      let code = c;
      if (hint) { const h = await fetch("/api/auth/hint").then((r) => (r.ok ? r.json() : null)).catch(() => null); const acc = h?.accounts?.find((a: any) => a.user === u.trim().toLowerCase() && a.password === p); if (acc) code = acc.totp_now; }   // demo only: codes rotate every 30 s, so use a fresh one
      await login(u, p, code);
    } catch (x: any) { setErr(x.message || "Sign-in failed"); }
    setBusy(false);
  };
  return (
    <div className="login-wrap">
      <form className="panel login" onSubmit={go}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 6 }}><img src="/athena-logo.png" alt="ATHENA Cyber Defense" style={{ height: 160, width: "auto" }} /></div>
        <div className="sub">Predict. Explain. Heal. Without switching the city off.</div>
        <label htmlFor="u">User</label><input id="u" type="text" value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" />
        <label htmlFor="p">Password</label><input id="p" type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" />
        <label htmlFor="c">6-digit code (MFA)</label><input id="c" type="text" value={c} onChange={(e) => setC(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" placeholder="123456" />
        <button className="btn primary big" style={{ marginTop: 16 }} disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        {err && <div className="err" role="alert">{err}</div>}
        {hint && (
          <div className="demo"><b>Demo accounts</b> <span className="dim">(tap one to fill)</span>
            <div>{hint.accounts.map((a: any) => <button key={a.user} type="button" className="btn small" onClick={() => { setU(a.user); setP(a.password); setC(a.totp_now); setErr(""); }}>{a.user} · {a.role}</button>)}</div></div>
        )}
      </form>
    </div>
  );
}

/* ------------------------------------------------------------------ top bar */
const MODES: [string, string][] = [["observe", "Watch only"], ["suggest", "Ask me first"], ["auto_low", "Auto (safe steps)"], ["auto_all", "Full auto"]];
function TopBar() {
  const snap = useStore((s) => s.snap), ana = useStore((s) => s.ana), role = useStore((s) => s.role), user = useStore((s) => s.user), hist = useStore((s) => s.hist), side = useStore((s) => s.side), marks = useStore((s) => s.marks);
  if (!snap) return null;
  const stt = statusOf(snap); const sar = ana?.summary; const inc = [...(snap.incidents || [])].reverse().find((i: any) => i.status === "open" || i.status === "contained");
  const h = hist.slice(-90); const ok = snap.services.served_frac; const w = snap.watch; const shown = w.shown ?? w.p; const word = w.phase === "healing" ? "Healing" : w.phase === "waiting" ? "Plan ready" : stt.word;
  const stopped = !!snap.stopped; const lastMark = [...marks].reverse().find((m) => Date.now() - m.wall < 25000);
  return (
    <div className="panel top">
      <div className="logo"><Mark size={42} /><div>ATHENA<small>City Threat Atlas · {snap.clock}</small></div></div>
      <div className="kpi" title="Share of homes with water and power right now"><div className="l">Homes served</div><div className="v" style={{ color: ok > 0.99 ? C.aquaD : ok > 0.9 ? C.apricot : C.terra }}><Num v={ok * 100} d={1} suffix="%" /></div></div>
      <div className="kpi worst" title="Worst-case service lost in 95 of 100 simulated attacks"><div className="l">Worst case</div><div className="v">{sar ? k(sar.sar95) : "…"}</div></div>
      <div className="kpi hb" title={w.note || "Attack probability: flat = calm, spike = something is wrong"}><div className="l row between"><span>Heartbeat</span><span className="hbword" style={{ color: stt.color }}>{word} · {(shown * 100).toFixed(0)}%</span></div><Heartbeat data={h.map((x) => x.p)} h={26} color={stt.color} thr={0.85} marks={marksOn(h, marks)} />{lastMark ? <div className="hbnote">✓ {lastMark.label}{lastMark.after !== undefined && lastMark.before !== undefined ? `: worst case ${k(lastMark.before)} → ${k(lastMark.after)}` : ""}</div> : w.note && <div className="hbnote">{w.note}</div>}</div>
      {inc && <div className="kpi" style={{ minWidth: 110 }} title="CERT-In: report within 6 hours"><div className="l">Report due in</div><div className="row"><Ring value={inc.left_min} max={360} size={32} stroke={4} color={C.terra}>{""}</Ring><b>{Math.floor(inc.left_min / 60)}h {inc.left_min % 60}m</b></div></div>}
      <div className="spacer" />
      <span className={"livepill" + (snap.paused ? " off" : "")}><i />{snap.paused ? "Paused" : "Live simulation"}</span>
      <select value={snap.autonomy} disabled={!can(role, "operator")} onChange={(e) => api("/api/autonomy", { body: { mode: e.target.value } }).catch(() => {})} aria-label="Who acts" title="Who may act on its own?">{MODES.filter(([m]) => m !== "auto_all" || role === "admin").map(([m, l]) => <option key={m} value={m}>{l}</option>)}</select>
      {can(role, "operator") && <select value={snap.speed} onChange={(e) => api("/api/speed", { body: { x: +e.target.value } })} aria-label="Speed" title="Simulation speed">{[1, 4, 16].map((x) => <option key={x} value={x}>×{x}</option>)}</select>}
      {can(role, "operator") && (stopped
        ? <button className="btn small heal" title="Start attacks and automatic defence again" onClick={() => api("/api/resume", { method: "POST" }).then(() => toast("ok", "Simulation resumed"))}>▶ Resume</button>
        : <button className="btn small danger" title="Emergency stop: halts running attacks, turns automatic attacks off, defence asks first" onClick={() => api("/api/freeze", { method: "POST" }).then((r) => toast("warn", r.halted ? `Stopped: ${r.halted} attack(s) halted` : "Stopped: automatic attacks are off"))}>■ Stop</button>)}
      <button className="btn small primary" onClick={() => setState({ judge: 0, side: true })}><Ic n="play" cls="" /> Tour</button>
      <button className={"btn small" + (side ? " primary" : "")} title="Show or hide the side panel" onClick={() => setState({ side: !side })}><Ic n="layers" /> Panel</button>
      <div style={{ textAlign: "right", fontSize: 11.5, lineHeight: 1.3 }}><b>{user}</b><div className="dim">{role} · <a style={{ color: C.terraD, cursor: "pointer", fontWeight: 700 }} onClick={logout}>sign out</a></div></div>
    </div>
  );
}

/* ------------------------------------------------------------------ tour */
const JUDGE: { view: View; act?: string; title: string; text: string }[] = [
  { view: "city", title: "A real Mumbai ward", text: "Pipes, power lines and hospitals below. Computers that control them float above. BARC, IT hubs and tourist spots sit on the surrounding land." },
  { view: "predict", title: "Predict before it happens", text: "Which devices are most likely to be attacked next, why, and what to do about each." },
  { view: "path", title: "How a hacker gets in", text: "One dangerous route per entry point, so you see more than one door." },
  { view: "fix", title: "What to fix first", text: "Risk drops from before to after. Fixes that need a restart are scheduled by outage cost and urgency." },
  { view: "lab", title: "What if it is hacked?", text: "Pick a device and press Simulate: reachable devices, services lost and the fixes that close them." },
  { view: "defend", act: "attack:standard", title: "A live attack", text: "Watch ATHENA detect it, cut one link, and keep water flowing." },
  { view: "defend", act: "attack:spoof", title: "Fake sensor readings", text: "No signature needed: a physics law breaks and the alarm rings." },
  { view: "defend", act: "attack:insider", title: "An attacker already inside", text: "An insider starts on an office or control machine. No internet hop is needed, yet ATHENA still notices." },
  { view: "zeroday", act: "zeroday", title: "A zero-day nobody has seen", text: "ATHENA spots the behaviour, learns a rule and protects the whole product family." },
  { view: "how", title: "How it works", text: "Attack and defence run side by side, with each algorithm named." },
  { view: "why", title: "Why choose it", text: "Real measured numbers: accuracy, scale, rules followed." },
];
function Tour() {
  const j = useStore((s) => s.judge), role = useStore((s) => s.role); const [auto, setAuto] = useState(true);
  useEffect(() => {
    if (j === null) return; const s = JUDGE[j];
    setState({ view: s.view, side: true, selected: null, focus: null, ...(s.view === "path" ? {} : { pathSel: null }) }); scene.current?.flyTo("overview");
    if (s.act === "zeroday" && can(role, "analyst")) api("/api/zeroday", { body: { mode: "standard" } }).catch(() => {});
    if (s.act?.startsWith("attack:") && can(role, "analyst")) api("/api/attack", { body: { mode: s.act.split(":")[1], entry: null, goal: null, stealth: 4 } }).catch(() => {});
  }, [j]);
  useEffect(() => { if (j === null || !auto) return; const t = setTimeout(() => setState({ judge: j + 1 >= JUDGE.length ? null : j + 1 }), 20000); return () => clearTimeout(t); }, [j, auto]);
  if (j === null) return null; const s = JUDGE[j];
  return (
    <div className="tour" role="dialog" aria-label="Guided tour">
      <div className="row between"><span className="n">STEP {j + 1} OF {JUDGE.length}</span><button className="btn small" onClick={() => setState({ judge: null })}>Skip</button></div>
      <h3>{s.title}</h3><p>{s.text}</p>
      <div className="row" style={{ marginTop: 10 }}><button className="btn small" onClick={() => setState({ judge: Math.max(0, j - 1) })}>← Back</button><button className="btn small primary" onClick={() => setState({ judge: j + 1 >= JUDGE.length ? null : j + 1 })}>{j + 1 >= JUDGE.length ? "Finish" : "Next →"}</button><button className="btn small" onClick={() => setAuto(!auto)}><Ic n={auto ? "pause" : "play"} /></button></div>
      <div className="prog" style={{ width: `${((j + 1) / JUDGE.length) * 100}%` }} />
    </div>
  );
}

/* ------------------------------------------------------------------ the map + its small controls */
function useHold(fn: () => void) {
  const t = useRef<any>(null); const stop = () => { clearInterval(t.current); t.current = null; };
  useEffect(() => stop, []);
  return { onPointerDown: (e: React.PointerEvent) => { e.preventDefault(); fn(); stop(); t.current = setInterval(fn, 70); }, onPointerUp: stop, onPointerLeave: stop, onPointerCancel: stop };
}
const PadBtn = ({ icon, tip, fn }: { icon: string; tip: string; fn: () => void }) => <button aria-label={tip} title={tip} {...useHold(fn)}><Ic n={icon} /></button>;

/** Each press of Hospitals / Water plants / Power zooms right in on the next one (they are kilometres apart, so one view cannot show all of them closely). */
const TOURS: Record<string, string[][]> = { hospital: [["H1"], ["H2"], ["H3"]], water: [["PS1", "T1"], ["PS2", "T2"], ["V1", "V2"]], power: [["CB_F1"], ["CB_F2"], ["CB_F3"]] };
const TOUR_WORD: Record<string, string> = { hospital: "Hospital", water: "Water site", power: "Power breaker" };
const tourAt: Record<string, number> = {};
function zoomTour(key: string, st: any) {
  const list = TOURS[key]; const i = (tourAt[key] = ((tourAt[key] ?? -1) + 1) % list.length); const ids = list[i]; scene.current?.frameNodes(ids, true);
  toast("ok", `${TOUR_WORD[key]} ${i + 1} of ${list.length}: ${ids.map((x) => (st.physical[x]?.name || x).replace(/ \(.*\)/, "")).join(" and ")}. Press again for the next.`);
}

function MapOverlay() {
  const view = useStore((s) => s.view), follow = useStore((s) => s.follow); const layers = useStore((s) => s.layers), stack = useStore((s) => s.stack), xray = useStore((s) => s.xray), toast_ = useStore((s) => s.toast), connected = useStore((s) => s.connected), full = useStore((s) => s.full), graph = useStore((s) => s.graph), snap = useStore((s) => s.snap);
  const [pad, setPad] = useState(false);
  const S = () => scene.current;
  const tog = (key: string) => setState((s) => ({ layers: { ...s.layers, [key]: !s.layers[key] } }));
  const decoys = snap?.defence?.decoys?.length || 0;
  const tools = [
    ["full", full ? "Exit full screen" : "Full screen", full, () => setState({ full: !full })],
    ["share", "2D network view", graph, () => setState({ graph: !graph })],
    ["link", "Network links", layers.links !== false, () => tog("links")], ["hill", "Risk hills", !!layers.risk, () => tog("risk")],
    ["mask", decoys ? `Decoys (${decoys} placed)` : "Decoys: none yet. Select a device, then press Place decoy", xray, () => { setState({ xray: !xray }); if (!xray && !decoys) toast("ok", "No decoys yet: select a device and press 'Place decoy'"); }],
    ["layers", "3D layers", stack, () => setState({ stack: !stack })], ["move", "Move pad", pad, () => setPad(!pad)],
  ] as const;
  return (
    <>
      <MapTitle />
      <div className="maptools">{tools.map(([ic, tip, on, fn]) => <button key={tip} className={"mapbtn" + (on ? " on" : "")} data-tip={tip} aria-label={tip} aria-pressed={on} onClick={fn}><Ic n={ic} />{ic === "mask" && decoys > 0 && <b className="badge">{decoys}</b>}</button>)}</div>
      <div className="views">{[["overview", "Overview"], ["hospital", "Hospitals"], ["water", "Water plants"], ["power", "Power"], ["mumbai", "Mumbai"]].map(([v, l]) => <button key={v} onClick={() => { setState({ stack: false, focus: null, selected: null }); if (TOURS[v]) zoomTour(v, getState().st); else S()?.flyTo(v); }}>{l}</button>)}</div>
      <IncidentCard />
      {view === "defend" || view === "zeroday" ? <button className={"followbtn" + (follow ? " on" : "")} onClick={() => setState({ follow: !follow, focus: null })}>{follow ? "● Following the attack (drag the map to stop)" : "Follow the attack"}</button> : null}
      {pad && <div className="pad" aria-label="Move the map">
        <PadBtn icon="rotl" tip="Turn left" fn={() => S()?.turn(0.08)} /><PadBtn icon="up" tip="Move forward" fn={() => S()?.nudge(0, 0.08)} /><PadBtn icon="rotr" tip="Turn right" fn={() => S()?.turn(-0.08)} />
        <PadBtn icon="left" tip="Move left" fn={() => S()?.nudge(-0.08, 0)} /><button aria-label="Reset view" title="Reset view" onClick={() => S()?.flyTo("overview")}><Ic n="target" /></button><PadBtn icon="right" tip="Move right" fn={() => S()?.nudge(0.08, 0)} />
        <PadBtn icon="minus" tip="Zoom out" fn={() => S()?.zoom(1.04)} /><PadBtn icon="down" tip="Move back" fn={() => S()?.nudge(0, -0.08)} /><PadBtn icon="plus" tip="Zoom in" fn={() => S()?.zoom(0.96)} />
      </div>}
      <Legend /><Timeline /><NodeCard />
      {full && <button className="exitfull" onClick={() => setState({ full: false })}>✕ Exit full screen</button>}
      {toast_ && <div key={toast_.id} className={"toast " + toast_.sev}>{toast_.text}</div>}
      {!connected && <div className="reconnect">Reconnecting to the server…</div>}
    </>
  );
}

function SceneHost({ hidden }: { hidden: boolean }) {
  const host = useRef<HTMLDivElement>(null); const st = useStore((s) => s.st), geo = useStore((s) => s.geo), snap = useStore((s) => s.snap), ana = useStore((s) => s.ana), view = useStore((s) => s.view), sel = useStore((s) => s.selected);
  const layers = useStore((s) => s.layers), stack = useStore((s) => s.stack), xray = useStore((s) => s.xray), pathSel = useStore((s) => s.pathSel), role = useStore((s) => s.role), labNodes = useStore((s) => s.labNodes), focus = useStore((s) => s.focus);
  useEffect(() => {
    if (!st || !geo || !host.current) return;
    const sc = new CityScene(host.current, (id) => pickNode(getState().st, id)); scene.current = sc;
    sc.onUserMove = () => { if (getState().follow) { setState({ follow: false }); toast("ok", "Following stopped. Press Follow the attack to resume."); } };
    sc.onHover = (id) => setState({ hovered: id }); sc.onQuality = (q) => setState({ quality: q }); sc.setStatic(st, geo);
    return () => { sc.dispose(); scene.current = null; };
  }, [st, geo]);
  useEffect(() => { if (scene.current) { scene.current.hidden = hidden; if (!hidden) scene.current.resize(); } }, [hidden, st, geo]);
  useEffect(() => { scene.current?.setSnapshot(snap); }, [snap]);
  useEffect(() => { scene.current?.setAnalytics(ana); }, [ana]);
  type Draw = { nodes: string[]; edges: string[]; kind: string; segs?: string[][]; marks?: string[] };
  const draw = useMemo<Draw>(() => {   // what to highlight: whatever the person pressed in the side panel, else the chosen route, else the live attacker
    if (focus) return { nodes: focus.route?.nodes || [], edges: focus.edges || [], segs: focus.segs, marks: focus.marks, kind: focus.kind };
    if ((view === "path" || view === "lab" || view === "live") && pathSel) return { nodes: pathSel.nodes as string[], edges: pathSel.edges as string[], kind: "attack" };
    const inc = [...(snap?.incidents || [])].reverse().find((i: any) => i.status === "open" || i.status === "contained");
    if ((view === "defend" || view === "zeroday") && snap?.adversary?.length && can(role, "operator")) { const c = [...snap.adversary].reverse().find((x: any) => x.state !== "done" && x.state !== "contained") || snap.adversary[snap.adversary.length - 1]; if (c && c.compromised.length > 1) return { nodes: c.compromised as string[], edges: c.hops.map((h: any) => h.edge) as string[], kind: "attack" }; }
    if ((view === "defend" || view === "zeroday") && inc?.next_hops?.length) { const h = inc.next_hops[0]; return { nodes: [h.src, h.dst], edges: [h.edge], kind: "predicted" }; }
    return { nodes: [] as string[], edges: [] as string[], kind: "none" };
  }, [view, pathSel, focus, snap?.adversary, snap?.incidents, role]);
  const dkey = draw.nodes.join(">") + "|" + draw.edges.join(",") + "|" + draw.kind + "|" + JSON.stringify(draw.segs || []) + "|" + (draw.marks || []).join(",");
  useEffect(() => {
    const labOn = (view === "lab" || view === "live") && labNodes.length > 0;
    scene.current?.setUI({ mode: stack ? "stack" : "city", layers, selected: labOn ? labNodes[0] : sel, xray, pathNodes: draw.nodes, pathEdges: draw.edges, pathSegs: draw.segs, pathMarks: draw.marks, pathKind: draw.kind, blast: focus?.blast || null, role, hotNodes: labOn ? labNodes : sel ? st.edges.filter((e: any) => e.source === sel || e.target === sel).flatMap((e: any) => [e.source, e.target]) : null });
  }, [stack, layers, sel, xray, dkey, role, st, view, labNodes, focus?.blast]);
  useEffect(() => { if (view === "path" && pathSel && !focus) scene.current?.flyTo("path"); }, [view, pathSel]);
  // Follow the attack: first the public side and the door being tried, then each new step as it happens, then the whole affected area. Any drag, zoom or key press stops it.
  const follow = useStore((s) => s.follow);
  const camp = view === "defend" || view === "zeroday" ? [...(snap?.adversary || [])].reverse()[0] : null; const stepKey = camp ? `${camp.id}:${camp.compromised.length}:${camp.state}` : "";
  useEffect(() => {
    if (!follow || !camp || getState().focus) return; const comp: string[] = camp.compromised; const finished = camp.state === "done" || camp.state === "contained";
    if (finished && comp.length > 1) scene.current?.frameNodes(comp.filter((n) => n !== "INTERNET"));
    else if (comp.length <= 1) scene.current?.frameNodes(["INTERNET", camp.entry].filter(Boolean) as string[]);
    else { const h = camp.hops[camp.hops.length - 1]; if (h) scene.current?.frameNodes([h.src, h.dst], true); }
  }, [follow, stepKey]);
  useEffect(() => { if (focus) scene.current?.frameNodes([...(focus.route?.nodes || []), ...(focus.marks || [])]); }, [focus?.key]);
  useEffect(() => { if (sel && !getState().focus) scene.current?.flyTo("node", sel); }, [sel]);
  return <div className="stage" ref={host} />;
}

function Hover() {
  const h = useStore((s) => s.hovered), st = useStore((s) => s.st), ana = useStore((s) => s.ana); const [pos, setPos] = useState([0, 0]);
  useEffect(() => { if (!h) return; const f = (e: MouseEvent) => setPos([e.clientX, e.clientY]); window.addEventListener("mousemove", f); return () => window.removeEventListener("mousemove", f); }, [!!h]);
  if (!h || !st) return null; const a = st.assets[h] || st.physical[h]; if (!a) return null; const r = ana?.ranking?.find((x: any) => x.id === h);
  return <div className="hover" style={{ left: pos[0] + 14, top: pos[1] + 12 }}><b>{a.name}</b>{r && <div className="dim">harm if hacked {k(r.raw)} · #{r.rank_sar}</div>}<div className="dim">click for details</div></div>;
}

/* ------------------------------------------------------------------ app */
export default function App() {
  const token = useStore((s) => s.token), booting = useStore((s) => s.booting), view = useStore((s) => s.view), snap = useStore((s) => s.snap), st = useStore((s) => s.st), side = useStore((s) => s.side), full = useStore((s) => s.full), graph = useStore((s) => s.graph);
  useEffect(() => { if (token && !getState().st) boot().catch(() => {}); }, [token]);
  useEffect(() => {
    const f = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement; if (["INPUT", "SELECT", "TEXTAREA"].includes(t?.tagName) || e.ctrlKey || e.metaKey || e.altKey) return;
      const k = e.key.toLowerCase(); const S = scene.current;
      if (k === "1") S?.flyTo("overview"); if (k === "2") S?.flyTo("water"); if (k === "3") S?.flyTo("hospital"); if (k === "4") S?.flyTo("mumbai"); if (k === "f") setState({ full: !getState().full });
      if (k === "escape") setState({ full: false });
      if (k === "x") setState({ xray: !getState().xray }); if (k === "j") setState({ judge: 0, side: true }); if (k === "l") setState((s) => ({ layers: { ...s.layers, links: !s.layers.links } })); if (k === "r") setState((s) => ({ layers: { ...s.layers, risk: !s.layers.risk } }));
    };
    window.addEventListener("keydown", f); return () => window.removeEventListener("keydown", f);
  }, []);
  useEffect(() => {   // real browser full screen follows the button; leaving it (Esc) clears the flag
    const el = document.documentElement;
    if (full && !document.fullscreenElement) el.requestFullscreen?.().catch(() => {}); if (!full && document.fullscreenElement) document.exitFullscreen?.().catch(() => {});
    const on = () => { if (!document.fullscreenElement && getState().full) setState({ full: false }); }; document.addEventListener("fullscreenchange", on); return () => document.removeEventListener("fullscreenchange", on);
  }, [full]);
  if (!token) return <Login />;
  if (booting || !st || !snap) return <div className="login-wrap"><div className="panel login" style={{ textAlign: "center" }}><Mark size={56} /><h1 style={{ fontSize: 22 }}>Loading the city…</h1><div className="sub">Building 7,400 real buildings and connecting to the live twin.</div></div></div>;
  const Panel = PANEL[view]; const page = view === "how" || view === "why"; const hasIncident = (snap.incidents || []).some((i: any) => i.status === "open");
  const go = (id: View) => { if (id === "how" || id === "why") { setState({ view: id, selected: null, focus: null, pathSel: null, full: false }); return; } if (id === view && side && !page) { setState({ side: false }); return; } setState({ view: id, side: true, selected: null, focus: null, pathSel: null }); };
  return (
    <div className={"app" + (side && !page ? " open" : "") + (page ? " page" : "") + (full ? " full" : "")}>
      <TopBar />
      <nav className="panel rail" aria-label="Pages">{NAV.map((n) => <button key={n.id} className={view === n.id && (side || n.id === "how" || n.id === "why") ? "on" : ""} onClick={() => go(n.id)} aria-current={view === n.id} title={n.label}><Ic n={n.icon} /><span>{n.label}</span>{(n.id === "defend" || n.id === "zeroday") && hasIncident && <span className="dot" />}</button>)}</nav>
      <div className={"stagewrap" + (graph ? " split" : "")} style={page ? { display: "none" } : undefined}><div className="mapcol"><SceneHost hidden={page} /><MapOverlay />{!side && !full && <button className="sidetab" onClick={() => setState({ side: true })} aria-label="Open the side panel">◂<span>{NAV.find((n) => n.id === view)?.label}</span></button>}</div>{graph && <GraphPanel />}</div>
      {page && <main className="fullpage" aria-label={NAV.find((n) => n.id === view)?.label}><Panel /></main>}
      {side && !full && !page && <main className="panel side"><div className="sidebar-top"><span>{NAV.find((n) => n.id === view)?.label}</span><button className="btn small" onClick={() => setState({ side: false })} aria-label="Close the side panel">Hide ▸</button></div><Tour /><SelectedBar /><Panel /></main>}
      {page && <Tour />}
      <Hover />
    </div>
  );
}
