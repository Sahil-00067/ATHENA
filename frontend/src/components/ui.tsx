import React, { useEffect, useRef, useState } from "react";

const P: Record<string, string> = {
  city: "M3 20V9l5-3v14M8 20V4l6 3v13M14 20v-9l6 2v7M2 20h20",
  route: "M5 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM19 9a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM6.5 15.5 11 11l3 3 3.5-4",
  wrench: "m14.5 6.5-8 8L4 20l5.5-2.5 8-8M13 5l3-3 4 4-3 3",
  shield: "M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6l-8-3zM9 12l2 2 4-4",
  bolt: "M13 2 4 14h7l-1 8 9-12h-7l1-8z",
  chart: "M4 20h16M7 16V10M12 16V5M17 16v-4",
  lock: "M6 11V8a6 6 0 1 1 12 0v3M5 11h14v10H5zM12 15v3",
  chevron: "m6 9 6 6 6-6",
  check: "m5 12 5 5 9-10",
  x: "M6 6l12 12M18 6 6 18",
  water: "M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z",
  plug: "M9 3v5M15 3v5M7 8h10v3a5 5 0 0 1-10 0zM12 16v5",
  hospital: "M5 21V5h14v16M12 8v6M9 11h6M9 21v-4h6v4",
  home: "M3 11 12 3l9 8M5 10v10h14V10",
  play: "M7 4v16l13-8z",
  pause: "M8 5v14M16 5v14",
  layers: "M12 3 3 8l9 5 9-5-9-5zM3 13l9 5 9-5M3 17.5l9 5 9-5",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  hill: "M2 20 9 7l4 7 3-4 6 10z",
  mask: "M12 3c4 0 8 2 8 6 0 5-3 10-8 12-5-2-8-7-8-12 0-4 4-6 8-6zM9 10h.01M15 10h.01",
  up: "m6 15 6-6 6 6", down: "m6 9 6 6 6-6", left: "m15 6-6 6 6 6", right: "m9 6 6 6-6 6",
  plus: "M12 5v14M5 12h14", minus: "M5 12h14", rotl: "M4 12a8 8 0 1 1 3 6.2M4 19v-5h5", rotr: "M20 12a8 8 0 1 0-3 6.2M20 19v-5h-5", target: "M12 12m-8 0a8 8 0 1 0 16 0 8 8 0 1 0-16 0M12 12m-3 0a3 3 0 1 0 6 0 3 3 0 1 0-6 0",
  clock: "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM12 8v4l3 2",
  radio: "M12 12m-3 0a3 3 0 1 0 6 0 3 3 0 1 0-6 0M12 12m-7 0a7 7 0 1 0 14 0 7 7 0 1 0-14 0M12 12v-8",
  question: "M9.5 9a2.5 2.5 0 1 1 3.6 2.2c-.8.5-1.1 1-1.1 1.8M12 17h.01M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z",
  doc: "M7 3h8l4 4v14H7zM14 3v5h5M10 13h6M10 17h6",
  swap: "M7 7h13l-3-3M17 17H4l3 3",
  sparkle: "M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z",
  full: "M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5",
  share: "M12 5.5a1.6 1.6 0 1 0 .01 0M5 18.5a1.6 1.6 0 1 0 .01 0M19 18.5a1.6 1.6 0 1 0 .01 0M12 7.2v4.8M12 12l-6 4.8M12 12l6 4.8",
  move: "M12 3v18M3 12h18M12 3l-3 3M12 3l3 3M12 21l-3-3M12 21l3-3M3 12l3-3M3 12l3 3M21 12l-3-3M21 12l-3 3",
};
export const Ic = ({ n, cls = "" }: { n: string; cls?: string }) => <svg className={"ic " + cls} viewBox="0 0 24 24"><path d={P[n] || P.sparkle} /></svg>;

const openMemory = new Map<string, boolean>();

/** Collapsible, scrollable box: headline value always visible, details on demand (progressive disclosure). */
export function Box({ id, title, icon, value, tone, defaultOpen = false, kind, children }: { id: string; title: string; icon?: string; value?: React.ReactNode; tone?: string; defaultOpen?: boolean; kind?: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(openMemory.has(id) ? openMemory.get(id)! : defaultOpen);
  const toggle = () => { openMemory.set(id, !open); setOpen(!open); };
  return (
    <section className={"box " + (open ? "open " : "") + (kind || "")}>
      <header onClick={toggle} role="button" aria-expanded={open} tabIndex={0} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), toggle())}>
        {icon && <Ic n={icon} />}<span className="t">{title}</span>{value !== undefined && <span className={"pill " + (tone || "info")}>{value}</span>}<Ic n="chevron" cls="chev" />
      </header>
      <div className="collapse"><div><div className="body">{children}</div></div></div>
    </section>
  );
}

import { plainMove } from "./status";

/** A remedial move: plain title and one line on what it does; the full technical description is one tap away in "details". */
export function Move({ label, extra, detail }: { label: string; extra?: React.ReactNode; detail?: React.ReactNode }) {
  const m = plainMove(label); const [open, setOpen] = useState(false);
  return (
    <div style={{ minWidth: 0 }}>
      <div style={{ fontSize: 13, fontWeight: 700, lineHeight: 1.3 }}>{m.title}</div>
      {(m.why || extra) && <div className="dim" style={{ fontSize: 11.5, lineHeight: 1.35 }}>{m.why}{extra}</div>}
      <button type="button" className="more" aria-expanded={open} onClick={(e) => { e.stopPropagation(); setOpen(!open); }}>{open ? "hide details" : "details"} <Ic n="chevron" cls={"chev" + (open ? " up" : "")} /></button>
      {open && <div className="moredetail" onClick={(e) => e.stopPropagation()}><div>{label}</div>{detail && <div className="dim">{detail}</div>}</div>}
    </div>
  );
}

export const PageHead = ({ icon, title, sub, right }: { icon: string; title: string; sub: string; right?: React.ReactNode }) => (
  <div className="page-head"><div className="badge"><Ic n={icon} /></div><div className="grow"><h2>{title}</h2><p>{sub}</p></div>{right}</div>
);

export const Stat = ({ v, l, color }: { v: React.ReactNode; l: string; color?: string }) => <div className="stat"><div className="v" style={color ? { color } : undefined}>{v}</div><div className="l">{l}</div></div>;

/** Number that glides to its new value (cheap, 400 ms). */
export function Num({ v, d = 0, suffix = "" }: { v: number; d?: number; suffix?: string }) {
  const [x, setX] = useState(v); const from = useRef(v);
  useEffect(() => {
    const a = from.current, b = v; if (a === b) return; const t0 = performance.now(); let raf = 0;
    const f = (t: number) => { const k = Math.min(1, (t - t0) / 400); const e = 1 - Math.pow(1 - k, 3); setX(a + (b - a) * e); if (k < 1) raf = requestAnimationFrame(f); else from.current = b; };
    raf = requestAnimationFrame(f); return () => { cancelAnimationFrame(raf); from.current = b; };
  }, [v]);
  return <>{x.toLocaleString("en-IN", { maximumFractionDigits: d, minimumFractionDigits: d })}{suffix}</>;
}

export const Check = () => <svg className="check" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="m5 12 5 5 9-10" /></svg>;

export const Switch = ({ on, onChange, label }: { on: boolean; onChange: () => void; label: string }) => <button className={"switch" + (on ? " on" : "")} role="switch" aria-checked={on} aria-label={label} onClick={onChange} />;

export function Steps({ labels, done, attack }: { labels: string[]; done: number; attack?: boolean }) {
  return <div className={"steps" + (attack ? " attack" : "")}>{labels.map((l, i) => <div key={l} className={"st" + (i < done ? " done" : i === done ? " now" : "")}><i>{i < done ? "✓" : i + 1}</i>{l}</div>)}</div>;
}
