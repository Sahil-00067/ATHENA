import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { setState, useStore } from "../store";
import { C } from "../palette";
import { Box, Ic, PageHead, Stat } from "./ui";
import { can, nameOf } from "./status";
import { setPath } from "./Views";

const cut = (s: string, n: number) => (s && s.length > n ? s.slice(0, n - 1).trimEnd() + "…" : s || "");
const LABEL: Record<string, string> = {
  port_scan: "Port scan",
  brute_force: "Brute force",
  syn_flood: "Connection flood",
  unknown_anomaly: "Unusual behaviour",
};
const WHAT: Record<string, string> = {
  port_scan: "The hacker is knocking on many doors to see which are open (reconnaissance).",
  brute_force: "The hacker keeps trying one service, guessing its password.",
  syn_flood: "The hacker is flooding the machine with connection requests to knock it offline.",
  unknown_anomaly: "Traffic that does not look like this machine's normal baseline behaviour.",
};

/** Hacker -> your real machine -> what it would give access to inside the simulated ward. */
function Diagram({ ev, laptop, reach }: { ev: any; laptop: string; reach: string[] }) {
  const rows = reach.slice(0, 5);
  const H = Math.max(190, 50 + rows.length * 34);
  const ly = H / 2;
  return (
    <svg
      viewBox={`0 0 400 ${H}`}
      width="100%"
      role="img"
      aria-label="Attack from the hacker's machine to your machine and onward into the ward"
      style={{ background: C.paper, borderRadius: 10, border: `1px solid ${C.line}` }}
    >
      <defs>
        <marker id="live-arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 0 8 4 0 8z" fill={C.terra} />
        </marker>
        <marker id="ward-arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 0 8 4 0 8z" fill={C.apricot} />
        </marker>
      </defs>
      <line x1="82" y1={ly} x2="150" y2={ly} stroke={C.terra} strokeWidth="3" strokeDasharray="6 4" markerEnd="url(#live-arr)">
        <animate attributeName="stroke-dashoffset" from="20" to="0" dur="0.8s" repeatCount="indefinite" />
      </line>
      {rows.map((r, i) => {
        const y = 30 + i * ((H - 60) / Math.max(1, rows.length - 1 || 1));
        const yy = rows.length === 1 ? ly : y;
        return (
          <g key={r}>
            <line x1="244" y1={ly} x2="288" y2={yy} stroke={C.apricot} strokeWidth="2" strokeDasharray="4 3" markerEnd="url(#ward-arr)" />
            <rect x="290" y={yy - 13} width="104" height="26" rx="7" fill={C.cream} stroke={C.apricot} />
            <text x="342" y={yy + 4} textAnchor="middle" fontSize="9.5" fill={C.ink}>
              {cut(r, 19)}
            </text>
          </g>
        );
      })}
      <g>
        <circle cx="42" cy={ly} r="34" fill={C.terra} opacity=".15">
          <animate attributeName="r" values="30;38;30" dur="1.6s" repeatCount="indefinite" />
        </circle>
        <circle cx="42" cy={ly} r="26" fill={C.terra} />
        <text x="42" y={ly - 2} textAnchor="middle" fontSize="9.5" fontWeight="700" fill="#fff">
          HACKER
        </text>
        <text x="42" y={ly + 10} textAnchor="middle" fontSize="7.5" fill="#fff">
          {cut(ev?.offender || "attacker", 15)}
        </text>
      </g>
      <g>
        <rect x="152" y={ly - 30} width="92" height="60" rx="10" fill={C.apricot} />
        <text x="198" y={ly - 12} textAnchor="middle" fontSize="9" fontWeight="700" fill={C.ink}>
          YOUR MACHINE
        </text>
        <text x="198" y={ly + 2} textAnchor="middle" fontSize="8.5" fill={C.ink}>
          {cut(ev?.host || "sensor host", 16)}
        </text>
        <text x="198" y={ly + 16} textAnchor="middle" fontSize="7.5" fill={C.ink}>
          plays: {cut(laptop, 15)}
        </text>
      </g>
      {rows.length === 0 && (
        <text x="342" y={ly + 4} textAnchor="middle" fontSize="9" fill={C.dim}>
          no further reach
        </text>
      )}
    </svg>
  );
}

export function LiveView() {
  const st = useStore((s) => s.st),
    role = useStore((s) => s.role);
  const [live, setLive] = useState<any>(null);
  const [err, setErr] = useState("");
  const [mapped, setMapped] = useState("OFFICE_PC_02");
  const [sim, setSim] = useState<any>(null);
  const [simErr, setSimErr] = useState("");
  const seen = useRef<string>("");

  const assets = useMemo(() => {
    if (!st?.assets) return [];
    return Object.values<any>(st.assets).filter((a) => a.id !== "INTERNET");
  }, [st]);

  useEffect(() => {
    let on = true;
    const tick = () => {
      api("/api/live")
        .then((r) => {
          if (on) {
            setLive(r);
            setErr("");
          }
        })
        .catch((e) => {
          if (on) setErr(e.message);
        });
    };
    tick();
    const t = setInterval(tick, 1500);
    return () => {
      on = false;
      clearInterval(t);
    };
  }, []);

  const last = live?.last_alert;
  const key = last ? `${last.received}|${last.offender}|${last.label}|${last.host}` : "";

  const run = (start: string) => {
    if (!can(role, "analyst")) {
      setSimErr("Sign in as analyst or admin to see what the attacker could reach.");
      return;
    }
    api("/api/v2/simulate/compromise", { body: { start, credentials: [] } })
      .then((r) => {
        setSim(r);
        setSimErr("");
        const comp: string[] = r.compromised || [];
        setState({ labNodes: comp });
        if (st?.actions && st?.edges) {
          const ctrl = Object.values<any>(st.actions)
            .map((a) => a.controller)
            .filter((c) => comp.includes(c) && r.paths?.[c])
            .sort((a, b) => (r.paths[b]?.length || 0) - (r.paths[a]?.length || 0))[0];
          if (ctrl) {
            const edges: string[] = r.paths[ctrl];
            const nodes = [start];
            for (const eid of edges) {
              const e = st.edges.find((x: any) => x.id === eid);
              nodes.push(e ? e.target : eid);
            }
            setPath(st, nodes, edges, "attack");
          } else {
            setState({ pathSel: null, focus: null });
          }
        }
      })
      .catch((e) => setSimErr(e.message));
  };

  useEffect(() => {
    if (key && key !== seen.current) {
      seen.current = key;
      run(mapped);
    }
  }, [key]);

  useEffect(() => {
    if (last || live?.hosts?.length) {
      run(mapped);
    }
  }, [mapped, live?.hosts?.length]);

  useEffect(() => {
    return () => {
      setState({ labNodes: [], pathSel: null, focus: null });
    };
  }, []);

  const a = st?.assets?.[mapped];
  const cve = a?.cve && st?.threat_snapshot?.cves ? st.threat_snapshot.cves[a.cve] : null;
  const reach = (sim?.compromised || []).slice(1).map((i: string) => nameOf(st, i));
  const events: any[] = (live?.events || []).filter((e: any) => e.kind === "alert");

  return (
    <>
      <PageHead
        icon="radio"
        title="Live"
        sub={last ? "A real machine is being attacked right now" : live?.hosts?.length ? "Sensor active and watching normal traffic" : "Waiting for a live sensor"}
        right={
          <span className={"pill " + (last ? "crit pulse" : live?.hosts?.length ? "safe" : "info")}>
            {last ? "ALERT" : live?.hosts?.length ? "watching" : "no sensor"}
          </span>
        }
      />

      {err && <div className="tip">Could not read live data: {err}</div>}

      {!live?.hosts?.length && (
        <div className="tip">
          <b>No sensor connected yet.</b> On the machine you want to protect (as Administrator) run:
          <br />
          <code>.\.venv\Scripts\python backend\live_sensor.py --api http://127.0.0.1:8000 --key decoy-lab-key</code>
          <br />
          Wait for “baseline learned”, then attack it from another laptop you own (e.g. <code>nmap -sT &lt;ip&gt;</code>).
          <br />
          Or rehearse with synthetic attacks without admin rights:
          <br />
          <code>.\.venv\Scripts\python backend\live_sensor.py --api http://127.0.0.1:8000 --key decoy-lab-key --simulate</code>
        </div>
      )}

      <div className="grid3">
        <Stat v={live?.hosts?.length ?? 0} l="sensors reporting" color={C.aquaD} />
        <Stat v={live?.alerts ?? 0} l="alerts" color={C.terra} />
        <Stat v={last ? LABEL[last.label] || last.label : "–"} l="latest attack type" color={C.apricot} />
      </div>

      {last ? (
        <Box id="live-what" title="What is happening" icon="mask" value={LABEL[last.label] || last.label} tone="crit" defaultOpen>
          <div className="tip">
            {WHAT[last.label] || "Real anomalous traffic detected."} <b>From {last.offender}</b>
            {last.ports ? <> · {last.ports} port{last.ports === 1 ? "" : "s"} tried</> : null}
            {last.syn ? <> · {last.syn} connection attempts</> : null}.
          </div>
          {last.targets?.length > 0 && (
            <div className="row wrap" style={{ gap: 5, margin: "6px 0" }}>
              {last.targets.map((p: number) => (
                <span key={p} className="pill info">
                  port {p}
                </span>
              ))}
            </div>
          )}
          <div className="tip">
            <b>DECOY's response:</b> {last.action}
          </div>
          <div className="row" style={{ marginTop: 8 }}>
            <label className="dim" style={{ fontSize: 12 }}>
              This real machine stands in for:
            </label>
            <select
              value={mapped}
              onChange={(e) => setMapped(e.target.value)}
              aria-label="Which ward device this machine represents"
              style={{ marginLeft: 8 }}
            >
              {assets.map((x: any) => (
                <option key={x.id} value={x.id}>
                  {cut(x.name, 38)}
                </option>
              ))}
            </select>
          </div>
        </Box>
      ) : live?.hosts?.length ? (
        <Box id="live-standin" title="Defended machine stand-in" icon="shield" value={nameOf(st, mapped)} tone="safe" defaultOpen>
          <div className="tip">
            <b>Sensor connected:</b> Host <b>{live.hosts.join(", ")}</b> is actively reporting normal traffic.
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            <label className="dim" style={{ fontSize: 12 }}>
              This real machine stands in for:
            </label>
            <select
              value={mapped}
              onChange={(e) => setMapped(e.target.value)}
              aria-label="Which ward device this machine represents"
              style={{ marginLeft: 8 }}
            >
              {assets.map((x: any) => (
                <option key={x.id} value={x.id}>
                  {cut(x.name, 38)}
                </option>
              ))}
            </select>
          </div>
        </Box>
      ) : null}

      <Box
        id="live-path"
        title="Attack route into the ward"
        icon="route"
        value={sim ? `${Math.max(0, (sim.compromised || []).length - 1)} more reachable` : "…"}
        tone={reach.length ? "crit" : "safe"}
        defaultOpen
      >
        <Diagram ev={last || { offender: "10.0.0.5", host: live?.hosts?.[0] || "my-pc" }} laptop={nameOf(st, mapped)} reach={reach} />
        {simErr && <div className="tip">{simErr}</div>}
        {sim?.services_lost?.length > 0 && (
          <>
            <div className="tip" style={{ marginTop: 8 }}>
              <b>If it went all the way, people would lose:</b>
            </div>
            <div className="row wrap" style={{ gap: 5, margin: "4px 0" }}>
              {sim.services_lost.slice(0, 6).map((s: string) => (
                <span key={s} className="pill crit">
                  {cut(s, 30)}
                </span>
              ))}
            </div>
          </>
        )}
        <div className="tip dim" style={{ marginTop: 6 }}>
          The packets are real. What the hacker could reach next is simulated: this machine is treated as “{nameOf(st, mapped)}” inside the city model, and the route is drawn on the 3D map.
        </div>
      </Box>

      <Box id="live-vuln" title="What is weak here" icon="lock" value={cve ? a?.cve : "no known bug"} tone={cve ? "watch" : "safe"}>
        {cve ? (
          <div className="list-row" style={{ cursor: "default" }}>
            <div className="grow">
              <div style={{ fontSize: 13, fontWeight: 700 }}>
                {a.cve} <span className="dim" style={{ fontWeight: 400 }}>({cut(cve.device_class || "", 46)})</span>
              </div>
              <div className="dim" style={{ fontSize: 11.5 }}>
                severity {cve.cvss} · exploit chance {typeof cve.epss === "number" ? (cve.epss * 100).toFixed(1) : 0}%
                {cve.in_kev ? " · exploited in real attacks (CISA KEV)" : ""}
              </div>
            </div>
            {cve.in_kev && <span className="pill crit">KEV</span>}
          </div>
        ) : (
          <div className="tip">The stand-in device has no known bug in the threat feed.</div>
        )}
        <div className="tip dim">Ports the hacker probed are listed above. Anything listening there is a possible way in.</div>
      </Box>

      <Box id="live-feed" title="Alert history" icon="clock" value={events.length} tone={events.length ? "crit" : "info"}>
        {events.length > 0 ? (
          <div className="col" style={{ gap: 6 }}>
            {events.slice(0, 15).map((e: any, i: number) => (
              <div key={i} className="list-row" style={{ cursor: "default" }}>
                <span className="dim" style={{ fontSize: 11 }}>
                  {e.received}
                </span>
                <div className="grow" style={{ fontSize: 12.5 }}>
                  <b>{LABEL[e.label] || e.label}</b> from {e.offender}
                  <div className="dim" style={{ fontSize: 11 }}>
                    {cut(e.action || "", 80)}
                  </div>
                </div>
                <span className="pill crit">{Math.round((e.severity || 0) * 100)}%</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="tip dim">No alerts logged yet. When an attack is detected by the sensor, it will appear here.</div>
        )}
      </Box>
    </>
  );
}
