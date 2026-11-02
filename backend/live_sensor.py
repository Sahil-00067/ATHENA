"""DECOY Live Sensor - watches REAL network traffic arriving at THIS computer and reacts to attacks.

Use it only on machines you own or are authorised to test (e.g. two of your own laptops in a lab).
It is defensive: it listens, learns what normal looks like, flags scans / brute force / floods, and (optionally) blocks the offender.

How it works
  1. Sniffer   : a raw socket reads incoming TCP packets (needs Administrator on Windows / root on Linux; no extra drivers).
  2. Windows   : every WINDOW seconds the packets are summarised into 6 numbers (SYNs, packets, sources, ports touched by one
                 source, SYNs from one source, SYNs from one source to one port).
  3. Learn     : for the first LEARN seconds (do NOT attack during this time) the sensor learns what "normal" looks like (mean/spread of each number).
  4. Detect    : two detectors vote. (a) a baseline model (per-feature z-scores) flags anything unlike this machine's normal (catches unseen behaviour);
                 (b) plain rules name the known patterns: port_scan, brute_force, syn_flood.
  5. Respond   : --respond recommend (default: print what to do) | block (add a firewall rule for the offender, auto-removed) | off.
  6. Report    : prints to the console, appends data/live_events.jsonl, and (optional) posts to the DECOY server so it shows in the
                 tamper-evident Black Box log and on GET /api/live.

Examples
  Defended laptop (run as Administrator):
      .\\.venv\\Scripts\\python backend\\live_sensor.py --api http://127.0.0.1:8000 --key decoy-lab-key
      .\\.venv\\Scripts\\python backend\\live_sensor.py --respond block --allow 192.168.1.1
  No admin rights / no second laptop -> rehearse the pipeline with synthetic traffic:
      .\\.venv\\Scripts\\python backend\\live_sensor.py --simulate
Then, from the OTHER laptop, only against the defended laptop's IP (a lab you own):  nmap -sT -p 1-1000 <ip>  (port scan)
or repeated connection attempts to one service port (brute-force pattern).
"""
from __future__ import annotations

import argparse, ipaddress, json, math, os, platform, socket, struct, subprocess, sys, threading, time, urllib.request
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / "data" / "live_events.jsonl"
FEATURES = ["syn", "pkts", "sources", "max_ports_one_src", "max_syn_one_src", "max_syn_one_src_port"]

# rule thresholds per window (defaults assume WINDOW = 2 s); chosen to be far above ordinary browsing
RULES = dict(port_scan_ports=15, brute_force_syn=12, syn_flood_syn=200)


# ------------------------------------------------------------------ packets -> window summary
class Window:
    def __init__(self):
        self.syn = 0; self.pkts = 0
        self.ports = defaultdict(set)      # src -> distinct destination ports touched
        self.syns = defaultdict(int)       # src -> SYN count
        self.syn_port = defaultdict(int)   # (src, dport) -> SYN count

    def add(self, src: str, dport: int, flags: int):
        self.pkts += 1
        if flags & 0x02 and not flags & 0x10:   # SYN without ACK = a new connection attempt
            self.syn += 1; self.syns[src] += 1; self.syn_port[(src, dport)] += 1; self.ports[src].add(dport)

    def features(self) -> np.ndarray:
        mp = max((len(v) for v in self.ports.values()), default=0)
        ms = max(self.syns.values(), default=0)
        msp = max(self.syn_port.values(), default=0)
        return np.array([self.syn, self.pkts, len(self.syns), mp, ms, msp], float)

    def offender(self, label=None):
        """The source most responsible for the detected pattern."""
        if not self.syns: return None
        if label == "port_scan": key = lambda s: (len(self.ports[s]), self.syns[s])
        elif label == "brute_force": key = lambda s: (max(self.syn_port[(s, p)] for p in self.ports[s]), self.syns[s])
        else: key = lambda s: (self.syns[s], len(self.ports[s]))
        return max(self.syns, key=key)


def parse_ipv4_tcp(buf: bytes):
    """-> (src, dst, dport, flags) or None. Only IPv4 + TCP."""
    if len(buf) < 40 or buf[0] >> 4 != 4 or buf[9] != 6: return None
    ihl = (buf[0] & 0x0F) * 4
    if len(buf) < ihl + 14: return None
    src = socket.inet_ntoa(buf[12:16]); dst = socket.inet_ntoa(buf[16:20])
    _sport, dport = struct.unpack("!HH", buf[ihl:ihl + 4])
    return src, dst, dport, buf[ihl + 13]


# ------------------------------------------------------------------ detector
class Detector:
    """Baseline model learned on normal windows + named rules. Pure logic: no sockets, fully testable.

    Learned part: per-feature mean/std of log1p(features) on the normal baseline (std floored so a quiet machine does not make every
    blip look huge). A window is 'unlike normal' when its largest z-score exceeds max(4, 1.5 x the largest z seen in the baseline).
    (An IsolationForest was tried first and rejected: on a quiet machine it scored out-of-range windows as MORE normal - it cannot
    extrapolate beyond the training range - and caught 0% of attacks that stayed below the rules.)
    """

    def __init__(self, seed=0):
        self.mu = self.sd = None; self.thr = None; self.streak = 0

    @staticmethod
    def _x(f): return np.log1p(np.asarray(f, float))

    def learn(self, windows_features):
        X = np.vstack([self._x(f) for f in windows_features])
        self.mu = X.mean(0); self.sd = np.maximum(X.std(0), 0.3)
        self.thr = float(max(4.0, 1.5 * np.abs((X - self.mu) / self.sd).max()))
        return dict(windows=len(X), threshold=round(self.thr, 2))

    def score(self, f):
        """Largest z-score of this window against the baseline (0 = typical)."""
        return float(np.abs((self._x(f) - self.mu) / self.sd).max()) if self.mu is not None else 0.0

    def judge(self, f):
        """-> dict(label, severity, learned_flag, rule) or None when normal."""
        syn, pkts, srcs, mp, ms, msp = f
        rule = None
        if syn >= RULES["syn_flood_syn"]: rule = "syn_flood"
        elif mp >= RULES["port_scan_ports"]: rule = "port_scan"
        elif msp >= RULES["brute_force_syn"]: rule = "brute_force"
        z = self.score(f)
        learned = self.mu is not None and z > self.thr and syn >= 5     # ignore tiny blips on an idle machine
        self.streak = self.streak + 1 if (rule or learned) else 0
        if not (rule or (learned and self.streak >= 2)):
            return None
        sev = min(1.0, 0.45 + (0.35 if rule else 0.0) + 0.2 * min(1.0, max(0.0, (z - (self.thr or 0)) / max(self.thr or 1, 1))))
        return dict(label=rule or "unknown_anomaly", severity=round(sev, 2), learned_flag=bool(learned), rule=rule, score=round(z, 2))


ADVICE = {
    "port_scan": "Someone is probing many ports (reconnaissance). Block the source; close unneeded listening ports.",
    "brute_force": "Repeated connection attempts to one service (password guessing). Block the source; enforce MFA/lockout; restrict the service to known IPs.",
    "syn_flood": "Connection flood (denial of service). Block/rate-limit the source; enable SYN cookies on the server.",
    "unknown_anomaly": "Traffic unlike this machine's normal baseline (possible new attack). Investigate the source; consider isolating the host.",
}


# ------------------------------------------------------------------ response (firewall)
def own_ips():
    ips = {"127.0.0.1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); ips.add(s.getsockname()[0]); s.close()   # no packet is sent
    except Exception: pass
    try: ips |= set(socket.gethostbyname_ex(socket.gethostname())[2])
    except Exception: pass
    return ips


def firewall_cmds(ip: str, system: str):
    ip = str(ipaddress.ip_address(ip))   # validates: raises on anything that is not a plain IP
    name = f"DECOY_BLOCK_{ip}"
    if system == "Windows":
        return (["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=block", f"remoteip={ip}"],
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    return (["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])


class Responder:
    def __init__(self, mode, allow, minutes, system=None, run=subprocess.run):
        self.mode = mode; self.allow = {str(ipaddress.ip_address(a)) for a in allow}; self.minutes = minutes
        self.system = system or platform.system(); self.run = run; self.blocked = {}

    def act(self, ip, label):
        if not ip: return "no offender identified"
        try: ip = str(ipaddress.ip_address(ip))
        except ValueError: return "invalid offender address ignored"
        if ip in self.allow: return f"{ip} is allow-listed: not blocked"
        if self.mode == "off": return "response disabled"
        if self.mode == "recommend": return f"RECOMMEND: block {ip}. {ADVICE.get(label, '')}"
        if ip in self.blocked: return f"{ip} already blocked"
        add, rem = firewall_cmds(ip, self.system)
        r = self.run(add, capture_output=True, text=True, timeout=15)
        if r.returncode != 0: return f"BLOCK FAILED for {ip} (run as Administrator/root): {(r.stderr or r.stdout).strip()[:120]}"
        self.blocked[ip] = time.time()
        t = threading.Timer(self.minutes * 60, self._unblock, args=(ip, rem)); t.daemon = True; t.start()
        return f"BLOCKED {ip} for {self.minutes} min (firewall rule DECOY_BLOCK_{ip})"

    def _unblock(self, ip, rem):
        try: self.run(rem, capture_output=True, text=True, timeout=15)
        finally: self.blocked.pop(ip, None)

    def release_all(self):
        for ip in list(self.blocked):
            self._unblock(ip, firewall_cmds(ip, self.system)[1])


# ------------------------------------------------------------------ sniffer
def open_sniffer(ip: str):
    if platform.system() == "Windows":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((ip, 0)); s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1); s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.settimeout(0.25)
    return s


def capture_window(sock, seconds, mine, include_local=False, stats=None):
    """Read packets for `seconds`. `stats` (a dict) counts what the sniffer sees, so problems can be diagnosed."""
    w = Window(); end = time.time() + seconds
    st = stats if stats is not None else {}
    while time.time() < end:
        try: buf, _ = sock.recvfrom(65535)
        except socket.timeout: continue
        st["raw"] = st.get("raw", 0) + 1                      # any IPv4 packet the OS handed to us
        p = parse_ipv4_tcp(buf)
        if not p: continue
        st["tcp"] = st.get("tcp", 0) + 1
        if p[1] in mine:
            st["tcp_to_me"] = st.get("tcp_to_me", 0) + 1
            if include_local or p[0] not in mine:
                st["remote"] = st.get("remote", 0) + 1
                if p[3] & 0x02 and not p[3] & 0x10: st["remote_syn"] = st.get("remote_syn", 0) + 1
                w.add(p[0], p[2], p[3])
    return w


class Simulator:
    """Synthetic traffic for rehearsal without admin rights: learn on normal, then scan -> brute force -> flood, repeating."""
    PLAN = ["n"] * 6 + ["scan"] * 2 + ["n"] * 4 + ["brute"] * 2 + ["n"] * 4 + ["flood"] * 2 + ["n"] * 3

    def __init__(self, learn_windows, seed=1):
        self.rng = np.random.default_rng(seed); self.learn_windows = learn_windows

    def normal(self):
        w = Window()
        for _ in range(int(self.rng.integers(0, 4))): w.add("192.168.1.20", int(self.rng.choice([443, 80, 8000])), 0x02)
        w.pkts += int(self.rng.integers(5, 60)); return w

    def window(self, i):
        w = self.normal()
        if i < self.learn_windows: return w
        k = self.PLAN[(i - self.learn_windows) % len(self.PLAN)]
        if k == "scan": [w.add("192.168.1.99", p, 0x02) for p in range(1, 61)]
        if k == "brute": [w.add("192.168.1.99", 22, 0x02) for _ in range(30)]
        if k == "flood": [w.add("192.168.1.99", 80, 0x02) for _ in range(400)]
        return w


# ------------------------------------------------------------------ reporting
def post_api(api, key, ev):
    if not api: return
    try:
        req = urllib.request.Request(api.rstrip("/") + "/api/live/event", data=json.dumps(ev).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-Sensor-Key": key or ""})
        urllib.request.urlopen(req, timeout=3).read()
    except Exception as e:
        print(f"  (could not reach DECOY server: {type(e).__name__})", flush=True)


def emit(ev, api, key):
    ev = dict(ev, t=time.strftime("%Y-%m-%d %H:%M:%S"))
    LOG.parent.mkdir(exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f: f.write(json.dumps(ev) + "\n")
    post_api(api, key, ev)


def main(argv=None):
    ap = argparse.ArgumentParser(description="DECOY live sensor (defensive; use only on machines you own).")
    ap.add_argument("--api"); ap.add_argument("--key", default=os.environ.get("DECOY_SENSOR_KEY", ""))
    ap.add_argument("--ip", help="this machine's IP on the lab network (auto-detected)")
    ap.add_argument("--window", type=float, default=2.0); ap.add_argument("--learn", type=int, default=90, help="seconds of normal traffic to learn")
    ap.add_argument("--respond", choices=["off", "recommend", "block"], default="recommend")
    ap.add_argument("--allow", default="", help="comma-separated IPs that are never blocked (gateway, teammates)")
    ap.add_argument("--block-minutes", type=float, default=5.0); ap.add_argument("--simulate", action="store_true")
    ap.add_argument("--include-local", action="store_true", help="also count traffic from this machine itself (testing on one computer)")
    a = ap.parse_args(argv)
    mine = own_ips() | ({a.ip} if a.ip else set()); host = socket.gethostname()[:40]
    resp = Responder(a.respond, [x for x in a.allow.split(",") if x] + sorted(mine), a.block_minutes)   # never block ourselves
    print(f"DECOY Live Sensor on {host} {sorted(mine)} | respond={a.respond} | learning {a.learn}s of NORMAL traffic - do not attack yet", flush=True)
    if a.simulate:
        sim = Simulator(int(a.learn / a.window)); sock = None; stats = None
        capture = lambda i: (time.sleep(0.05), sim.window(i))[1]
    else:
        others = sorted(mine - {"127.0.0.1"})
        ip = a.ip or (others[0] if others else "127.0.0.1")
        try: sock = open_sniffer(ip)
        except PermissionError: sys.exit("Need Administrator (Windows) / root (Linux) to read raw packets. Re-run elevated, or use --simulate.")
        stats = {}
        capture = lambda i: capture_window(sock, a.window, mine, a.include_local, stats)
    det = Detector(); base = []; i = 0; learned = False; cooldown = {}; last_hb = time.time()
    try:
        while True:
            w = capture(i); f = w.features(); i += 1
            if stats is not None and time.time() - last_hb >= 10:
                last_hb = time.time()
                print(f"  [alive] last 10s: {stats.get('raw', 0)} packets seen | {stats.get('tcp', 0)} TCP | {stats.get('tcp_to_me', 0)} TCP addressed to {ip} | "
                      f"{stats.get('remote', 0)} from other machines ({stats.get('remote_syn', 0)} new connections)", flush=True)
                if stats.get("raw", 0) == 0: print("        !! NO packets at all: capture is not working. Run as Administrator and make sure --ip is your Wi-Fi/Ethernet address.", flush=True)
                elif stats.get("tcp_to_me", 0) == 0: print("        !! Packets are seen but none are addressed to this IP: wrong --ip, or the network isolates devices from each other.", flush=True)
                stats.clear()
            if not learned:
                base.append(f)
                if len(base) * a.window >= a.learn:
                    info = det.learn(base); learned = True
                    print(f"  baseline learned from {info['windows']} windows (threshold {info['threshold']}). Watching.", flush=True)
                    emit(dict(kind="learning_done", host=host, note=f"baseline from {info['windows']} windows"), a.api, a.key)
                continue
            v = det.judge(f)
            if v:
                off = w.offender(v["label"]); now = time.time()
                if cooldown.get((off, v["label"]), 0) > now: continue
                cooldown[(off, v["label"])] = now + 20
                action = resp.act(off, v["label"])
                ev = dict(kind="alert", host=host, label=v["label"], severity=v["severity"], offender=off, syn=int(f[0]), ports=int(f[3]), targets=sorted(w.ports.get(off, []))[:12], score=v["score"],
                          action=action[:300], note=ADVICE[v["label"]])
                print(f"  ALERT {v['label']:16s} sev={v['severity']:.2f} from {off}  ({int(f[3])} ports, {int(f[0])} SYNs)\n        -> {action}", flush=True)
                emit(ev, a.api, a.key)
    except KeyboardInterrupt:
        print("stopping; removing any firewall rules created by this run", flush=True); resp.release_all()


if __name__ == "__main__":
    main()
