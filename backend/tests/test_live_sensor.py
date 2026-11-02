"""Live sensor: detector logic, offender attribution, firewall command safety, and the authenticated ingest endpoint."""
import sys, pathlib
import numpy as np
import pytest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import live_sensor as ls


RNG = np.random.default_rng(5)


def win(spec):
    w = ls.Window()
    for src, port, n in spec:
        for _ in range(n): w.add(src, port, 0x02)
    w.pkts += int(RNG.integers(5, 60))      # ordinary background packets, as in real windows
    return w


def trained():
    rng = np.random.default_rng(0); d = ls.Detector()
    base = []
    for _ in range(45):
        base.append(win([("10.0.0.5", int(rng.choice([80, 443])), int(rng.integers(0, 4)))]).features())
    d.learn(base); return d


def test_normal_is_quiet():
    d = trained()
    assert all(d.judge(win([("10.0.0.5", 443, 2)]).features()) is None for _ in range(20))


def test_port_scan_brute_force_flood_named_and_attributed():
    d = trained()
    w = win([("10.0.0.5", 443, 2)] + [("10.0.0.9", p, 1) for p in range(1, 61)])
    v = d.judge(w.features()); assert v["label"] == "port_scan" and w.offender(v["label"]) == "10.0.0.9"
    w = win([("10.0.0.5", 80, 3), ("10.0.0.9", 22, 30)])
    v = d.judge(w.features()); assert v["label"] == "brute_force" and w.offender(v["label"]) == "10.0.0.9"
    w = win([("10.0.0.5", 80, 3), ("10.0.0.9", 80, 400)])
    v = d.judge(w.features()); assert v["label"] == "syn_flood" and w.offender(v["label"]) == "10.0.0.9"


def test_unseen_pattern_caught_by_learned_detector_only_when_sustained():
    d = trained()
    f = win([("10.0.0.7", 8080, 9), ("10.0.0.8", 8081, 9), ("10.0.0.6", 8082, 9)]).features()   # below every rule
    first = d.judge(f); second = d.judge(f)
    assert first is None and second is not None and second["label"] == "unknown_anomaly" and second["rule"] is None
    d2 = trained(); tiny = win([("10.0.0.7", 8080, 6)]).features()
    assert d2.judge(tiny) is None and d2.judge(tiny) is None      # small blips stay quiet


def test_parse_packet():
    import struct, socket
    ip = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]) + socket.inet_aton("1.2.3.4") + socket.inet_aton("5.6.7.8")
    tcp = struct.pack("!HHIIBBHHH", 5555, 22, 0, 0, 5 << 4, 0x02, 0, 0, 0)
    assert ls.parse_ipv4_tcp(ip + tcp) == ("1.2.3.4", "5.6.7.8", 22, 0x02)
    assert ls.parse_ipv4_tcp(b"\x45" + b"\x00" * 10) is None


def test_firewall_commands_reject_injection_and_respect_allowlist():
    with pytest.raises(ValueError): ls.firewall_cmds("1.2.3.4; rm -rf /", "Linux")
    calls = []
    class R: returncode = 0; stderr = stdout = ""
    r = ls.Responder("block", ["10.0.0.1"], 5, system="Linux", run=lambda *a, **k: (calls.append(a[0]), R())[1])
    assert "allow-listed" in r.act("10.0.0.1", "port_scan") and not calls
    assert r.act("10.0.0.9", "port_scan").startswith("BLOCKED") and calls[0][:4] == ["iptables", "-I", "INPUT", "-s"]
    assert "already" in r.act("10.0.0.9", "port_scan")
    r.release_all(); assert calls[-1][0:2] == ["iptables", "-D"]
    assert ls.Responder("recommend", [], 5).act("10.0.0.9", "port_scan").startswith("RECOMMEND")


def test_ingest_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    from decoy import api
    from decoy.security import Auth, RateLimiter
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def test_lifespan(app):
        if "auth" not in api.state:
            api.state.update(auth=Auth(), rl=RateLimiter(), approvals={})
        yield

    monkeypatch.setattr(api.app.router, "lifespan_context", test_lifespan)
    with TestClient(api.app) as c:
        ev = dict(kind="alert", host="laptop-b", label="port_scan", severity=0.8, offender="192.168.1.99", syn=61, ports=60, action="RECOMMEND", note="x")
        assert c.post("/api/live/event", json=ev).status_code == 401
        assert c.post("/api/live/event", json=ev, headers={"X-Sensor-Key": "wrong"}).status_code == 401
        assert c.post("/api/live/event", json=dict(ev, label="rm -rf"), headers={"X-Sensor-Key": api.SENSOR_KEY}).status_code == 422
        class DummyBB:
            def __init__(self): self.logs = []
            def append(self, kind, data, actor): self.logs.append((kind, data, actor))
        class DummyRT:
            bb = DummyBB()
        api.state["rt"] = DummyRT()

        assert c.post("/api/live/event", json=ev, headers={"X-Sensor-Key": api.SENSOR_KEY}).json() == {"ok": True}
        assert len(api.state["rt"].bb.logs) >= 1
        assert api.state["rt"].bb.logs[-1][0] == "live_alert"
        assert api.state["rt"].bb.logs[-1][2] == "sensor:laptop-b"
        assert c.get("/api/live").status_code == 401          # reading needs a normal login
        tok = api.state["auth"].token("analyst", "analyst")
        r = c.get("/api/live", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        data = r.json()
        assert data["alerts"] >= 1
        assert data["last_alert"]["label"] == "port_scan"
        assert "laptop-b" in data["hosts"]
        assert api.LIVE[0]["label"] == "port_scan"
