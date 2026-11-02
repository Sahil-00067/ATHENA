"""FastAPI app: secure REST + WebSocket + static frontend.

Every request passes: rate limit -> authentication (signed token) -> role check (RBAC) -> pydantic validation -> audit log.
"""
from __future__ import annotations

import asyncio
import threading
import time
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Path as PathParam, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, field_validator

from .city import DATA
from .lab_api import make_router
from .lab_service import LabService
from .runtime import Runtime
from .security import Auth, AirGap, RateLimiter
import hmac, secrets
from collections import deque

ROOT = Path(__file__).resolve().parent.parent.parent
DIST = ROOT / "frontend" / "dist"
ID = r"^[A-Za-z0-9_:\-\.]{1,64}$"

state: dict = {}

DECOY_DEMO = os.environ.get("DECOY_DEMO", "1") == "1"
SENSOR_KEY: str = os.environ.get("DECOY_SENSOR_KEY") or ("decoy-lab-key" if DECOY_DEMO else secrets.token_urlsafe(16))
LIVE: deque = deque(maxlen=300)


@asynccontextmanager
async def lifespan(app):
    rt = Runtime(sync=False, persist=True)
    state.update(rt=rt, auth=Auth(), rl=RateLimiter(), ag=AirGap(), approvals={})
    rt.start()
    state["lab"] = LabService(rt)
    print("[boot] preparing the risk model ...", flush=True)
    try:
        state["lab"].train()      # trained (or loaded from the cache) BEFORE the server says it is ready, so no page ever has to wait for it
    except Exception as e:
        print(f"[boot] risk model failed: {e}", flush=True)
    print("\n  ATHENA is ready ->  http://127.0.0.1:8000   (risk numbers appear a few seconds after you sign in)\n", flush=True)
    yield
    rt.stop()


app = FastAPI(title="ATHENA", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)  # no public schema surface
from starlette.middleware.gzip import GZipMiddleware  # noqa: E402
app.add_middleware(GZipMiddleware, minimum_size=1000)   # the map data is large JSON; compressing it makes the first load several times faster
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000"],
                   allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def guard(request: Request, call_next):
    ip = request.client.host if request.client else "?"
    if request.url.path.startswith("/api") and not state["rl"].allow(f"{ip}"):
        return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; "
                                               "img-src 'self' data: blob:; connect-src 'self' ws: wss: https://*.tile.openstreetmap.org; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api") else resp.headers.get("Cache-Control", "no-cache")
    if request.url.scheme == "https":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def user_for(perm):
    def dep(request: Request):
        h = request.headers.get("authorization", "")
        tok = h[7:] if h.lower().startswith("bearer ") else ""
        d = state["auth"].verify(tok)
        if not d:
            raise HTTPException(401, "authentication required")
        if not state["auth"].allowed(d["role"], perm):
            state["rt"].bb.append("denied", dict(user=d["sub"], perm=perm, path=request.url.path), actor=d["sub"])
            raise HTTPException(403, f"role '{d['role']}' may not {perm}")
        return d
    return dep


# ---------------------------------------------------------------- auth
class Login(BaseModel):
    username: str = Field(min_length=1, max_length=32, pattern=r"^[a-z0-9_]+$")
    password: str = Field(min_length=1, max_length=128)
    totp: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")

    @field_validator("username", "totp", mode="before")
    @classmethod
    def _tidy(cls, v, info):   # forgive harmless typing slips (capitals, a space inside the code) instead of failing with a 422
        if not isinstance(v, str):
            return v
        v = v.strip()
        return v.lower() if info.field_name == "username" else v.replace(" ", "")


@app.exception_handler(RequestValidationError)
async def bad_request(request: Request, exc: RequestValidationError):
    """Validation failures stay strict but answer in one plain sentence instead of a nested error list."""
    first = exc.errors()[0] if exc.errors() else {}
    where = ".".join(str(x) for x in first.get("loc", ()) if x not in ("body", "query", "path"))
    return JSONResponse({"detail": f"Please check '{where}': {first.get('msg', 'invalid value')}" if where else "Invalid request"}, status_code=422)


@app.post("/api/auth/login")
def login(b: Login, request: Request):
    tok, err = state["auth"].login(b.username, b.password, b.totp, request.client.host if request.client else "?")
    rt = state["rt"]
    if err:
        rt.bb.append("login_failed", dict(user=b.username), actor=b.username)
        raise HTTPException(401, err)
    d = state["auth"].verify(tok)
    rt.bb.append("login", dict(user=b.username, role=d["role"], mfa=True), actor=b.username)
    return dict(token=tok, user=d["sub"], role=d["role"])


@app.get("/api/auth/hint")
def hint():
    h = state["auth"].hint()
    if h is None:
        raise HTTPException(404, "not available")
    return dict(note="DEMO ONLY (DECOY_DEMO=1). Disable in production.", accounts=h)


@app.get("/api/me")
def me(u=Depends(user_for("read"))):
    return u


# ---------------------------------------------------------------- reads
@app.get("/api/static")
def static(u=Depends(user_for("read"))):
    return state["rt"].static()


@app.get("/api/risk")
def risk(u=Depends(user_for("risk"))):
    return state["rt"].analytics


@app.get("/api/whatif")
def whatif(fix: str = Query(max_length=400, pattern=r"^[A-Za-z0-9_:\-\.,]+$"), u=Depends(user_for("whatif"))):
    return state["rt"].whatif(fix.split(","))


@app.get("/api/compliance")
def compliance(u=Depends(user_for("compliance"))):
    rt = state["rt"]
    c = rt.compliance()
    c["airgap"] = dict(version=state["ag"].version, accepted=state["ag"].accepted, rejected=state["ag"].rejected)
    return c


@app.get("/api/incident/{iid}/report")
def report(iid: str = PathParam(pattern=ID), u=Depends(user_for("report"))):
    r = state["rt"].report(iid)
    if not r:
        raise HTTPException(404, "no such incident")
    return r


@app.get("/api/timeline")
def timeline(actions: str = Query(max_length=200, pattern=r"^[A-Z0-9_,]+$"), start: float = Query(6.0, ge=0, le=23), u=Depends(user_for("whatif"))):
    rt = state["rt"]
    ids = [a for a in actions.split(",") if a]
    if not ids or any(a not in rt.ward["actions"] for a in ids):
        raise HTTPException(422, "unknown action")
    ev = rt.phys.attack_events(sorted(ids), start)
    r = rt.phys.loss(ev, want_series=True)
    base = rt.phys.loss([], want_series=True)
    return dict(actions=ids, start=start, result={k: v for k, v in r.items() if k != "series"}, series=r["series"], baseline=base["series"],
                hospital_min_pressure=15.0, labels={a: rt.ward["actions"][a]["label"] for a in ids})


_geo = {}


@app.get("/api/geo")
def geo(u=Depends(user_for("read"))):
    if not _geo:
        for k, fn in (("buildings", "osm_buildings.json"), ("features", "osm_features.json"), ("roads", "osm_roads.json")):
            p = DATA / fn
            _geo[k] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    return _geo


@app.get("/api/experiments")
def experiments(u=Depends(user_for("read"))):
    p = DATA / "experiments.json"
    if not p.exists():
        raise HTTPException(404, "experiments not run yet")
    return json.loads(p.read_text(encoding="utf-8"))


@app.get("/api/blackbox")
def blackbox(u=Depends(user_for("read"))):
    bb = state["rt"].bb
    return dict(verify=bb.verify(), tail=bb.tail(30), count=len(bb.entries))


@app.get("/api/blackbox/tamper")
def tamper(u=Depends(user_for("tamper"))):
    state["rt"].bb.append("tamper_demo", dict(by=u["sub"]), actor=u["sub"])
    return state["rt"].bb.tamper_demo()


@app.get("/api/export/incidents")
def export_incidents(fmt: Literal["cef", "json"] = "cef", u=Depends(user_for("report"))):
    """Incidents for the SOC: CEF lines for the SIEM, or JSON tickets for the ticket queue."""
    from . import soc
    rt = state["rt"]
    with rt.lock:
        incs, assets = list(rt.incidents), rt.ward["assets"]
        rows = [soc.to_cef(i, assets) for i in incs] if fmt == "cef" else [soc.to_ticket(i, assets) for i in incs]
    rt.bb.append("soc_export", dict(fmt=fmt, n=len(rows)), actor=u["sub"])
    return dict(format=fmt, count=len(rows), items=rows)


@app.get("/api/security")
def security(u=Depends(user_for("security"))):
    rt, rl = state["rt"], state["rl"]
    from . import selfcheck
    return dict(
        controls=selfcheck.run(rt, app, state["auth"], rl),
        chain=rt.bb.verify(), airgap=dict(version=state["ag"].version, accepted=state["ag"].accepted, rejected=state["ag"].rejected), user=u,
        tests=json.loads((DATA / "security_tests.json").read_text()) if (DATA / "security_tests.json").exists() else None)


# ---------------------------------------------------------------- writes
class Attack(BaseModel):
    mode: Literal["standard", "zero_day", "spoof", "wear", "insider", "ddos", "swarm", "blitz", "group", "spoof_coherent"] = "standard"
    entry: str | None = Field(default=None, pattern=ID)
    goal: str | None = Field(default=None, pattern=ID)
    stealth: float | None = Field(default=None, ge=1.0, le=12.0)


@app.post("/api/attack")
def attack(b: Attack, u=Depends(user_for("attack"))):
    try:
        c = state["rt"].launch_attack(b.mode, b.entry, b.goal, b.stealth, actor=u["sub"])
    except ValueError as e:
        raise HTTPException(422, str(e))
    state["rt"].bb.append("api_attack", b.model_dump(), actor=u["sub"])
    return c


class Toggle(BaseModel):
    on: bool


@app.post("/api/autopilot")
def autopilot(b: Toggle, u=Depends(user_for("settings"))):
    state["rt"].autopilot = b.on
    state["rt"].note("setting", "info", f"{u['sub']} set autopilot adversary {'ON' if b.on else 'OFF'}.")
    return dict(autopilot=b.on)


class Autonomy(BaseModel):
    mode: Literal["observe", "suggest", "auto_low", "auto_all"]


@app.post("/api/autonomy")
def autonomy(b: Autonomy, u=Depends(user_for("settings"))):
    if b.mode == "auto_all" and u["role"] != "admin":
        raise HTTPException(403, "only an admin may enable full autonomy")
    state["rt"].autonomy = b.mode
    state["rt"].note("setting", "info", f"{u['sub']} set autonomy to '{b.mode}'.")
    return dict(autonomy=b.mode)


@app.post("/api/freeze")
def freeze(u=Depends(user_for("freeze"))):
    return state["rt"].emergency_stop(u["sub"])


@app.post("/api/pause")
def pause(b: Toggle, u=Depends(user_for("settings"))):
    state["rt"].paused = b.on
    state["rt"].note("setting", "info", f"{u['sub']} {'paused' if b.on else 'resumed'} the simulation clock.")
    return dict(paused=b.on)


@app.post("/api/resume")
def resume(u=Depends(user_for("freeze"))):
    return state["rt"].resume(u["sub"])


class DecoyReq(BaseModel):
    node: str = Field(pattern=ID)


@app.post("/api/decoy")
def decoy(b: DecoyReq, u=Depends(user_for("fix"))):
    try:
        return state["rt"].deploy_decoy(b.node, u["sub"])
    except ValueError as e:
        raise HTTPException(422, str(e))


class Speed(BaseModel):
    x: float = Field(ge=0.25, le=16)


@app.post("/api/speed")
def speed(b: Speed, u=Depends(user_for("settings"))):
    state["rt"].speed = b.x
    return dict(speed=b.x)


@app.post("/api/reset")
def reset(u=Depends(user_for("reset"))):
    state["rt"].reset()
    state["approvals"].clear()
    state["rt"].bb.append("reset", dict(by=u["sub"]), actor=u["sub"])
    return dict(ok=True)


def needs_two(steps) -> bool:
    """High-impact = switches off service or costs a lot of operator effort: a second, different person must approve."""
    return any(s["service"] > 0 or s["ops"] > 800 for s in steps)


@app.post("/api/proposal/{pid}/approve")
def approve(pid: str = PathParam(pattern=ID), u=Depends(user_for("approve"))):
    rt = state["rt"]
    prop = next((p for p in rt.proposals if p["id"] == pid), None)
    if not prop or prop["status"] != "pending":
        raise HTTPException(404, "no pending proposal")
    high = needs_two(prop["steps"])
    ap = state["approvals"].setdefault(pid, set())
    ap.add(u["sub"])
    if high and len(ap) < 2:
        rt.note("approval", "warn", f"{u['sub']} approved {pid}; a second, different person must approve (high-impact action, two-person rule).", proposal=pid)
        return dict(status="awaiting_second", approvals=sorted(ap))
    ok = rt.approve(pid, actor=" + ".join(sorted(ap)))
    return dict(status="applied" if ok else "failed", approvals=sorted(ap))


@app.post("/api/proposal/{pid}/reject")
def reject(pid: str = PathParam(pattern=ID), u=Depends(user_for("approve"))):
    return dict(ok=state["rt"].reject(pid, u["sub"]))


class Answer(BaseModel):
    uid: str = Field(pattern=ID)
    yes: bool


@app.post("/api/answer")
def answer(b: Answer, u=Depends(user_for("answer"))):
    ok = state["rt"].answer(b.uid, b.yes)
    if not ok:
        raise HTTPException(404, "unknown question")
    return dict(ok=True)


class Fix(BaseModel):
    id: str = Field(pattern=r"^[a-z]{2,4}:[A-Za-z0-9_\.\-]{1,48}$")


@app.post("/api/fix")
def fix(b: Fix, u=Depends(user_for("fix"))):
    try:
        state["rt"].apply_fix(b.id, u["sub"])
    except ValueError as e:
        raise HTTPException(409, str(e))
    return dict(ok=True)


@app.post("/api/incident/{iid}/reported")
def reported(iid: str = PathParam(pattern=ID), u=Depends(user_for("report"))):
    return dict(ok=state["rt"].mark_reported(iid))


class Skew(BaseModel):
    source: str = Field(pattern=ID)
    seconds: float = Field(ge=-3600, le=3600)


@app.post("/api/timeguard")
def timeguard(b: Skew, u=Depends(user_for("settings"))):
    state["rt"].timeguard_skew(b.source, b.seconds)
    return state["rt"].tg.status()


class ZeroDayReq(BaseModel):
    product: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9 ./()\-_+]{1,80}$")
    exploit: Literal["rce", "auth_bypass", "protocol_abuse"] | None = None
    mode: Literal["standard", "spoof", "wear", "insider"] = "standard"
    entry: str | None = Field(default=None, pattern=ID)
    goal: str | None = Field(default=None, pattern=ID)
    stealth: float | None = Field(default=None, ge=1.0, le=12.0)


@app.post("/api/zeroday")
def zeroday(b: ZeroDayReq, u=Depends(user_for("attack"))):
    try:
        c = state["rt"].introduce_zero_day(b.product, b.exploit, b.mode, b.entry, b.goal, b.stealth, actor=u["sub"])
    except ValueError as e:
        raise HTTPException(422, str(e))
    state["rt"].bb.append("api_zero_day", b.model_dump(), actor=u["sub"])
    return c


@app.get("/api/zeroday")
def zeroday_info(u=Depends(user_for("whatif"))):
    from .zeroday import EXPLOITS, products, split_products
    rt = state["rt"]
    tr = DATA / "ppo_train.json"
    train, test = split_products(rt.ward)
    return dict(products=sorted(products(rt.ward)), train_products=train, held_out_products=test, exploits=EXPLOITS,
                curve=json.loads(tr.read_text(encoding="utf-8")) if tr.exists() else [], evaluation=rt.ppo_eval, ppo_loaded=rt.ppo is not None,
                meta={k: v for k, v in (rt.ppo_meta or {}).items() if k in ("iters", "steps", "seed", "obs_dim", "n_act")})


class Responder(BaseModel):
    mode: Literal["auto", "ppo", "search"]


@app.post("/api/responder")
def responder(b: Responder, u=Depends(user_for("settings"))):
    rt = state["rt"]
    if b.mode != "search" and rt.ppo is None:
        raise HTTPException(422, "no trained PPO policy available")
    rt.responder = b.mode
    rt.note("setting", "info", f"{u['sub']} set the responder to '{b.mode}'.")
    return dict(responder=b.mode)


@app.post("/api/chaos/analytics")
def chaos(u=Depends(user_for("chaos"))):
    rt = state["rt"]
    rt.health["restarts"] += 1
    rt.health["last_restart"] = f"analytics worker killed by {u['sub']} and restarted by the supervisor"
    rt.bb.append("module_restart", dict(module="analytics", by=u["sub"], note="chaos test"), actor=u["sub"])
    rt.note("health", "warn", "Chaos test: analytics worker killed; supervisor restarted it. The plant never depended on ATHENA (it sits beside the control path).")
    rt.dirty = True
    return dict(ok=True)


@app.get("/api/airgap/export")
def ag_export(u=Depends(user_for("risk"))):
    rt = state["rt"]
    payload = dict(city=rt.ward["meta"]["city"], assets=[dict(id=a["id"], firmware=a["firmware"], cve=a["cve"]) for a in rt.ward["assets"].values()],
                   unknown_questions=[x["id"] for x in rt.planner.unknowns()])
    return state["ag"].export(payload)


class AGDoc(BaseModel):
    payload: dict
    sha256: str = Field(max_length=64)
    signature: str = Field(max_length=200)
    public_key: str = Field(max_length=100)


@app.post("/api/airgap/import")
def ag_import(b: AGDoc, u=Depends(user_for("airgap_import"))):
    ok, msg = state["ag"].verify_import(b.model_dump())
    state["rt"].note("airgap", "ok" if ok else "warn", f"Air-gap import by {u['sub']}: {msg}")
    if ok:
        for ans in b.payload.get("answers", [])[:20]:
            if isinstance(ans, dict) and isinstance(ans.get("uid"), str):
                state["rt"].answer(ans["uid"], bool(ans.get("yes")))
    return dict(ok=ok, message=msg)


# ---------------------------------------------------------------- websocket
WS_MAX, WS_PER_USER = 40, 4
_ws_open: dict = {}
_frames: dict = {}
_frame_lock = threading.Lock()


@app.websocket("/ws")
async def ws(sock: WebSocket):
    """The session token is sent as the FIRST message (so it never appears in a URL, a proxy log or browser history). At most WS_MAX sockets overall and WS_PER_USER per person;
    every client of a role shares one snapshot built at most four times a second, so more viewers cannot mean more work under the simulation lock."""
    await sock.accept()
    try:
        first = json.loads(await asyncio.wait_for(sock.receive_text(), timeout=5))
        token = first.get("token", "") if isinstance(first, dict) else ""
    except Exception:
        await sock.close(code=4401)
        return
    d = state["auth"].verify(token if isinstance(token, str) and len(token) <= 600 else "")
    if not d:
        await sock.close(code=4401)
        return
    if sum(_ws_open.values()) >= WS_MAX or _ws_open.get(d["sub"], 0) >= WS_PER_USER:
        await sock.close(code=4429)
        return
    _ws_open[d["sub"]] = _ws_open.get(d["sub"], 0) + 1
    rt = state["rt"]
    role = "analyst" if state["auth"].allowed(d["role"], "adversary_view") else "executive"
    loop = asyncio.get_running_loop()
    try:
        while True:
            try:   # built in a worker thread: waiting for the simulation lock must never freeze the web server
                text = await loop.run_in_executor(None, _frame_shared, rt, role)
                await sock.send_text(text)
            except (WebSocketDisconnect, RuntimeError):
                return
            except Exception as e:   # one bad frame must not end the stream
                rt.health["last_restart"] = f"stream: {type(e).__name__}: {e}"
            if state["auth"].verify(token) is None:      # the session expired: end the stream, the page signs in again
                await sock.close(code=4401)
                return
            await asyncio.sleep(0.25 / max(rt.speed, 0.25) if rt.speed < 4 else 0.12)
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        return
    finally:
        _ws_open[d["sub"]] = max(0, _ws_open.get(d["sub"], 1) - 1)


def _frame_shared(rt, role):
    now = time.time()
    with _frame_lock:
        c = _frames.get(role)
        if c and now - c[0] < 0.2:
            return c[1]
        text = _frame(rt, role)
        _frames[role] = (now, text)
        return text


def _frame(rt, role):
    return json.dumps(rt.snapshot(role), separators=(",", ":"), default=_plain)


def _plain(o):
    if isinstance(o, (set, frozenset, tuple)):
        return sorted(o) if isinstance(o, (set, frozenset)) else list(o)
    try:
        return float(o)
    except (TypeError, ValueError):
        return str(o)



# ---------------------------------------------------------------- live sensor
from typing import List as _List
class LiveEvent(BaseModel):
    kind: Literal["alert", "learning_done", "heartbeat"]
    host: str = Field(max_length=128)
    label: str | None = Field(default=None, max_length=64)
    severity: float | None = Field(default=None, ge=0.0, le=1.0)
    offender: str | None = Field(default=None, max_length=64)
    syn: int | None = None
    ports: int | None = None
    targets: _List[int] | None = None
    score: float | None = None
    action: str | None = Field(default=None, max_length=512)
    note: str | None = Field(default=None, max_length=512)
    t: str | None = Field(default=None, max_length=32)


@app.post("/api/live/event", status_code=204)
async def live_event(body: LiveEvent, request: Request):
    key = request.headers.get("X-Sensor-Key", "")
    if not hmac.compare_digest(key.encode(), SENSOR_KEY.encode()):
        raise HTTPException(403, "bad key")
    ev = body.model_dump()
    ev["received"] = ev.get("t") or ""
    LIVE.append(ev)
    try:
        rt = state.get("rt")
        if rt and body.kind == "alert":
            rt.bb.append("live_sensor_alert", ev, actor="sensor")
    except Exception:
        pass


@app.get("/api/live")
def live_status(u=Depends(user_for("read"))):
    events = list(LIVE)
    alerts = [e for e in events if e.get("kind") == "alert"]
    hosts = list({e["host"] for e in events if e.get("host")})
    return dict(
        events=events[-50:],
        alerts=len(alerts),
        last_alert=alerts[-1] if alerts else None,
        hosts=hosts,
    )


@app.get("/api/health")
def health():
    rt = state["rt"]
    return dict(ok=True, minute=rt.live.minute, restarts=rt.health["restarts"])


# ---------------------------------------------------------------- what-if lab (must be registered before the catch-all frontend route)
app.include_router(make_router(state, user_for), prefix="/api/v2")


# ---------------------------------------------------------------- frontend
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/")
    def index():
        return FileResponse(DIST / "index.html")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        f = DIST / full_path
        if f.is_file() and DIST.resolve() in f.resolve().parents:
            return FileResponse(f)
        return FileResponse(DIST / "index.html")
