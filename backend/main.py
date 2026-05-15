import asyncio
import json
import os
import re
from datetime import datetime, timedelta
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from database import engine, get_db, Base, SessionLocal
import auth
from cve_lookup import enrich_nmap_results_with_cves
from scanners.nmap_scanner import run_nmap
from pdf_generator import generate_pdf_report

Base.metadata.create_all(bind=engine)


def _migrate_db():
    from sqlalchemy import text
    with engine.connect() as conn:
        migrations = [
            ("scans", "targets", "TEXT"),
            ("scans", "ports", "TEXT"),
            ("scans", "scheduled_scan_id", "INTEGER"),
            ("scheduled_scans", "run_time", "TEXT DEFAULT '00:00'"),
        ]
        for table, col, defn in migrations:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {defn}"))
                conn.commit()
            except Exception:
                pass


_migrate_db()

# ── Scheduler ─────────────────────────────────────────────────────────────────

scheduler = AsyncIOScheduler()

VALID_INTERVALS = {"1h", "6h", "12h", "daily", "3d", "weekly", "monthly"}

SCHEDULE_LABELS = {
    "1h":      "Every hour",
    "6h":      "Every 6 hours",
    "12h":     "Every 12 hours",
    "daily":   "Daily",
    "3d":      "Every 3 days",
    "weekly":  "Weekly",
    "monthly": "Monthly",
}


def _make_trigger(interval: str, run_time: str) -> CronTrigger:
    try:
        hh, mm = (int(x) for x in run_time.split(":"))
    except Exception:
        hh, mm = 0, 0

    if interval == "1h":
        return CronTrigger(minute=mm)
    elif interval == "6h":
        return CronTrigger(hour="0,6,12,18", minute=mm)
    elif interval == "12h":
        return CronTrigger(hour="0,12", minute=mm)
    elif interval == "daily":
        return CronTrigger(hour=hh, minute=mm)
    elif interval == "3d":
        return CronTrigger(day="*/3", hour=hh, minute=mm)
    elif interval == "weekly":
        return CronTrigger(day_of_week="mon", hour=hh, minute=mm)
    elif interval == "monthly":
        return CronTrigger(day=1, hour=hh, minute=mm)
    return CronTrigger(hour=hh, minute=mm)

app = FastAPI(title="WebHaunter", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


@app.on_event("startup")
async def startup():
    scheduler.start()
    db = SessionLocal()
    try:
        schedules = db.query(models.ScheduledScan).filter(models.ScheduledScan.enabled == True).all()
        for sched in schedules:
            _add_schedule_job(sched)
    finally:
        db.close()


@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown(wait=False)


def _add_schedule_job(sched: models.ScheduledScan):
    trigger = _make_trigger(sched.interval, sched.run_time or "00:00")
    scheduler.add_job(
        _run_scheduled_scan,
        trigger,
        id=f"schedule_{sched.id}",
        args=[sched.id],
        replace_existing=True,
        misfire_grace_time=3600,
    )


def _remove_schedule_job(sched_id: int):
    try:
        scheduler.remove_job(f"schedule_{sched_id}")
    except Exception:
        pass


async def _run_scheduled_scan(scheduled_scan_id: int):
    db = SessionLocal()
    try:
        sched = db.query(models.ScheduledScan).filter(
            models.ScheduledScan.id == scheduled_scan_id,
            models.ScheduledScan.enabled == True,
        ).first()
        if not sched:
            return

        targets_data = sched.get_targets()
        hosts = [t["host"] for t in targets_data]
        modules = sched.get_modules()
        ports = sched.ports or "top1000"

        initial_progress = {m: {"status": "pending", "percent": 0, "message": "Queued"} for m in modules}
        display_target = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"

        scan = models.Scan(
            user_id=sched.user_id,
            target=display_target,
            targets=sched.targets,
            ports=ports,
            scan_name=sched.scan_name,
            modules=sched.modules,
            status="pending",
            progress=json.dumps(initial_progress),
            results=json.dumps({}),
            scheduled_scan_id=sched.id,
        )
        db.add(scan)

        now = datetime.utcnow()
        sched.last_run_at = now
        trigger = _make_trigger(sched.interval, sched.run_time or "00:00")
        from datetime import timezone
        sched.next_run_at = trigger.get_next_fire_time(None, now.replace(tzinfo=timezone.utc)).replace(tzinfo=None)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    await _run_scan(scan_id, hosts, modules, ports)


# ── Auth ─────────────────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str


@app.post("/api/auth/register", response_model=TokenResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(models.User).filter(models.User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = models.User(
        username=req.username,
        email=req.email,
        hashed_password=auth.hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = auth.create_access_token({"sub": user.username})
    return TokenResponse(access_token=token, token_type="bearer", username=user.username)


@app.post("/api/auth/login", response_model=TokenResponse)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form.username).first()
    if not user or not auth.verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = auth.create_access_token({"sub": user.username})
    return TokenResponse(access_token=token, token_type="bearer", username=user.username)


@app.get("/api/auth/me")
def me(current_user: models.User = Depends(auth.get_current_user)):
    return {"id": current_user.id, "username": current_user.username, "email": current_user.email}


# ── Scans ─────────────────────────────────────────────────────────────────────

AVAILABLE_MODULES = {"nmap"}

_VALID_PORTS_RE = re.compile(r'^[0-9,\-UTut: ]+$')
VALID_PORT_PRESETS = {"top100", "top1000", "top10k", "allports"}


def _norm_target(t):
    if isinstance(t, dict):
        h = str(t.get("host", "")).strip()
        l = str(t.get("label", "")).strip() or None
        return {"host": h, "label": l} if h else None
    h = str(t).strip()
    return {"host": h} if h else None


def _validate_and_norm_targets(raw: list) -> list:
    normalized = [n for n in (_norm_target(t) for t in raw) if n]
    if not normalized:
        raise HTTPException(status_code=400, detail="At least one target is required")
    return normalized


def _validate_ports(ports: Optional[str]) -> str:
    p = (ports or "top1000").strip()
    if p not in VALID_PORT_PRESETS and not _VALID_PORTS_RE.match(p):
        raise HTTPException(status_code=400, detail="Invalid port specification")
    return p


class ScanRequest(BaseModel):
    targets: Optional[list] = None   # [{host, label}] or plain strings
    target: Optional[str] = None     # legacy single-target
    scan_name: Optional[str] = None
    modules: list[str]
    ports: Optional[str] = "top1000"


@app.post("/api/scans")
def create_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    invalid = set(req.modules) - AVAILABLE_MODULES
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown modules: {invalid}")
    if not req.modules:
        raise HTTPException(status_code=400, detail="Select at least one module")

    raw = req.targets or ([req.target] if req.target else [])
    normalized = _validate_and_norm_targets(raw)
    hosts = [t["host"] for t in normalized]
    ports = _validate_ports(req.ports)

    display_target = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"
    first = normalized[0]
    scan_name = req.scan_name or (first.get("label") or first["host"] if len(hosts) == 1 else f"{len(hosts)} hosts")

    initial_progress = {m: {"status": "pending", "percent": 0, "message": "Queued"} for m in req.modules}

    scan = models.Scan(
        user_id=current_user.id,
        target=display_target,
        targets=json.dumps(normalized),
        ports=ports,
        scan_name=scan_name,
        modules=json.dumps(req.modules),
        status="pending",
        progress=json.dumps(initial_progress),
        results=json.dumps({}),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan, scan.id, hosts, req.modules, ports)
    return {"id": scan.id, "status": "pending"}


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.user_id == current_user.id)
        .order_by(models.Scan.created_at.desc())
        .all()
    )
    return [_scan_summary(s) for s in scans]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    scan = _get_user_scan(scan_id, current_user.id, db)
    return {**_scan_summary(scan), "results": scan.get_results()}


@app.get("/api/scans/{scan_id}/stream")
async def stream_scan_progress(scan_id: int, token: str, db: Session = Depends(get_db)):
    try:
        user = auth.get_current_user(token, db)
    except HTTPException:
        raise HTTPException(status_code=401, detail="Invalid token")

    scan = _get_user_scan(scan_id, user.id, db)

    async def event_generator():
        last_progress = None
        consecutive_same = 0
        while True:
            db.expire(scan)
            db.refresh(scan)
            current_progress = scan.progress
            current_status = scan.status

            if current_progress != last_progress:
                last_progress = current_progress
                consecutive_same = 0
                yield f"data: {json.dumps({'status': current_status, 'progress': scan.get_progress()})}\n\n"
            else:
                consecutive_same += 1

            if current_status in ("completed", "failed"):
                yield f"data: {json.dumps({'status': current_status, 'progress': scan.get_progress(), 'results': scan.get_results()})}\n\n"
                break

            if consecutive_same > 300:
                break

            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    scan = _get_user_scan(scan_id, current_user.id, db)
    db.delete(scan)
    db.commit()
    return {"ok": True}


@app.get("/api/scans/{scan_id}/pdf")
def export_pdf(scan_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    scan = _get_user_scan(scan_id, current_user.id, db)
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan must be completed before exporting")

    scan_data = {**_scan_summary(scan), "results": scan.get_results()}
    try:
        pdf_bytes = generate_pdf_report(scan_data, current_user.username)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in scan.scan_name)
    filename = f"webhaunter-{safe_name}-{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Schedules ─────────────────────────────────────────────────────────────────


class ScheduleRequest(BaseModel):
    scan_name: str
    targets: list                    # [{host, label}] or plain strings
    modules: list[str]
    ports: Optional[str] = "top1000"
    interval: str                    # key from VALID_INTERVALS
    run_time: Optional[str] = "00:00"  # "HH:MM" 24-hour


@app.get("/api/schedules")
def list_schedules(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    schedules = (
        db.query(models.ScheduledScan)
        .filter(models.ScheduledScan.user_id == current_user.id)
        .order_by(models.ScheduledScan.created_at.desc())
        .all()
    )
    return [_schedule_summary(s) for s in schedules]


@app.post("/api/schedules")
def create_schedule(
    req: ScheduleRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if req.interval not in VALID_INTERVALS:
        raise HTTPException(status_code=400, detail=f"Invalid interval. Options: {list(VALID_INTERVALS)}")
    invalid = set(req.modules) - AVAILABLE_MODULES
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown modules: {invalid}")

    normalized = _validate_and_norm_targets(req.targets)
    ports = _validate_ports(req.ports)
    run_time = (req.run_time or "00:00").strip()

    from datetime import timezone
    trigger = _make_trigger(req.interval, run_time)
    next_run = trigger.get_next_fire_time(None, datetime.now(timezone.utc)).replace(tzinfo=None)

    sched = models.ScheduledScan(
        user_id=current_user.id,
        scan_name=req.scan_name,
        targets=json.dumps(normalized),
        modules=json.dumps(req.modules),
        ports=ports,
        interval=req.interval,
        run_time=run_time,
        enabled=True,
        next_run_at=next_run,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    _add_schedule_job(sched)
    return _schedule_summary(sched)


@app.patch("/api/schedules/{sched_id}/toggle")
def toggle_schedule(sched_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    sched = _get_user_schedule(sched_id, current_user.id, db)
    sched.enabled = not sched.enabled
    if sched.enabled:
        from datetime import timezone
        trigger = _make_trigger(sched.interval, sched.run_time or "00:00")
        sched.next_run_at = trigger.get_next_fire_time(None, datetime.now(timezone.utc)).replace(tzinfo=None)
        _add_schedule_job(sched)
    else:
        _remove_schedule_job(sched_id)
    db.commit()
    return _schedule_summary(sched)


@app.post("/api/schedules/{sched_id}/run")
async def run_schedule_now(
    sched_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    sched = _get_user_schedule(sched_id, current_user.id, db)

    targets_data = sched.get_targets()
    hosts = [t["host"] for t in targets_data]
    modules = sched.get_modules()
    ports = sched.ports or "top1000"
    display_target = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"

    initial_progress = {m: {"status": "pending", "percent": 0, "message": "Queued"} for m in modules}

    scan = models.Scan(
        user_id=current_user.id,
        target=display_target,
        targets=sched.targets,
        ports=ports,
        scan_name=sched.scan_name,
        modules=sched.modules,
        status="pending",
        progress=json.dumps(initial_progress),
        results=json.dumps({}),
        scheduled_scan_id=sched.id,
    )
    db.add(scan)
    sched.last_run_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan, scan.id, hosts, modules, ports)
    return {"scan_id": scan.id}


@app.delete("/api/schedules/{sched_id}")
def delete_schedule(sched_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    sched = _get_user_schedule(sched_id, current_user.id, db)
    _remove_schedule_job(sched_id)
    db.delete(sched)
    db.commit()
    return {"ok": True}


# ── Background scan runner ────────────────────────────────────────────────────


async def _run_scan(scan_id: int, targets: list[str], modules: list[str], ports: str = "top1000"):
    db = SessionLocal()
    try:
        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        scan.status = "running"
        progress = {m: {"status": "pending", "percent": 0, "message": "Queued"} for m in modules}
        scan.progress = json.dumps(progress)
        db.commit()

        results = {}

        async def update_progress(module: str, percent: int, message: str):
            nonlocal progress
            progress[module] = {"status": "running", "percent": percent, "message": message}
            scan.progress = json.dumps(progress)
            db.commit()

        async def mark_done(module: str, result: dict):
            nonlocal progress, results
            progress[module] = {"status": "completed", "percent": 100, "message": "Done"}
            results[module] = result
            scan.progress = json.dumps(progress)
            scan.results = json.dumps(results)
            db.commit()

        async def mark_failed(module: str, error: str):
            nonlocal progress, results
            progress[module] = {"status": "failed", "percent": 100, "message": error}
            results[module] = {"error": error}
            scan.progress = json.dumps(progress)
            scan.results = json.dumps(results)
            db.commit()

        for module in modules:
            try:
                if module == "nmap":
                    result = await run_nmap(targets, ports, lambda m, p, msg, _m=module: update_progress(_m, p, msg))
                    result = await enrich_nmap_results_with_cves(result)
                    await mark_done(module, result)
            except Exception as e:
                await mark_failed(module, str(e))

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan.status = "failed"
        scan.error_message = str(e)
        db.commit()
    finally:
        db.close()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_user_scan(scan_id: int, user_id: int, db: Session) -> models.Scan:
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id,
        models.Scan.user_id == user_id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _get_user_schedule(sched_id: int, user_id: int, db: Session) -> models.ScheduledScan:
    sched = db.query(models.ScheduledScan).filter(
        models.ScheduledScan.id == sched_id,
        models.ScheduledScan.user_id == user_id,
    ).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return sched


def _scan_summary(scan: models.Scan) -> dict:
    return {
        "id": scan.id,
        "target": scan.target,
        "targets": scan.get_targets(),
        "ports": scan.ports or "top1000",
        "scan_name": scan.scan_name,
        "modules": scan.get_modules(),
        "status": scan.status,
        "scheduled_scan_id": scan.scheduled_scan_id,
        "progress": scan.get_progress(),
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "error_message": scan.error_message,
    }


def _schedule_summary(sched: models.ScheduledScan) -> dict:
    return {
        "id": sched.id,
        "scan_name": sched.scan_name,
        "targets": sched.get_targets(),
        "modules": sched.get_modules(),
        "ports": sched.ports or "top1000",
        "interval": sched.interval,
        "interval_label": SCHEDULE_LABELS.get(sched.interval, sched.interval),
        "run_time": sched.run_time or "00:00",
        "enabled": sched.enabled,
        "created_at": sched.created_at.isoformat() if sched.created_at else None,
        "last_run_at": sched.last_run_at.isoformat() if sched.last_run_at else None,
        "next_run_at": sched.next_run_at.isoformat() if sched.next_run_at else None,
    }


# ── Static files (frontend) ───────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_DIR, "static")), name="static")


@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    index = os.path.join(FRONTEND_DIR, "index.html")
    return FileResponse(index)
