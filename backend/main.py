import asyncio
import json
import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from database import engine, get_db, Base
import auth
from cve_lookup import enrich_nmap_results_with_cves
from scanners.nmap_scanner import run_nmap
from scanners.gobuster_scanner import run_gobuster_dir, run_gobuster_dns
from scanners.nikto_scanner import run_nikto
from scanners.ssl_scanner import run_ssl_check
from scanners.headers_scanner import run_headers_check
from pdf_generator import generate_pdf_report

Base.metadata.create_all(bind=engine)

app = FastAPI(title="WebHaunter", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

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


AVAILABLE_MODULES = {"nmap", "gobuster_dir", "gobuster_dns", "nikto", "ssl", "headers"}


class ScanRequest(BaseModel):
    target: str
    scan_name: Optional[str] = None
    modules: list[str]


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

    initial_progress = {m: {"status": "pending", "percent": 0, "message": "Queued"} for m in req.modules}

    scan = models.Scan(
        user_id=current_user.id,
        target=req.target.strip(),
        scan_name=req.scan_name or req.target.strip(),
        modules=json.dumps(req.modules),
        status="pending",
        progress=json.dumps(initial_progress),
        results=json.dumps({}),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan, scan.id, req.target.strip(), req.modules)

    return {"id": scan.id, "status": "pending"}


@app.get("/api/scans")
def list_scans(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.user_id == current_user.id)
        .order_by(models.Scan.created_at.desc())
        .all()
    )
    return [_scan_summary(s) for s in scans]


@app.get("/api/scans/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    scan = _get_user_scan(scan_id, current_user.id, db)
    return {
        **_scan_summary(scan),
        "results": scan.get_results(),
    }


@app.get("/api/scans/{scan_id}/stream")
async def stream_scan_progress(
    scan_id: int,
    token: str,
    db: Session = Depends(get_db),
):
    """SSE endpoint for live scan progress. Token passed as query param."""
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
                data = json.dumps({
                    "status": current_status,
                    "progress": scan.get_progress(),
                })
                yield f"data: {data}\n\n"
            else:
                consecutive_same += 1

            if current_status in ("completed", "failed"):
                # Send final results
                data = json.dumps({
                    "status": current_status,
                    "progress": scan.get_progress(),
                    "results": scan.get_results(),
                })
                yield f"data: {data}\n\n"
                break

            # Timeout after ~5 minutes of no changes
            if consecutive_same > 300:
                break

            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.delete("/api/scans/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    scan = _get_user_scan(scan_id, current_user.id, db)
    db.delete(scan)
    db.commit()
    return {"ok": True}


@app.get("/api/scans/{scan_id}/pdf")
def export_pdf(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    scan = _get_user_scan(scan_id, current_user.id, db)
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan must be completed before exporting")

    scan_data = {
        **_scan_summary(scan),
        "results": scan.get_results(),
    }

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


# ── Background scan runner ────────────────────────────────────────────────────


async def _run_scan(scan_id: int, target: str, modules: list[str]):
    from database import SessionLocal
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
                    result = await run_nmap(target, lambda m, p, msg, _m=module: update_progress(_m, p, msg))
                    result = await enrich_nmap_results_with_cves(result)
                    await mark_done(module, result)

                elif module == "gobuster_dir":
                    result = await run_gobuster_dir(target, lambda m, p, msg, _m=module: update_progress(_m, p, msg))
                    await mark_done(module, result)

                elif module == "gobuster_dns":
                    result = await run_gobuster_dns(target, lambda m, p, msg, _m=module: update_progress(_m, p, msg))
                    await mark_done(module, result)

                elif module == "nikto":
                    result = await run_nikto(target, lambda m, p, msg, _m=module: update_progress(_m, p, msg))
                    await mark_done(module, result)

                elif module == "ssl":
                    result = await run_ssl_check(target, lambda m, p, msg, _m=module: update_progress(_m, p, msg))
                    await mark_done(module, result)

                elif module == "headers":
                    result = await run_headers_check(target, lambda m, p, msg, _m=module: update_progress(_m, p, msg))
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


def _scan_summary(scan: models.Scan) -> dict:
    return {
        "id": scan.id,
        "target": scan.target,
        "scan_name": scan.scan_name,
        "modules": scan.get_modules(),
        "status": scan.status,
        "progress": scan.get_progress(),
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "error_message": scan.error_message,
    }


# ── Static files (frontend) ───────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_DIR, "static")), name="static")


@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    index = os.path.join(FRONTEND_DIR, "index.html")
    return FileResponse(index)
