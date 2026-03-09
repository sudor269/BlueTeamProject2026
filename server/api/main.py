from fastapi import FastAPI, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
from datetime import datetime, timezone

from db import get_db
import models
import schemas

app = FastAPI(title="UsbGuard Admin")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.get("/agent/policy", response_model=schemas.PolicyOut)
def agent_policy(host: str, db: Session = Depends(get_db)):
    pol = db.get(models.Policy, 1)
    if not pol:
        pol = models.Policy(id=1, version=1, audit_only=False, default_allow_if_no_serial=False)
        db.add(pol)
        db.commit()
        db.refresh(pol)

    devices = db.execute(
        select(models.Device).where(models.Device.enabled == True).order_by(models.Device.hash_hex)
    ).scalars().all()

    return schemas.PolicyOut(
        version=pol.version,
        audit_only=pol.audit_only,
        default_allow_if_no_serial=pol.default_allow_if_no_serial,
        hashes=[d.hash_hex.upper() for d in devices]
    )

@app.post("/agent/heartbeat")
def agent_heartbeat(body: schemas.AgentHeartbeat, db: Session = Depends(get_db)):
    host = db.execute(select(models.Host).where(models.Host.hostname == body.host)).scalar_one_or_none()
    if host is None:
        host = models.Host(hostname=body.host)
        db.add(host)

    host.last_seen = datetime.now(timezone.utc)
    host.status = body.status

    ev = models.Event(host=body.host, action="HEARTBEAT", reason=body.status)
    db.add(ev)

    db.commit()
    return {"ok": True}

@app.post("/agent/events")
def agent_events(body: schemas.AgentEventIn, db: Session = Depends(get_db)):
    ev = models.Event(
        host=body.host,
        action=body.action,
        reason=body.reason,
        hash_hex=(body.hash_hex.upper() if body.hash_hex else None),
        serial_normalized=body.serial_normalized
    )
    db.add(ev)
    db.commit()
    return {"ok": True}


@app.get("/api/devices")
def api_devices(db: Session = Depends(get_db)):
    rows = db.execute(select(models.Device).order_by(models.Device.id.desc())).scalars().all()
    return [
        {
            "id": r.id,
            "hash_hex": r.hash_hex,
            "serial_normalized": r.serial_normalized,
            "comment": r.comment,
            "enabled": r.enabled,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in rows
    ]

@app.post("/api/devices")
def api_add_device(body: schemas.DeviceCreate, db: Session = Depends(get_db)):
    h = body.hash_hex.strip().upper()
    if len(h) != 16 or any(c not in "0123456789ABCDEF" for c in h):
        raise HTTPException(400, "hash_hex must be 16 hex chars")

    exists = db.execute(select(models.Device).where(models.Device.hash_hex == h)).scalar_one_or_none()
    if exists:
        raise HTTPException(409, "device already exists")

    row = models.Device(hash_hex=h, serial_normalized=body.serial_normalized, comment=body.comment, enabled=True)
    db.add(row)

    pol = db.get(models.Policy, 1)
    pol.version += 1

    db.add(models.Event(action="ADMIN_ADD_DEVICE", reason="admin", hash_hex=h))
    db.commit()
    return {"ok": True}

@app.delete("/api/devices/{device_id}")
def api_delete_device(device_id: int, db: Session = Depends(get_db)):
    row = db.get(models.Device, device_id)
    if not row:
        raise HTTPException(404, "not found")

    db.delete(row)
    pol = db.get(models.Policy, 1)
    pol.version += 1
    db.add(models.Event(action="ADMIN_DELETE_DEVICE", reason="admin", hash_hex=row.hash_hex))
    db.commit()
    return {"ok": True}

@app.post("/api/policy")
def api_policy_update(body: schemas.PolicyUpdate, db: Session = Depends(get_db)):
    pol = db.get(models.Policy, 1)
    if not pol:
        pol = models.Policy(id=1)
        db.add(pol)

    pol.audit_only = body.audit_only
    pol.default_allow_if_no_serial = body.default_allow_if_no_serial
    pol.version += 1
    db.add(models.Event(action="ADMIN_POLICY_UPDATE", reason=f"audit={body.audit_only}"))
    db.commit()
    return {"ok": True, "version": pol.version}


@app.get("/", response_class=HTMLResponse)
def ui_index(request: Request, db: Session = Depends(get_db)):
    pol = db.get(models.Policy, 1)
    hosts = db.execute(select(models.Host).order_by(models.Host.hostname)).scalars().all()
    recent = db.execute(select(models.Event).order_by(desc(models.Event.id)).limit(20)).scalars().all()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "policy": pol,
        "hosts": hosts,
        "recent": recent,
    })

@app.get("/devices", response_class=HTMLResponse)
def ui_devices(request: Request, db: Session = Depends(get_db)):
    devices = db.execute(select(models.Device).order_by(desc(models.Device.id))).scalars().all()
    return templates.TemplateResponse("devices.html", {"request": request, "devices": devices})

@app.post("/devices/add")
def ui_devices_add(
    hash_hex: str = Form(...),
    serial_normalized: str = Form(""),
    comment: str = Form(""),
    db: Session = Depends(get_db)
):
    h = hash_hex.strip().upper()
    if len(h) != 16 or any(c not in "0123456789ABCDEF" for c in h):
        raise HTTPException(400, "Invalid hash")

    exists = db.execute(select(models.Device).where(models.Device.hash_hex == h)).scalar_one_or_none()
    if not exists:
        db.add(models.Device(hash_hex=h, serial_normalized=serial_normalized or None, comment=comment or None))
        pol = db.get(models.Policy, 1)
        pol.version += 1
        db.add(models.Event(action="ADMIN_ADD_DEVICE", reason="web", hash_hex=h))
        db.commit()

    return RedirectResponse("/devices", status_code=303)

@app.post("/devices/delete/{device_id}")
def ui_devices_delete(device_id: int, db: Session = Depends(get_db)):
    row = db.get(models.Device, device_id)
    if row:
        h = row.hash_hex
        db.delete(row)
        pol = db.get(models.Policy, 1)
        pol.version += 1
        db.add(models.Event(action="ADMIN_DELETE_DEVICE", reason="web", hash_hex=h))
        db.commit()
    return RedirectResponse("/devices", status_code=303)

@app.get("/events", response_class=HTMLResponse)
def ui_events(request: Request, db: Session = Depends(get_db)):
    events = db.execute(select(models.Event).order_by(desc(models.Event.id)).limit(500)).scalars().all()
    return templates.TemplateResponse("events.html", {"request": request, "events": events})

@app.post("/policy/update")
def ui_policy_update(
    audit_only: str = Form("off"),
    default_allow_if_no_serial: str = Form("off"),
    db: Session = Depends(get_db)
):
    pol = db.get(models.Policy, 1)
    pol.audit_only = (audit_only == "on")
    pol.default_allow_if_no_serial = (default_allow_if_no_serial == "on")
    pol.version += 1
    db.add(models.Event(action="ADMIN_POLICY_UPDATE", reason=f"web v={pol.version}"))
    db.commit()
    return RedirectResponse("/", status_code=303)