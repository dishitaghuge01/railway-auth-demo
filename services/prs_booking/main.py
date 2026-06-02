import os
import time
import random
from contextlib import asynccontextmanager
from datetime import datetime, date as date_type

import qrcode
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
import httpx

from shared.config import settings
from shared.database import init_db, get_db
from shared.models import IssuedTicket, PassengerChart


# ── Pydantic models ───────────────────────────────────────────────────────────

class PassengerInput(BaseModel):
    name: str
    berth: Optional[str]  = None
    aadhaar: Optional[str] = None
    dob: Optional[str]    = None   # YYYY-MM-DD

class BookingRequest(BaseModel):
    ticket_type:    str          # "R", "U", "T"
    train:          str
    from_stn:       str
    to_stn:         str
    ticket_class:   str          # "1A","2A","3A","SL","UR"
    travel_date:    str          # YYYY-MM-DD
    departure_time: str          # HH:MM  (24h)
    arrival_time:   str          # HH:MM  (24h, next-day auto-detected)
    passengers:     list[PassengerInput]


# ── Lifespan ──────────────────────────────────────────────────────────────────

templates = Jinja2Templates(directory="services/prs_booking/templates")

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    os.makedirs(settings.TICKETS_DIR, exist_ok=True)
    print("✓ PRS Booking Service ready")
    yield

app = FastAPI(title="PRS Booking Service", version="1.0.0", lifespan=lifespan)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_pnr() -> str:
    """PNR + 7 random digits, e.g. PNR8472910."""
    return "PNR" + str(random.randint(1000000, 9999999))


def _make_unix(date_str: str, time_str: str, base_date_str: Optional[str] = None) -> int:
    """
    Combine YYYY-MM-DD + HH:MM into a unix timestamp.
    If arrival_time < departure_time numerically (overnight journey),
    arrival date is bumped by one day.
    base_date_str: the departure date, used to detect next-day arrival.
    """
    dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
    return int(dt.timestamp())


def _arrival_unix(travel_date: str, departure_time: str, arrival_time: str) -> int:
    """Handle overnight journeys: if arrival_time < departure_time, arrival is next day."""
    dep_h, dep_m = map(int, departure_time.split(":"))
    arr_h, arr_m = map(int, arrival_time.split(":"))
    dep_minutes  = dep_h * 60 + dep_m
    arr_minutes  = arr_h * 60 + arr_m

    if arr_minutes < dep_minutes:
        # overnight — arrival is next calendar day
        from datetime import timedelta
        arr_date = (datetime.strptime(travel_date, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    else:
        arr_date = travel_date

    return _make_unix(arr_date, arrival_time)


def _generate_qr(jwt_string: str, uuid: str) -> str:
    """Generate QR PNG, return absolute file path."""
    qr = qrcode.QRCode(
        version             = None,          # auto-size
        error_correction    = qrcode.constants.ERROR_CORRECT_H,
        box_size            = 10,
        border              = 4,
    )
    qr.add_data(jwt_string)
    qr.make(fit=True)
    img      = qr.make_image(fill_color="black", back_color="white")
    filepath = os.path.join(settings.TICKETS_DIR, f"{uuid}_qr.png")
    img.save(filepath)
    return filepath


def _call_cris_signer(req: BookingRequest) -> dict:
    """Call CRIS signing microservice. Returns {uuid, pnr, jwt, payload_preview}."""
    departure_unix = _make_unix(req.travel_date, req.departure_time)
    arrival_unix   = _arrival_unix(req.travel_date, req.departure_time, req.arrival_time)

    passengers = [
        {
            "name":    p.name,
            "berth":   p.berth,
            "aadhaar": p.aadhaar,
            "dob":     p.dob,
        }
        for p in req.passengers
    ]

    payload = {
        "ticket_type":     req.ticket_type,
        "train":           req.train,
        "from_stn":        req.from_stn,
        "to_stn":          req.to_stn,
        "ticket_class":    req.ticket_class,
        "travel_date":     req.travel_date,
        "departure_unix":  departure_unix,
        "arrival_unix":    arrival_unix,
        "passengers":      passengers,
    }

    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{settings.CRIS_SIGNER_URL}/sign", json=payload)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"CRIS signer error: {resp.text}"
            )
        return resp.json()


def _call_hht_chart_add(pnr: str, uuid: str, req: BookingRequest):
    """Push passenger chart to HHT service."""
    passengers = [
        {"name": p.name, "berth": p.berth}
        for p in req.passengers
    ]
    body = {
        "pnr":          pnr,
        "uuid":         uuid,
        "train":        req.train,
        "travel_date":  req.travel_date,
        "ticket_class": req.ticket_class,
        "passengers":   passengers,
    }
    try:
        with httpx.Client(timeout=5.0) as client:
            client.post(f"{settings.HHT_SERVICE_URL}/chart/add", json=body)
    except Exception as e:
        # Non-fatal for booking — chart sync can be retried
        print(f"⚠ HHT chart sync failed: {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/book")
def book_ticket(req: BookingRequest, request: Request, db: Session = Depends(get_db)):
    # 1. Call CRIS signer
    signed = _call_cris_signer(req)
    uuid   = signed["uuid"]
    jwt    = signed["jwt"]

    # 2. Generate PNR (use the one from signer, or generate here — signer owns it)
    pnr = signed["pnr"]

    # 3. Persist to issued_tickets
    passenger_names = ", ".join(p.name for p in req.passengers)
    ticket = IssuedTicket(
        uuid            = uuid,
        pnr             = pnr,
        jwt_string      = jwt,
        train           = req.train,
        from_stn        = req.from_stn,
        to_stn          = req.to_stn,
        ticket_class    = req.ticket_class,
        travel_date     = req.travel_date,
        ticket_type     = req.ticket_type,
        issued_at       = int(time.time()),
        passenger_names = passenger_names,
    )
    db.add(ticket)
    db.commit()

    # 4. Generate QR code PNG
    _generate_qr(jwt, uuid)

    # 5. Push chart to HHT service
    _call_hht_chart_add(pnr, uuid, req)

    # 6. Build response URLs using the actual host the client used
    base_url = str(request.base_url).rstrip("/")
    return {
        "pnr":        pnr,
        "uuid":       uuid,
        "ticket_url": f"{base_url}/ticket/{pnr}",
        "qr_url":     f"{base_url}/ticket/{pnr}/qr",
        "message":    "Booking confirmed",
    }


@app.get("/ticket/{pnr}", response_class=HTMLResponse)
def ticket_page(pnr: str, request: Request, db: Session = Depends(get_db)):
    ticket = db.query(IssuedTicket).filter_by(pnr=pnr).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="PNR not found")

    # Fetch passengers from chart
    passengers = (
        db.query(PassengerChart)
        .filter_by(pnr=pnr)
        .all()
    )

    # Human-readable validity window from payload
    from shared.payload import parse_jwt
    try:
        payload, _, _ = parse_jwt(ticket.jwt_string)
        vf = datetime.fromtimestamp(payload["vf"]).strftime("%d %b %Y %H:%M")
        vu = datetime.fromtimestamp(payload["vu"]).strftime("%d %b %Y %H:%M")
    except Exception:
        vf, vu = "—", "—"

    return templates.TemplateResponse("ticket.html", {
        "request":    request,
        "ticket":     ticket,
        "passengers": passengers,
        "valid_from": vf,
        "valid_until": vu,
        "qr_url":     f"/ticket/{pnr}/qr",
    })


@app.get("/ticket/{pnr}/qr")
def ticket_qr(pnr: str, db: Session = Depends(get_db)):
    ticket = db.query(IssuedTicket).filter_by(pnr=pnr).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="PNR not found")

    qr_path = os.path.join(settings.TICKETS_DIR, f"{ticket.uuid}_qr.png")
    if not os.path.exists(qr_path):
        # Regenerate if file was deleted
        _generate_qr(ticket.jwt_string, ticket.uuid)

    return FileResponse(qr_path, media_type="image/png")


@app.get("/ticket/{pnr}/raw")
def ticket_raw(pnr: str, db: Session = Depends(get_db)):
    ticket = db.query(IssuedTicket).filter_by(pnr=pnr).first()
    if not ticket:
        raise HTTPException(status_code=404,detail="PNR not found")
    return {
        "pnr":       ticket.pnr,
        "uuid":      ticket.uuid,
        "jwt":       ticket.jwt_string,
        "issued_at": ticket.issued_at,
    }


@app.get("/tickets")
def list_tickets(db: Session = Depends(get_db)):
    tickets = db.query(IssuedTicket).order_by(IssuedTicket.issued_at.desc()).all()
    return {
        "tickets": [
            {
                "pnr":             t.pnr,
                "train":           t.train,
                "from":            t.from_stn,
                "to":              t.to_stn,
                "class":           t.ticket_class,
                "date":            t.travel_date,
                "type":            t.ticket_type,
                "passengers":      t.passenger_names,
                "issued_at":       t.issued_at,
            }
            for t in tickets
        ]
    }