import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
import httpx

from shared.config import settings
from shared.database import init_db, get_db, engine
from shared.models import PassengerChart, AuditLog
from shared.crypto_utils import load_public_key, verify_signature, compute_identity_hash
from shared.payload import parse_jwt


# ── Pydantic request/response models ─────────────────────────────────────────

class AadhaarInput(BaseModel):
    berth: str
    aadhaar: str
    dob: str          # YYYY-MM-DD

class VerifyRequest(BaseModel):
    jwt: str
    tte_id: str
    expected_train: str
    aadhaar_inputs: Optional[list[AadhaarInput]] = None

class ChartAddPassenger(BaseModel):
    name: str
    berth: Optional[str] = None

class ChartAddRequest(BaseModel):
    pnr: str
    uuid: str
    train: str
    travel_date: str
    ticket_class: str
    passengers: list[ChartAddPassenger]


# ── App lifespan: load keys + init DB ────────────────────────────────────────

PUBLIC_KEYS = {}   # {"current": key_obj, "previous": key_obj or None}

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    import os
    current_path = os.path.join(settings.KEYS_DIR, "public_key.pem")
    old_path     = os.path.join(settings.KEYS_DIR, "old_public_key.pem")

    if not os.path.exists(current_path):
        raise RuntimeError(
            "public_key.pem not found. Run `python -m cli keygen` first."
        )

    PUBLIC_KEYS["current"] = load_public_key(current_path)
    PUBLIC_KEYS["previous"] = load_public_key(old_path) if os.path.exists(old_path) else None

    print(f"✓ HHT Service ready — public key loaded from {current_path}")
    if PUBLIC_KEYS["previous"]:
        print(f"✓ Previous public key also loaded from {old_path}")

    yield

    PUBLIC_KEYS.clear()


app = FastAPI(title="HHT Verification Service", version="1.0.0", lifespan=lifespan)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _post_audit_log(uuid: str, tte_id: str, train: str,
                    coach: Optional[str], result: str, ip: str) -> bool:
    """
    Fire-and-forget POST to audit server.
    Returns is_duplicate bool. Returns False on any network error.
    """
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.post(
                f"{settings.AUDIT_SERVER_URL}/log",
                json={
                    "uuid":       uuid,
                    "tte_id":     tte_id,
                    "train":      train,
                    "coach":      coach,
                    "result":     result,
                    "ip_address": ip,
                }
            )
            data = resp.json()
            return data.get("is_duplicate", False)
    except Exception:
        return False


def _extract_coach(berth: Optional[str]) -> Optional[str]:
    """Extract coach from berth string like 'B2/14' → 'B2'."""
    if berth and "/" in berth:
        return berth.split("/")[0]
    return None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "public_key_loaded": "current" in PUBLIC_KEYS,
        "previous_key_loaded": PUBLIC_KEYS.get("previous") is not None,
    }


@app.post("/verify")
def verify_ticket(req: VerifyRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    now = int(time.time())

    # ── Step 1: Parse JWT ────────────────────────────────────────────────────
    try:
        payload, raw_payload_bytes, sig_b64url = parse_jwt(req.jwt)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"detail": f"Malformed JWT: {e}"})

    uuid = payload.get("uuid", "unknown")

    # ── Step 2: Signature verification ───────────────────────────────────────
    key_used = None
    sig_valid = False

    if verify_signature(raw_payload_bytes, sig_b64url, PUBLIC_KEYS["current"]):
        sig_valid = True
        key_used = "current"
    elif PUBLIC_KEYS.get("previous") and verify_signature(
        raw_payload_bytes, sig_b64url, PUBLIC_KEYS["previous"]
    ):
        sig_valid = True
        key_used = "previous"

    if not sig_valid:
        is_dup = _post_audit_log(uuid, req.tte_id, req.expected_train, None, "FORGED", ip)
        return {
            "result":           "FORGED",
            "signature_valid":  False,
            "chart_matched":    False,
            "is_duplicate":     is_dup,
            "audit_logged":     True,
            "key_used":         None,
            "ticket_details":   None,
            "passengers":       [],
        }

    # ── Step 3: Validity window ───────────────────────────────────────────────
    vf = payload.get("vf", 0)
    vu = payload.get("vu", 0)

    if now < vf:
        is_dup = _post_audit_log(uuid, req.tte_id, req.expected_train, None, "NOT_YET_VALID", ip)
        return {
            "result":          "NOT_YET_VALID",
            "signature_valid": True,
            "chart_matched":   False,
            "is_duplicate":    is_dup,
            "audit_logged":    True,
            "key_used":        key_used,
            "ticket_details":  _ticket_details(payload),
            "passengers":      [],
        }

    if now > vu:
        is_dup = _post_audit_log(uuid, req.tte_id, req.expected_train, None, "EXPIRED", ip)
        return {
            "result":          "EXPIRED",
            "signature_valid": True,
            "chart_matched":   False,
            "is_duplicate":    is_dup,
            "audit_logged":    True,
            "key_used":        key_used,
            "ticket_details":  _ticket_details(payload),
            "passengers":      [],
        }

    # ── Step 4: Train match ───────────────────────────────────────────────────
    if payload.get("train") != req.expected_train:
        is_dup = _post_audit_log(uuid, req.tte_id, req.expected_train, None, "WRONG_TRAIN", ip)
        return {
            "result":          "WRONG_TRAIN",
            "signature_valid": True,
            "chart_matched":   False,
            "is_duplicate":    is_dup,
            "audit_logged":    True,
            "key_used":        key_used,
            "ticket_details":  _ticket_details(payload),
            "passengers":      [],
        }

    # ── Step 5: Date match ────────────────────────────────────────────────────
    from datetime import date as date_type
    today_str = date_type.today().isoformat()
    if payload.get("date") != today_str:
        is_dup = _post_audit_log(uuid, req.tte_id, req.expected_train, None, "WRONG_DATE", ip)
        return {
            "result":          "WRONG_DATE",
            "signature_valid": True,
            "chart_matched":   False,
            "is_duplicate":    is_dup,
            "audit_logged":    True,
            "key_used":        key_used,
            "ticket_details":  _ticket_details(payload),
            "passengers":      [],
        }

    # ── Step 6: Chart lookup ──────────────────────────────────────────────────
    chart_rows = (
        db.query(PassengerChart)
        .filter_by(uuid=uuid)
        .all()
    )

    if not chart_rows:
        is_dup = _post_audit_log(uuid, req.tte_id, req.expected_train, None, "INVALID_PNR", ip)
        return {
            "result":          "INVALID_PNR",
            "signature_valid": True,
            "chart_matched":   False,
            "is_duplicate":    is_dup,
            "audit_logged":    True,
            "key_used":        key_used,
            "ticket_details":  _ticket_details(payload),
            "passengers":      [],
        }

    # ── Step 7: Identity check (optional, mandatory for Tatkal) ──────────────
    aadhaar_map = {}   # berth → AadhaarInput
    if req.aadhaar_inputs:
        for ai in req.aadhaar_inputs:
            aadhaar_map[ai.berth] = ai

    pax_results = []
    pax_list    = payload.get("pax", [])

    for pax in pax_list:
        berth   = pax.get("b")
        id_hash = pax.get("id")

        # Find matching chart row for display name
        chart_row = next((r for r in chart_rows if r.berth == berth), None)
        name = chart_row.passenger_name if chart_row else "Unknown"

        identity_result = "NOT_REQUIRED"

        if id_hash:
            if berth in aadhaar_map:
                ai = aadhaar_map[berth]
                computed = compute_identity_hash(ai.aadhaar, ai.dob)
                identity_result = "PASSED" if computed == id_hash else "FAILED"
            else:
                # Tatkal tickets MUST have identity check
                if payload.get("type") == "T":
                    identity_result = "NOT_ATTEMPTED_MANDATORY"
                else:
                    identity_result = "NOT_ATTEMPTED"

        pax_results.append({
            "name":           name,
            "berth":          berth,
            "identity_check": identity_result,
        })

    # ── Step 8: Determine coach from first pax berth ──────────────────────────
    coach = None
    if pax_list and pax_list[0].get("b"):
        coach = _extract_coach(pax_list[0]["b"])

    # ── Step 9: Audit log + duplicate check ───────────────────────────────────
    is_duplicate = _post_audit_log(uuid, req.tte_id, req.expected_train, coach, "VALID", ip)

    final_result = "DUPLICATE" if is_duplicate else "VALID"

    return {
        "result":          final_result,
        "signature_valid": True,
        "chart_matched":   True,
        "is_duplicate":    is_duplicate,
        "audit_logged":    True,
        "key_used":        key_used,
        "ticket_details":  _ticket_details(payload),
        "passengers":      pax_results,
    }


@app.post("/chart/add")
def chart_add(req: ChartAddRequest, db: Session = Depends(get_db)):
    for p in req.passengers:
        row = PassengerChart(
            pnr            = req.pnr,
            uuid           = req.uuid,
            train          = req.train,
            travel_date    = req.travel_date,
            berth          = p.berth,
            passenger_name = p.name,
            ticket_class   = req.ticket_class,
            aadhaar_hash   = None,   # chart never stores hash — it lives only in JWT
        )
        db.add(row)
    db.commit()
    return {"added": True, "passengers_added": len(req.passengers)}


@app.get("/chart/{train}/{date}")
def chart_get(train: str, date: str, db: Session = Depends(get_db)):
    rows = (
        db.query(PassengerChart)
        .filter_by(train=train, travel_date=date)
        .all()
    )

    coaches: dict = {}
    for r in rows:
        coach = _extract_coach(r.berth) or "UNRESERVED"
        coaches.setdefault(coach, []).append({
            "berth": r.berth,
            "name":  r.passenger_name,
            "pnr":   r.pnr,
            "class": r.ticket_class,
        })

    return {
        "train":            train,
        "date":             date,
        "total_passengers": len(rows),
        "coaches":          coaches,
    }


@app.delete("/chart/{train}/{date}")
def chart_clear(train: str, date: str, db: Session = Depends(get_db)):
    deleted = (
        db.query(PassengerChart)
        .filter_by(train=train, travel_date=date)
        .delete()
    )
    db.commit()
    return {"cleared": True, "rows_deleted": deleted}


# ── Internal helper ───────────────────────────────────────────────────────────

def _ticket_details(payload: dict) -> dict:
    return {
        "uuid":  payload.get("uuid"),
        "train": payload.get("train"),
        "from":  payload.get("from"),
        "to":    payload.get("to"),
        "class": payload.get("class"),
        "date":  payload.get("date"),
        "type":  payload.get("type"),
    }