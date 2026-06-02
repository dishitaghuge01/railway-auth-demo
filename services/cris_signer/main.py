import os
import uuid as uuid_lib
import random
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from shared.config import settings
from shared.crypto_utils import load_private_key, load_public_key, get_public_key_fingerprint
from shared.payload import build_payload, assemble_jwt


# ── Request model ─────────────────────────────────────────────────────────────

class PassengerIn(BaseModel):
    name:    str
    berth:   Optional[str] = None
    aadhaar: Optional[str] = None
    dob:     Optional[str] = None

class SignRequest(BaseModel):
    ticket_type:    str
    train:          str
    from_stn:       str
    to_stn:         str
    ticket_class:   str
    travel_date:    str
    departure_unix: int
    arrival_unix:   int
    passengers:     list[PassengerIn]


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    private_path = os.path.join(settings.KEYS_DIR, "private_key.pem")
    public_path  = os.path.join(settings.KEYS_DIR, "public_key.pem")
    old_path     = os.path.join(settings.KEYS_DIR, "old_public_key.pem")

    if not os.path.exists(private_path):
        raise RuntimeError(
            f"Private key not found at {private_path}. "
            "Run `python -m cli keygen` first."
        )

    app.state.private_key     = load_private_key(private_path)
    app.state.public_key_pem  = open(public_path, "rb").read()
    app.state.fingerprint     = get_public_key_fingerprint(app.state.public_key_pem)
    app.state.old_public_pem  = open(old_path, "rb").read() if os.path.exists(old_path) else None

    print(f"✓ CRIS Signer ready — key fingerprint: {app.state.fingerprint}")
    yield


app = FastAPI(title="CRIS Signing Service", version="1.0.0", lifespan=lifespan)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_pnr() -> str:
    return "PNR" + str(random.randint(1000000, 9999999))


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":      "ok",
        "hsm_loaded":  hasattr(app.state, "private_key"),
        "fingerprint": getattr(app.state, "fingerprint", None),
    }


@app.get("/public-key")
def get_public_key():
    old_pem = app.state.old_public_pem
    return {
        "current":     app.state.public_key_pem.decode(),
        "previous":    old_pem.decode() if old_pem else None,
        "fingerprint": app.state.fingerprint,
    }


@app.post("/sign")
def sign_ticket(req: SignRequest):
    # Generate uuid and pnr here — signer owns identity generation
    ticket_uuid = str(uuid_lib.uuid4())
    ticket_pnr  = _generate_pnr()

    passengers = [
        {
            "name":    p.name,
            "berth":   p.berth,
            "aadhaar": p.aadhaar,
            "dob":     p.dob,
        }
        for p in req.passengers
    ]

    payload = build_payload(
        ticket_type    = req.ticket_type,
        uuid           = ticket_uuid,
        train          = req.train,
        from_stn       = req.from_stn,
        to_stn         = req.to_stn,
        ticket_class   = req.ticket_class,
        travel_date    = req.travel_date,
        departure_unix = req.departure_unix,
        arrival_unix   = req.arrival_unix,
        passengers     = passengers,
    )

    jwt = assemble_jwt(payload, app.state.private_key)

    return {
        "uuid":            ticket_uuid,
        "pnr":             ticket_pnr,
        "jwt":             jwt,
        "payload_preview": payload,
    }