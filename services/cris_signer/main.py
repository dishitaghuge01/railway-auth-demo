import os
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from shared.config import settings
from shared.crypto_utils import load_private_key, get_public_key_fingerprint
from shared.payload import build_payload, assemble_jwt

app = FastAPI(title="CRIS Signing Service")

# Request Model
class SignRequest(BaseModel):
    ticket_type: str
    uuid: str
    pnr: str
    train: str
    from_stn: str
    to_stn: str
    ticket_class: str
    travel_date: str
    departure_unix: int
    arrival_unix: int
    passengers: list[dict]

@app.on_event("startup")
def startup_event():
    key_path = os.path.join("keys", "private_key.pem")
    if not os.path.exists(key_path):
        print(f"\n[!] Error: Key file missing at {key_path}")
        print("Run 'python -m cli keygen' first\n")
        os._exit(1)
    
    app.state.private_key = load_private_key(key_path)
    # Read public key to provide fingerprint
    pub_key_path = os.path.join("keys", "public_key.pem")
    with open(pub_key_path, "rb") as f:
        app.state.public_key_pem = f.read()
    app.state.fingerprint = get_public_key_fingerprint(app.state.public_key_pem)

@app.post("/sign")
def sign_ticket(req: SignRequest):
    payload = build_payload(
        req.ticket_type, req.uuid, req.train, req.from_stn, req.to_stn,
        req.ticket_class, req.travel_date, req.departure_unix, 
        req.arrival_unix, req.passengers
    )
    jwt = assemble_jwt(payload, app.state.private_key)
    return {"uuid": req.uuid, "pnr": req.pnr, "jwt": jwt}

@app.get("/public-key")
def get_public_key():
    return {
        "current_public_key": app.state.public_key_pem.decode(),
        "fingerprint": app.state.fingerprint
    }

@app.get("/health")
def health():
    return {"status": "ok", "key_loaded": hasattr(app.state, "private_key")}