"""CRIS Signer Service - Signs passenger data with private key (Port 8001)."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import os
import base64
from shared.config import settings
from shared.crypto_utils import get_private_key, sign_data, compute_identity_hash
from shared.payload import PayloadBuilder, encode_payload_b64
from shared.database import init_db
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CRIS Signer Service")

class PassengerData(BaseModel):
    pnr: str
    name: str
    coach: str
    seat: str
    train: str
    date: str

class SignedTicket(BaseModel):
    pnr: str
    payload: str
    signature: str
    identity_hash: str

@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    init_db()
    logger.info("CRIS Signer Service started on port 8001")

@app.post("/sign", response_model=SignedTicket)
async def sign_ticket(passenger: PassengerData):
    """Sign passenger data and return signature."""
    try:
        # Get private key
        private_key = get_private_key()
        if not private_key:
            raise HTTPException(status_code=500, detail="Private key not found")
        
        # Create payload
        payload_dict = PayloadBuilder.create_ticket_payload(passenger.dict())
        payload_b64 = encode_payload_b64(payload_dict)
        
        # Sign the payload
        payload_bytes = payload_b64.encode('utf-8')
        signature_bytes = sign_data(payload_bytes, private_key)
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
        
        identity_hash = compute_identity_hash(passenger.json())
        
        logger.info(f"Signed ticket for PNR: {passenger.pnr}")
        
        return SignedTicket(
            pnr=passenger.pnr,
            payload=payload_b64,
            signature=signature_b64,
            identity_hash=identity_hash
        )
    except Exception as e:
        logger.error(f"Error signing ticket: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "cris_signer"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.CRIS_SIGNER_PORT)
