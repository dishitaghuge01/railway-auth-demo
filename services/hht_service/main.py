"""HHT Service - Verifies ticket signatures (Port 8003)."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import base64
import os
from shared.config import settings
from shared.crypto_utils import get_public_key, verify_signature
from shared.payload import decode_payload_b64
from shared.database import init_db, SessionLocal
from shared.models import IssuedTicket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="HHT Service")

class TicketVerificationRequest(BaseModel):
    pnr: str
    payload: str
    signature: str
    identity_hash: str

class VerificationResult(BaseModel):
    pnr: str
    valid: bool
    message: str
    identity_hash: str

@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    init_db()
    logger.info("HHT Service started on port 8003")

@app.post("/verify", response_model=VerificationResult)
async def verify_ticket(request: TicketVerificationRequest):
    """Verify ticket signature."""
    try:
        # Get public key
        public_key = get_public_key()
        if not public_key:
            raise HTTPException(status_code=500, detail="Public key not found")
        
        # Decode payload and signature
        payload_bytes = request.payload.encode('utf-8')
        signature_bytes = base64.b64decode(request.signature)
        
        # Verify signature
        is_valid = verify_signature(payload_bytes, signature_bytes, public_key)
        
        if is_valid:
            # Update ticket verification count
            db = SessionLocal()
            ticket = db.query(IssuedTicket).filter(IssuedTicket.pnr == request.pnr).first()
            if ticket:
                ticket.verified = True
                ticket.verification_count += 1
                db.commit()
            db.close()
            
            logger.info(f"Verified ticket for PNR: {request.pnr}")
            return VerificationResult(
                pnr=request.pnr,
                valid=True,
                message="Signature valid. Ticket authenticated.",
                identity_hash=request.identity_hash
            )
        else:
            logger.warning(f"Failed verification for PNR: {request.pnr}")
            return VerificationResult(
                pnr=request.pnr,
                valid=False,
                message="Signature invalid. Ticket authentication failed.",
                identity_hash=request.identity_hash
            )
    except Exception as e:
        logger.error(f"Error verifying ticket: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "hht_service"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.HHT_SERVICE_PORT)
