"""Audit Server - Logs all authentication events (Port 8002)."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import uvicorn
from datetime import datetime
from shared.config import settings
from shared.database import init_db, SessionLocal
from shared.models import AuditLog
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Audit Server")

class AuditEvent(BaseModel):
    event_type: str
    passenger_id: str
    service: str
    status: str
    details: str

class AuditEventResponse(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    passenger_id: str
    service: str
    status: str
    details: str
    
    class Config:
        from_attributes = True

@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    init_db()
    logger.info("Audit Server started on port 8002")

@app.post("/log", response_model=AuditEventResponse)
async def log_event(event: AuditEvent):
    """Log authentication event."""
    try:
        db = SessionLocal()
        audit_log = AuditLog(
            event_type=event.event_type,
            passenger_id=event.passenger_id,
            service=event.service,
            status=event.status,
            details=event.details
        )
        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)
        
        logger.info(f"Logged event: {event.event_type} for {event.passenger_id}")
        
        db.close()
        return audit_log
    except Exception as e:
        logger.error(f"Error logging event: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs/{passenger_id}")
async def get_passenger_logs(passenger_id: str):
    """Get audit logs for a passenger."""
    try:
        db = SessionLocal()
        logs = db.query(AuditLog).filter(AuditLog.passenger_id == passenger_id).all()
        db.close()
        return logs
    except Exception as e:
        logger.error(f"Error fetching logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "audit_server"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.AUDIT_SERVER_PORT)
