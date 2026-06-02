"""PRS Booking Service - Web interface for booking and viewing tickets (Port 8000)."""
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
import requests
import json
import os
from shared.config import settings
from shared.database import init_db, SessionLocal
from shared.models import PassengerChart, IssuedTicket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="PRS Booking Service")

class BookingRequest(BaseModel):
    pnr: str
    name: str
    coach: str
    seat: str
    train: str
    date: str

class BookingResponse(BaseModel):
    pnr: str
    status: str
    ticket_url: str

@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    init_db()
    logger.info("PRS Booking Service started on port 8000")

@app.post("/book", response_model=BookingResponse)
async def book_ticket(booking: BookingRequest):
    """Book a ticket and request signature from CRIS Signer."""
    try:
        # Save passenger data
        db = SessionLocal()
        passenger = PassengerChart(
            pnr=booking.pnr,
            passenger_name=booking.name,
            coach=booking.coach,
            seat_number=booking.seat,
            train_number=booking.train,
            journey_date=booking.date
        )
        db.add(passenger)
        db.commit()
        
        # Request signature from CRIS Signer
        signer_url = f"http://localhost:{settings.CRIS_SIGNER_PORT}/sign"
        response = requests.post(signer_url, json=booking.dict())
        
        if response.status_code == 200:
            signed_ticket = response.json()
            
            # Store issued ticket
            ticket = IssuedTicket(
                pnr=booking.pnr,
                ticket_hash=signed_ticket['identity_hash'],
                signature=signed_ticket['signature'],
                public_key_version=1
            )
            db.add(ticket)
            db.commit()
            
            logger.info(f"Booked ticket for PNR: {booking.pnr}")
            
            db.close()
            return BookingResponse(
                pnr=booking.pnr,
                status="success",
                ticket_url=f"/ticket/{booking.pnr}"
            )
        else:
            db.close()
            raise HTTPException(status_code=500, detail="Failed to sign ticket")
    except Exception as e:
        logger.error(f"Error booking ticket: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ticket/{pnr}", response_class=HTMLResponse)
async def view_ticket(pnr: str):
    """View ticket as HTML page with QR code."""
    try:
        db = SessionLocal()
        passenger = db.query(PassengerChart).filter(PassengerChart.pnr == pnr).first()
        ticket = db.query(IssuedTicket).filter(IssuedTicket.pnr == pnr).first()
        db.close()
        
        if not passenger or not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found")
        
        # Load ticket HTML template
        template_path = os.path.join(os.path.dirname(__file__), 'templates', 'ticket.html')
        with open(template_path, 'r') as f:
            template = f.read()
        
        # Replace placeholders
        html = template.format(
            pnr=pnr,
            name=passenger.passenger_name,
            coach=passenger.coach,
            seat=passenger.seat_number,
            train=passenger.train_number,
            date=passenger.journey_date
        )
        
        return html
    except Exception as e:
        logger.error(f"Error viewing ticket: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "prs_booking"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.PRS_BOOKING_PORT)
