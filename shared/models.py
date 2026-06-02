"""ORM models: AuditLog, PassengerChart, IssuedTicket."""
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from datetime import datetime
from shared.database import Base

class AuditLog(Base):
    """Audit log for authentication events."""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String(50))
    passenger_id = Column(String(50))
    service = Column(String(50))
    status = Column(String(20))
    details = Column(Text)

class PassengerChart(Base):
    """Passenger reservation data."""
    __tablename__ = "passenger_charts"
    
    id = Column(Integer, primary_key=True)
    pnr = Column(String(10), unique=True)
    passenger_name = Column(String(100))
    coach = Column(String(10))
    seat_number = Column(String(10))
    train_number = Column(String(10))
    journey_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

class IssuedTicket(Base):
    """Issued and signed tickets."""
    __tablename__ = "issued_tickets"
    
    id = Column(Integer, primary_key=True)
    pnr = Column(String(10), unique=True)
    ticket_hash = Column(String(64))
    signature = Column(Text)
    public_key_version = Column(Integer)
    issued_at = Column(DateTime, default=datetime.utcnow)
    verified = Column(Boolean, default=False)
    verification_count = Column(Integer, default=0)
