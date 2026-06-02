"""Typer CLI: keygen, book, verify, audit, chart."""
import typer
import os
import requests
import json
from pathlib import Path
from shared.config import settings
from shared.crypto_utils import generate_ecdsa_keypair, get_private_key, get_public_key
from cryptography.hazmat.primitives import serialization
from shared.database import SessionLocal
from shared.models import AuditLog, PassengerChart, IssuedTicket

app = typer.Typer(help="Railway Authentication System CLI")

@app.command()
def keygen():
    """Generate ECDSA keypair for signing and verification."""
    try:
        typer.echo("Generating ECDSA keypair...")
        
        # Generate keypair
        private_key = generate_ecdsa_keypair()
        public_key = private_key.public_key()
        
        # Create keys directory if it doesn't exist
        os.makedirs(settings.KEYS_DIR, exist_ok=True)
        
        # Save private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(os.path.join(settings.KEYS_DIR, 'private_key.pem'), 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(os.path.join(settings.KEYS_DIR, 'public_key.pem'), 'wb') as f:
            f.write(public_pem)
        
        typer.echo(f"✓ Keys generated in {settings.KEYS_DIR}/")
        typer.echo(f"  - private_key.pem (GITIGNORED)")
        typer.echo(f"  - public_key.pem (committed)")
    except Exception as e:
        typer.echo(f"✗ Error: {str(e)}", err=True)
        raise typer.Exit(1)

@app.command()
def book(
    pnr: str = typer.Argument(..., help="Passenger Name Record"),
    name: str = typer.Argument(..., help="Passenger name"),
    coach: str = typer.Argument(..., help="Coach number"),
    seat: str = typer.Argument(..., help="Seat number"),
    train: str = typer.Argument(..., help="Train number"),
    date: str = typer.Argument(..., help="Journey date (YYYY-MM-DD)")
):
    """Book a ticket via PRS Booking service."""
    try:
        booking_url = f"http://localhost:{settings.PRS_BOOKING_PORT}/book"
        
        payload = {
            "pnr": pnr,
            "name": name,
            "coach": coach,
            "seat": seat,
            "train": train,
            "date": date
        }
        
        typer.echo(f"Booking ticket for {name}...")
        response = requests.post(booking_url, json=payload)
        
        if response.status_code == 200:
            result = response.json()
            typer.echo(f"✓ Ticket booked successfully!")
            typer.echo(f"  PNR: {result['pnr']}")
            typer.echo(f"  View ticket: {result['ticket_url']}")
        else:
            typer.echo(f"✗ Booking failed: {response.text}", err=True)
            raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ Error: {str(e)}", err=True)
        raise typer.Exit(1)

@app.command()
def verify(
    pnr: str = typer.Argument(..., help="Passenger Name Record"),
    payload: str = typer.Argument(..., help="Encoded payload"),
    signature: str = typer.Argument(..., help="Signature (base64)")
):
    """Verify a ticket signature via HHT Service."""
    try:
        verify_url = f"http://localhost:{settings.HHT_SERVICE_PORT}/verify"
        
        request_data = {
            "pnr": pnr,
            "payload": payload,
            "signature": signature,
            "identity_hash": ""
        }
        
        typer.echo(f"Verifying ticket {pnr}...")
        response = requests.post(verify_url, json=request_data)
        
        if response.status_code == 200:
            result = response.json()
            if result['valid']:
                typer.echo(f"✓ Ticket verified: {result['message']}")
            else:
                typer.echo(f"✗ Ticket invalid: {result['message']}", err=True)
        else:
            typer.echo(f"✗ Verification failed: {response.text}", err=True)
            raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ Error: {str(e)}", err=True)
        raise typer.Exit(1)

@app.command()
def audit(passenger_id: str = typer.Argument(..., help="Passenger ID/PNR")):
    """View audit logs for a passenger."""
    try:
        audit_url = f"http://localhost:{settings.AUDIT_SERVER_PORT}/logs/{passenger_id}"
        
        typer.echo(f"Fetching audit logs for {passenger_id}...")
        response = requests.get(audit_url)
        
        if response.status_code == 200:
            logs = response.json()
            if logs:
                typer.echo(f"\n📋 Audit Logs ({len(logs)} events):\n")
                for log in logs:
                    typer.echo(f"  [{log['event_type']}] {log['timestamp']}")
                    typer.echo(f"    Service: {log['service']}")
                    typer.echo(f"    Status: {log['status']}")
                    typer.echo(f"    Details: {log['details']}\n")
            else:
                typer.echo(f"No audit logs found for {passenger_id}")
        else:
            typer.echo(f"✗ Error fetching logs: {response.text}", err=True)
    except Exception as e:
        typer.echo(f"✗ Error: {str(e)}", err=True)
        raise typer.Exit(1)

@app.command()
def chart():
    """View passenger reservation chart."""
    try:
        db = SessionLocal()
        passengers = db.query(PassengerChart).all()
        
        if passengers:
            typer.echo(f"\n📊 Passenger Chart ({len(passengers)} records):\n")
            for p in passengers:
                typer.echo(f"  PNR: {p.pnr} | {p.passenger_name}")
                typer.echo(f"    Coach: {p.coach}, Seat: {p.seat_number}")
                typer.echo(f"    Train: {p.train_number} | Date: {p.journey_date}\n")
        else:
            typer.echo("No passenger records found")
        
        db.close()
    except Exception as e:
        typer.echo(f"✗ Error: {str(e)}", err=True)
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
