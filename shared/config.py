"""Configuration module - reads .env and exposes settings object."""
import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    """Application settings from environment variables."""
    CRIS_SIGNER_PORT = int(os.getenv('CRIS_SIGNER_PORT', 8001))
    AUDIT_SERVER_PORT = int(os.getenv('AUDIT_SERVER_PORT', 8002))
    HHT_SERVICE_PORT = int(os.getenv('HHT_SERVICE_PORT', 8003))
    PRS_BOOKING_PORT = int(os.getenv('PRS_BOOKING_PORT', 8000))
    
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./db/railway.db')
    
    KEY_ROTATION_ENABLED = os.getenv('KEY_ROTATION_ENABLED', 'true').lower() == 'true'
    KEY_ROTATION_DAYS = int(os.getenv('KEY_ROTATION_DAYS', 30))
    
    KEYS_DIR = os.getenv('KEYS_DIR', './keys')
    TICKETS_DIR = os.getenv('TICKETS_DIR', './tickets')
    DB_DIR = os.getenv('DB_DIR', './db')

settings = Settings()
