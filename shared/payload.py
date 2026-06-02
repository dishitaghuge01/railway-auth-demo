"""Payload builder, JWT assemble/parse."""
import jwt
import json
import base64
from datetime import datetime, timedelta
from shared.crypto_utils import compute_identity_hash
from shared.config import settings

class PayloadBuilder:
    """Build passenger payload for signing."""
    
    @staticmethod
    def create_ticket_payload(passenger_data: dict) -> dict:
        """Create ticket payload from passenger data."""
        return {
            'pnr': passenger_data.get('pnr'),
            'name': passenger_data.get('name'),
            'coach': passenger_data.get('coach'),
            'seat': passenger_data.get('seat'),
            'train': passenger_data.get('train'),
            'date': passenger_data.get('date'),
            'identity_hash': compute_identity_hash(json.dumps(passenger_data, sort_keys=True)),
            'issued_at': datetime.utcnow().isoformat(),
        }

def create_jwt(payload: dict, private_key, algorithm='HS256', secret=None) -> str:
    """Create JWT token."""
    payload['exp'] = datetime.utcnow() + timedelta(days=365)
    return jwt.encode(payload, secret or 'secret', algorithm=algorithm)

def parse_jwt(token: str, secret=None) -> dict:
    """Parse JWT token."""
    try:
        return jwt.decode(token, secret or 'secret', algorithms=['HS256', 'HS512'])
    except jwt.InvalidTokenError:
        return None

def encode_payload_b64(payload: dict) -> str:
    """Encode payload to base64."""
    json_bytes = json.dumps(payload).encode('utf-8')
    return base64.b64encode(json_bytes).decode('utf-8')

def decode_payload_b64(encoded: str) -> dict:
    """Decode payload from base64."""
    try:
        json_bytes = base64.b64decode(encoded.encode('utf-8'))
        return json.loads(json_bytes.decode('utf-8'))
    except:
        return None
