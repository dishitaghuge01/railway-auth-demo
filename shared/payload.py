import json
import time
import base64
from typing import Any
from shared.crypto_utils import sign_payload, compute_identity_hash

def build_payload(
    ticket_type: str,
    uuid: str,
    train: str,
    from_stn: str,
    to_stn: str,
    ticket_class: str,
    travel_date: str,
    departure_unix: int,
    arrival_unix: int,
    passengers: list[dict]
) -> dict:
    """Constructs the payload dictionary with identity hashing and timing metadata."""
    now = int(time.time())
    
    # Process passengers: compute identity hash and remove raw PII
    processed_passengers = []
    for p in passengers:
        p_copy = p.copy()
        if "aadhaar" in p_copy and "dob" in p_copy:
            p_copy["id_hash"] = compute_identity_hash(p_copy.pop("aadhaar"), p_copy.pop("dob"))
        processed_passengers.append(p_copy)

    return {
        "ticket_type": ticket_type,
        "uuid": uuid,
        "train": train,
        "from_stn": from_stn,
        "to_stn": to_stn,
        "ticket_class": ticket_class,
        "travel_date": travel_date,
        "departure": departure_unix,
        "arrival": arrival_unix,
        "passengers": processed_passengers,
        "iat": now,
        "vf": now,                # Valid From: immediate
        "vu": arrival_unix + 86400 # Valid Until: arrival + 24hrs
    }

def assemble_jwt(payload_dict: dict, private_key: Any) -> str:
    """Assembles and signs a compact JWT (Payload.Signature)."""
    # Compact JSON serialization: no spaces
    payload_json = json.dumps(payload_dict, sort_keys=False, separators=(',', ':'))
    payload_bytes = payload_json.encode('utf-8')
    
    # Base64url encode (no padding)
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode('utf-8').rstrip('=')
    
    # Sign
    sig_b64 = sign_payload(payload_bytes, private_key)
    
    return f"{payload_b64}.{sig_b64}"

def parse_jwt(jwt_str: str) -> tuple[dict, bytes, str]:
    """Splits, decodes, and returns payload, raw bytes, and signature."""
    try:
        parts = jwt_str.split('.')
        if len(parts) != 2:
            raise ValueError("Malformed JWT: expected exactly one dot separator")
            
        payload_b64, sig_b64 = parts
        
        # Add back padding for base64 decoding
        padding = '=' * (-len(payload_b64) % 4)
        raw_payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        
        payload_dict = json.loads(raw_payload_bytes.decode('utf-8'))
        return payload_dict, raw_payload_bytes, sig_b64
    except Exception as e:
        raise ValueError(f"Failed to parse JWT: {e}")

