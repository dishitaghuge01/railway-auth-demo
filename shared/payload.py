import json
import time
import uuid as uuid_lib
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
    passengers: list[dict],
) -> dict:
    """
    Constructs the full payload dict exactly matching the proposal schema.

    passengers: list of dicts with keys: name, berth, aadhaar (optional), dob (optional)

    Validity windows per spec:
      Reserved / Tatkal : vf = departure - 2h,  vu = arrival + 4h
      Unreserved        : vf = departure - 1h,  vu = arrival + 6h
    """
    now = int(time.time())

    if ticket_type == "U":
        vf = departure_unix - 3600
        vu = arrival_unix  + 21600
    else:
        vf = departure_unix - 7200
        vu = arrival_unix  + 14400

    pax = []
    for p in passengers:
        aadhaar = p.get("aadhaar")
        dob     = p.get("dob")
        berth   = p.get("berth")

        # Identity hash only when both aadhaar and dob are provided
        # and class warrants it (AC / Tatkal). For SL without aadhaar → null.
        id_hash = None
        if aadhaar and dob:
            id_hash = compute_identity_hash(aadhaar, dob)

        # Unreserved: berth and id are null per spec
        if ticket_type == "U":
            berth   = None
            id_hash = None

        pax.append({"b": berth, "id": id_hash})

    return {
        "v":     1,
        "type":  ticket_type,
        "uuid":  uuid,
        "train": train,
        "from":  from_stn,
        "to":    to_stn,
        "class": ticket_class,
        "date":  travel_date,
        "vf":    vf,
        "vu":    vu,
        "iat":   now,
        "pax":   pax,
    }


def assemble_jwt(payload_dict: dict, private_key: Any) -> str:
    """
    Compact JSON → UTF-8 bytes → base64url (no padding) → sign.
    Returns '<payload_b64url>.<sig_b64url>'
    """
    payload_json  = json.dumps(payload_dict, sort_keys=False, separators=(",", ":"))
    payload_bytes = payload_json.encode("utf-8")
    payload_b64   = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
    sig_b64       = sign_payload(payload_bytes, private_key)
    return f"{payload_b64}.{sig_b64}"


def parse_jwt(jwt_str: str) -> tuple[dict, bytes, str]:
    """
    Splits '<payload_b64url>.<sig_b64url>'.
    Returns (payload_dict, raw_payload_bytes, sig_b64url).
    raw_payload_bytes are the exact bytes that were signed — used for verification.
    Raises ValueError on any malformed input.
    """
    parts = jwt_str.strip().split(".")
    if len(parts) != 2:
        raise ValueError(f"Expected exactly one '.' separator, got {len(parts) - 1}")

    payload_b64, sig_b64 = parts

    try:
        padding         = "=" * (-len(payload_b64) % 4)
        raw_bytes       = base64.urlsafe_b64decode(payload_b64 + padding)
        payload_dict    = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to decode payload segment: {e}")

    return payload_dict, raw_bytes, sig_b64