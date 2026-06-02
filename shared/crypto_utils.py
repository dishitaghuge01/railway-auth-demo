import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def generate_keypair() -> tuple[bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign_payload(payload_bytes: bytes, private_key) -> str:
    signature = private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

def verify_signature(payload_bytes: bytes, sig_b64url: str, public_key) -> bool:
    try:
        sig_bytes = base64.urlsafe_b64decode(sig_b64url + "==")
        public_key.verify(sig_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False

def compute_identity_hash(aadhaar: str, dob: str) -> str:
    # Per instructions: SHA256 with pipe separator, lowercase hex
    data = f"{aadhaar.strip()}|{dob}"
    return hashlib.sha256(data.encode()).hexdigest()

def get_public_key_fingerprint(public_key_pem: bytes) -> str:
    # First 16 hex characters of SHA256 hash of the PEM bytes
    full_hash = hashlib.sha256(public_key_pem).hexdigest()
    return full_hash[:16]

