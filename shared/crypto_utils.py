"""ECDSA sign/verify and identity hash utilities."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import hashlib
import os
from shared.config import settings

def generate_ecdsa_keypair():
    """Generate ECDSA P-256 keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key

def load_private_key(pem_data):
    """Load private key from PEM bytes."""
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())

def load_public_key(pem_data):
    """Load public key from PEM bytes."""
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

def sign_data(data: bytes, private_key) -> bytes:
    """Sign data with ECDSA private key."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """Verify ECDSA signature."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

def compute_identity_hash(passenger_data: str) -> str:
    """Compute identity hash from passenger data."""
    return hashlib.sha256(passenger_data.encode()).hexdigest()

def get_private_key():
    """Load private key from file."""
    key_path = os.path.join(settings.KEYS_DIR, 'private_key.pem')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return load_private_key(f.read())
    return None

def get_public_key():
    """Load public key from file."""
    key_path = os.path.join(settings.KEYS_DIR, 'public_key.pem')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return load_public_key(f.read())
    return None
