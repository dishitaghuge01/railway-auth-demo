# Railway Authentication Demo

A distributed multi-service authentication system simulating Railway Reservation System with ECDSA-based ticket signing, audit logging, and key rotation.

## Architecture

Four microservices coordinate to issue and verify digitally signed railway tickets:

- **CRIS Signer** (Port 8001): Signs passenger data with private key
- **Audit Server** (Port 8002): Logs all authentication events
- **HHT Service** (Port 8003): Verifies ticket signatures
- **PRS Booking** (Port 8000): Web interface for booking and viewing tickets

## Setup

### Prerequisites
- Python 3.9+
- pip
- honcho (for process management)

### Installation

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Generate Keys

```bash
python -m cli.main keygen
```

This generates:
- `keys/private_key.pem` - Signing key (GITIGNORED)
- `keys/public_key.pem` - Verification key

### Run Services

```bash
honcho start
```

This starts all 4 services simultaneously.

## File Structure

- `keys/` - Cryptographic keys for signing/verification
- `db/` - SQLite database (runtime artifact)
- `tickets/` - Generated ticket PNGs and JSON data
- `shared/` - Common utilities shared across services
- `services/` - Microservices
- `cli/` - Command-line interface for operations
