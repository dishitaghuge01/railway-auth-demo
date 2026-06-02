# Railway Ticket Authentication & Anti-Forgery Demo

A working demonstration of a cryptographic authentication framework for printed railway tickets, built as a proof-of-concept for the proposed *Cryptographic Authentication and Anti-Forgery Framework for Printed Indian Railway Tickets*.

This system proves that fabricating a ticket is mathematically impossible, duplication is detectable with or without a network connection, and the verification process fits inside the time a TTE currently spends on a single manual check.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Properties Demonstrated](#security-properties-demonstrated)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [First-Time Setup](#first-time-setup)
- [Starting the Services](#starting-the-services)
- [Using the CLI](#using-the-cli)
- [Full Demo Walkthrough](#full-demo-walkthrough)
- [Attack Scenarios](#attack-scenarios)
- [JWT Format](#jwt-format)
- [Payload Schema](#payload-schema)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Viewing Tickets on Your Phone](#viewing-tickets-on-your-phone)
- [Troubleshooting](#troubleshooting)

---

## Overview

Indian Railways issues approximately 12 million tickets per day. Current QR codes on printed tickets encode plain text with no digital signature — anyone with a QR generator and a printer can produce a visually identical fake ticket.

This demo implements a layered security framework:

1. **Cryptographic signing** — every ticket is signed with ECDSA P-256 at issuance. Modifying any field in the ticket data, even a single character, produces a completely different signature that fails verification instantly.
2. **Duplicate detection** — every scan is logged to a central audit server with the ticket's UUID. If the same UUID is scanned more than once, both events are flagged automatically.
3. **Identity verification** — AC and Tatkal tickets store a one-way SHA-256 hash of the passenger's Aadhaar number and date of birth. The TTE can verify identity on-device without any network connection. The raw Aadhaar number is never stored anywhere.
4. **Offline-capable verification** — the TTE's HHT (Hand Held Terminal) service verifies signatures using an embedded public key, with no internet connection required for the cryptographic check.

---

## Architecture

Four independent microservices communicate over HTTP, mirroring the real distributed system:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Local Machine                            │
│                                                                 │
│  ┌─────────────────┐   ┌─────────────────┐                     │
│  │  CRIS Signing   │   │  Audit Server   │                     │
│  │  Service :8001  │   │  Service :8002  │                     │
│  │                 │   │                 │                     │
│  │ Holds private   │   │ Logs every      │                     │
│  │ key (HSM sim)   │   │ scan, detects   │                     │
│  │ Signs tickets   │   │ duplicate UUIDs │                     │
│  └────────┬────────┘   └────────┬────────┘                     │
│           │                     │                              │
│  ┌────────▼────────┐   ┌────────▼────────┐                     │
│  │  PRS Booking    │   │  HHT Service    │                     │
│  │  Service :8000  │   │  Service :8003  │                     │
│  │                 │   │                 │                     │
│  │ Books tickets   │   │ TTE verification│                     │
│  │ Serves QR page  │   │ Chart lookup    │                     │
│  │ Phone-viewable  │   │ Identity check  │                     │
│  └─────────────────┘   └─────────────────┘                     │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 CLI Tool (python -m cli)                  │   │
│  │  keygen · book · verify · audit · chart · clone · forge  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│                    Shared SQLite Database                       │
│              db/railway.db  (issued_tickets,                    │
│              passenger_chart, audit_log)                        │
└─────────────────────────────────────────────────────────────────┘
          │  HTTP (same LAN)
          ▼
┌─────────────────────┐
│     Phone Browser   │
│  Scan QR → VALID /  │
│  view ticket page   │
└─────────────────────┘
```

### Service Responsibilities

| Service | Port | Real-world Equivalent | Key Responsibility |
|---|---|---|---|
| CRIS Signing Service | 8001 | CRIS HSM microservice | Signs ticket payloads. Only service with access to the private key. |
| Audit Server | 8002 | CRIS central audit server | Logs every verification event. Detects duplicate UUID scans. |
| HHT Service | 8003 | TTE Hand Held Terminal | Verifies JWT signatures, checks passenger chart, runs identity verification. |
| PRS Booking Service | 8000 | IRCTC / PRS counter | Books tickets, calls CRIS signer, serves phone-viewable ticket page with QR. |

---

## Security Properties Demonstrated

| Property | Mechanism | Demo Command |
|---|---|---|
| Forged ticket detection | ECDSA signature fails when any payload field is modified | `python -m cli forge` |
| Cloned ticket detection | Duplicate UUID flagged in audit log on second scan | `python -m cli clone` |
| Expired ticket rejection | Validity window checked against current time | Book with past date |
| Wrong train rejection | Train field in JWT compared against TTE's expected train | `--train` mismatch |
| Identity verification | SHA-256 hash of Aadhaar+DOB compared on-device | `--aadhaar` flag |
| Key rotation support | HHT loads both current and previous public key | `python -m cli keygen` |

---

## Prerequisites

### System Dependencies

**Ubuntu / Debian:**
```bash
sudo apt install libzbar0 python3.11 python3-pip git
```

**Arch Linux:**
```bash
sudo pacman -S zbar python git
```

**macOS:**
```bash
brew install zbar python@3.11 git
```

`libzbar` / `zbar` is required by `pyzbar` for decoding QR codes from image files (used by `python -m cli verify --image`). Without it, image-based verification won't work but all other features will.

### Python Version

Python 3.11 or 3.12 is recommended. Python 3.14 requires upgraded versions of SQLAlchemy and Typer:

```bash
pip install --upgrade sqlalchemy typer
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/railway-auth-demo.git
cd railway-auth-demo

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows

# Install all dependencies
pip install -r requirements.txt
```

---

## First-Time Setup

### 1. Generate Cryptographic Keys

```bash
python -m cli keygen
```

This generates an ECDSA P-256 keypair and writes two files:

- `keys/private_key.pem` — chmod 600, simulates the HSM. **Never share or commit this file.**
- `keys/public_key.pem` — embedded in the HHT service at startup for verification.

The private key never leaves the CRIS Signing Service. No other service or CLI command reads it.

Sample output:
```
  Generating ECDSA P-256 keypair...

  ✓ Keypair generated successfully.

  Private key  : keys/private_key.pem  (permissions: 600)
  Public key   : keys/public_key.pem

  Public key fingerprint: a3f2e1c9d2b4f5e6

  ⚠  The private key is stored locally and simulates an HSM.
     In production it would never exist as a file.
```

### 2. Initialise the Database

The database is created automatically when any service starts for the first time. No manual step needed.

---

## Starting the Services

All four services start with one command using Honcho:

```bash
honcho start
```

Expected output:
```
22:54:25 cris_signer.1  | ✓ CRIS Signer ready — key fingerprint: a3f2e1c9d2b4f5e6
22:54:25 audit_server.1 | ✓ Database initialized at db/railway.db
22:54:25 hht_service.1  | ✓ HHT Service ready — public key loaded from keys/public_key.pem
22:54:25 prs_booking.1  | ✓ PRS Booking Service ready
```

To start services individually for debugging:

```bash
uvicorn services.cris_signer.main:app  --port 8001 --reload
uvicorn services.audit_server.main:app --port 8002 --reload
uvicorn services.hht_service.main:app  --port 8003 --reload
uvicorn services.prs_booking.main:app  --port 8000 --reload
```

### Health Checks

```bash
curl http://localhost:8000/health   # PRS Booking
curl http://localhost:8001/health   # CRIS Signer
curl http://localhost:8002/health   # Audit Server
curl http://localhost:8003/health   # HHT Service
```

Each returns `{"status": "ok"}` when running correctly.

### Interactive API Docs

FastAPI provides automatic interactive documentation for every service:

| Service | Docs URL |
|---|---|
| PRS Booking | http://localhost:8000/docs |
| CRIS Signer | http://localhost:8001/docs |
| Audit Server | http://localhost:8002/docs |
| HHT Service | http://localhost:8003/docs |

---

## Using the CLI

All CLI commands are run as:

```bash
python -m cli <command> [options]
```

### `keygen` — Generate cryptographic keys

```bash
python -m cli keygen
python -m cli keygen --force    # skip confirmation prompt
```

Run once before starting services. Re-running rotates keys: the current public key moves to `old_public_key.pem` and a new pair is generated. The HHT service loads both keys so tickets issued just before rotation remain verifiable.

---

### `book` — Book a ticket

**Interactive mode:**
```bash
python -m cli book
```
Prompts for all fields one by one, including optional Aadhaar for identity verification.

**JSON mode (for scripting and demos):**
```bash
python -m cli book --json demo_booking.json
```

Example `demo_booking.json`:
```json
{
  "ticket_type":    "R",
  "train":          "12051",
  "from_stn":       "CSMT",
  "to_stn":         "NDLS",
  "ticket_class":   "3A",
  "travel_date":    "2026-06-02",
  "departure_time": "06:00",
  "arrival_time":   "10:00",
  "passengers": [
    {
      "name":    "Rajan Kumar",
      "berth":   "B2/14",
      "aadhaar": "123456789012",
      "dob":     "1990-05-10"
    },
    {
      "name":  "Priya Kumar",
      "berth": "B2/15"
    }
  ]
}
```

Valid values:
- `ticket_type`: `R` (Reserved), `U` (Unreserved), `T` (Tatkal)
- `ticket_class`: `1A`, `2A`, `3A`, `SL`, `UR`
- `travel_date`: `YYYY-MM-DD` — must be today or a future date for `VALID` verification result
- `departure_time` / `arrival_time`: `HH:MM` in 24-hour format. Overnight journeys (arrival earlier than departure) are handled automatically.

Output:
```
  ── BOOKING CONFIRMED ──────────────────────────────
  PNR                   PNR8472910
  UUID                  550e8400-e29b-41d4-a716-446655440000
  Ticket URL            http://192.168.1.42:8000/ticket/PNR8472910
  QR URL                http://192.168.1.42:8000/ticket/PNR8472910/qr
```

---

### `verify` — Verify a ticket (TTE simulation)

Three input modes — provide exactly one:

**By PNR** (fetches JWT from PRS service automatically):
```bash
python -m cli verify --pnr PNR8472910 --tte TTE-MUM-047 --train 12051
```

**By raw JWT string:**
```bash
python -m cli verify --jwt "eyJ....<sig>" --tte TTE-MUM-047 --train 12051
```

**By QR image file** (decodes QR using pyzbar, simulates TTE scanning physical ticket):
```bash
python -m cli verify --image tickets/<uuid>_qr.png --tte TTE-MUM-047 --train 12051
```

**With identity check** (prompts for Aadhaar+DOB for each passenger that has a stored hash):
```bash
python -m cli verify --pnr PNR8472910 --tte TTE-MUM-047 --train 12051 --aadhaar
```

Possible results:

| Result | Meaning |
|---|---|
| `VALID` | Signature valid, ticket not expired, train matches, PNR in chart |
| `FORGED` | ECDSA signature failed — payload was tampered with |
| `DUPLICATE` | Valid ticket but UUID was already scanned — possible clone attack |
| `EXPIRED` | Current time is past the ticket's validity window |
| `NOT_YET_VALID` | Current time is before the ticket's validity window opens |
| `WRONG_TRAIN` | Train number in JWT does not match `--train` argument |
| `WRONG_DATE` | Travel date in JWT does not match today's date |
| `INVALID_PNR` | JWT is valid but PNR not found in passenger chart |

---

### `audit` — Audit server commands

```bash
# Summary statistics
python -m cli audit stats

# List all duplicate scan events
python -m cli audit duplicates

# Full event timeline for a specific UUID
python -m cli audit log <uuid>
```

---

### `chart` — Passenger chart commands

```bash
# Show full chart for a train and date
python -m cli chart show --train 12051 --date 2026-06-02

# Clear chart (simulates end-of-journey wipe)
python -m cli chart clear --train 12051 --date 2026-06-02
```

---

### `clone` — Demo attack: ticket cloning

```bash
python -m cli clone --pnr PNR8472910
```

Fetches the JWT of a real ticket and generates a new QR image containing the **identical JWT** — same UUID, same valid signature. Saved to `tickets/CLONED_PNR8472910_qr.png`.

When the clone is scanned after the original, the audit server detects the duplicate UUID and flags both events.

---

### `forge` — Demo attack: ticket forgery

```bash
python -m cli forge --pnr PNR8472910 --field class --value 1A
```

Modifies a field in the ticket payload and re-encodes it **without re-signing**. The original signature is kept but it now covers different bytes, so signature verification fails immediately.

Forgeable fields: `class`, `date`, `from`, `to`, `train`

Examples:
```bash
python -m cli forge --pnr PNR8472910 --field class --value 1A    # upgrade class
python -m cli forge --pnr PNR8472910 --field date  --value 2026-12-25  # change date
python -m cli forge --pnr PNR8472910 --field from  --value NDLS  # change origin
```

Saved to `tickets/FORGED_<PNR>_<field>_qr.png`.

---

## Full Demo Walkthrough

Run these commands in sequence to demonstrate all security features to your guide.

### Step 1 — Start services
```bash
honcho start
```

### Step 2 — Book a legitimate ticket
```bash
python -m cli book --json demo_booking.json
# Note the PNR printed in output, e.g. PNR8472910
```

### Step 3 — View ticket on phone
Open the printed Ticket URL on your phone browser (same WiFi network). The page shows all ticket details and a scannable QR code. Scan it with your phone camera — it will display the raw JWT string, proving the cryptographic data is embedded directly in the QR.

### Step 4 — Verify the legitimate ticket (TTE check)
```bash
python -m cli verify --pnr PNR8472910 --tte TTE-MUM-047 --train 12051
# Expected: VALID, Signature ✓, Chart Match ✓, Duplicate ✓ NO
```

### Step 5 — Clone attack
```bash
# Create clone
python -m cli clone --pnr PNR8472910

# Verify original again (still valid)
python -m cli verify --pnr PNR8472910 --tte TTE-MUM-047 --train 12051

# Verify clone — different TTE, same train
python -m cli verify --image tickets/CLONED_PNR8472910_qr.png --tte TTE-MUM-099 --train 12051
# Expected: DUPLICATE — audit server flagged the second UUID scan
```

### Step 6 — Check audit log
```bash
python -m cli audit duplicates
# Shows the UUID, both scan events, TTE IDs, timestamps
```

### Step 7 — Forge attack
```bash
# Attacker upgrades class from 3A to 1A
python -m cli forge --pnr PNR8472910 --field class --value 1A

# TTE scans the forged ticket
python -m cli verify --image tickets/FORGED_PNR8472910_class_qr.png --tte TTE-MUM-047 --train 12051
# Expected: FORGED — signature verification fails instantly
```

### Step 8 — Identity verification
```bash
# Book a ticket with Aadhaar
python -m cli book
# Enter Aadhaar: 123456789012, DOB: 1990-05-10 when prompted

# Verify with correct Aadhaar
python -m cli verify --pnr <NEW_PNR> --tte TTE-MUM-047 --train <train> --aadhaar
# Enter correct Aadhaar when prompted → IDENTITY: PASSED

# Verify again with wrong Aadhaar
python -m cli verify --pnr <NEW_PNR> --tte TTE-MUM-047 --train <train> --aadhaar
# Enter wrong Aadhaar → IDENTITY: FAILED
```

### Step 9 — Final stats
```bash
python -m cli audit stats
# Shows counts: valid, forged, duplicate UUIDs, etc.
```

---

## Attack Scenarios

### Attack 1: Forged Ticket (Tampered Fields)

An attacker photographs a legitimate ticket, upgrades the class field in the QR data, and reprints it.

**What happens:** The ECDSA signature covers the exact bytes of the original payload. Changing any field — even one character — produces completely different bytes. The signature no longer matches. The HHT service returns `FORGED` in under 100 milliseconds, no network connection required.

**Why it's impossible to fix:** The attacker would need the private key to produce a valid signature for the modified payload. The private key never leaves the HSM and is never exposed through any API.

### Attack 2: Cloned Ticket (Same QR on Multiple Papers)

An attacker photographs a legitimate QR code and prints it on a second piece of paper. Both tickets have identical, valid signatures.

**What happens:** The first scan passes as `VALID`. The second scan also passes cryptographic verification (the signature is genuine) but the audit server detects the UUID has been seen before and returns `DUPLICATE`. Both scan events are flagged in the audit log with TTE IDs and timestamps for investigation.

**Limitation of this demo:** In the real system, the TTE would need network connectivity to catch this in real time. The audit server's duplicate detection is a background/logging layer. The primary defence against cloning in the full proposal is the physical holographic strip and OVI patch on the paper.

### Attack 3: Identity Impersonation

An attacker clones a ticket from a publicly accessible PNR lookup (NTES shows passenger name and berth for any PNR).

**What happens:** The cloned ticket passes signature verification. However, when the TTE initiates an identity check, the app computes `SHA256(entered_aadhaar + "|" + entered_dob)` and compares it to the hash stored in the JWT. The attacker does not know the original passenger's Aadhaar number, so this check fails. The raw Aadhaar number is never stored anywhere — only the irreversible hash is in the JWT.

---

## JWT Format

This system uses a simplified JWT-inspired format:

```
<base64url(payload_json)>.<base64url(ecdsa_signature)>
```

No header segment is used. This is intentional — omitting the header eliminates the `"alg":"none"` attack surface present in standard JWT libraries and makes the format explicit. The algorithm is always ECDSA P-256 with SHA-256.

The payload JSON is serialized in compact form (no spaces, keys in insertion order) and UTF-8 encoded before signing. The exact bytes are what gets signed and verified — any modification to the JSON, including whitespace, changes the bytes and invalidates the signature.

---

## Payload Schema

```json
{
  "v":     1,
  "type":  "R",
  "uuid":  "550e8400-e29b-41d4-a716-446655440000",
  "train": "12051",
  "from":  "CSMT",
  "to":    "NDLS",
  "class": "3A",
  "date":  "2026-06-02",
  "vf":    1748578200,
  "vu":    1748671800,
  "iat":   1748491800,
  "pax": [
    { "b": "B2/14", "id": "a3f2e1c9d2b4f5e6..." },
    { "b": "B2/15", "id": null }
  ]
}
```

| Field | Description |
|---|---|
| `v` | Schema version, always 1 |
| `type` | `R` = Reserved, `U` = Unreserved, `T` = Tatkal |
| `uuid` | Unique ticket identifier for audit deduplication |
| `train` | Train number |
| `from` / `to` | Station codes |
| `class` | `1A`, `2A`, `3A`, `SL`, or `UR` |
| `date` | Travel date in `YYYY-MM-DD` |
| `vf` | Valid-from Unix timestamp (2 hours before departure for reserved) |
| `vu` | Valid-until Unix timestamp (4 hours after arrival for reserved) |
| `iat` | Issued-at Unix timestamp |
| `pax[].b` | Berth as `CoachNumber/BerthNumber`, null for unreserved |
| `pax[].id` | `SHA256(aadhaar + "\|" + dob)` lowercase hex, null if not provided |

The pipe separator in the identity hash (`aadhaar + "|" + dob`) is not cosmetic — without it, Aadhaar `"123456"` with DOB `"789"` would hash identically to Aadhaar `"1234567"` with DOB `"89"`. The separator eliminates this collision.

---

## API Reference

### PRS Booking Service — port 8000

| Method | Path | Description |
|---|---|---|
| `POST` | `/book` | Book a ticket, returns PNR + ticket URL |
| `GET` | `/ticket/{pnr}` | HTML ticket page, phone-viewable |
| `GET` | `/ticket/{pnr}/qr` | QR code PNG image |
| `GET` | `/ticket/{pnr}/raw` | Full JSON including JWT string |
| `GET` | `/tickets` | List all issued tickets |
| `GET` | `/health` | Health check |

### CRIS Signing Service — port 8001

| Method | Path | Description |
|---|---|---|
| `POST` | `/sign` | Sign a ticket payload, returns JWT + UUID + PNR |
| `GET` | `/public-key` | Current and previous public key PEM + fingerprint |
| `GET` | `/health` | Health check |

### Audit Server — port 8002

| Method | Path | Description |
|---|---|---|
| `POST` | `/log` | Log a verification event, returns `is_duplicate` |
| `GET` | `/duplicates` | All flagged duplicate UUID events |
| `GET` | `/log/{uuid}` | All events for a specific UUID |
| `GET` | `/stats` | Aggregate counts by result type |
| `GET` | `/health` | Health check |

### HHT Service — port 8003

| Method | Path | Description |
|---|---|---|
| `POST` | `/verify` | Full ticket verification pipeline |
| `POST` | `/chart/add` | Add passengers to the chart |
| `GET` | `/chart/{train}/{date}` | View chart for a train and date |
| `DELETE` | `/chart/{train}/{date}` | Clear chart (end-of-journey) |
| `GET` | `/health` | Health check |

---

## Project Structure

```
railway-auth-demo/
├── .env                          # Service ports, paths, URLs
├── .gitignore                    # Private keys and DB excluded
├── Procfile                      # honcho: starts all 4 services
├── requirements.txt
├── README.md
│
├── keys/
│   ├── private_key.pem           # GITIGNORED — simulated HSM private key
│   ├── public_key.pem            # Embedded in HHT service at startup
│   └── old_public_key.pem        # Previous key, kept for rotation grace window
│
├── db/
│   └── railway.db                # SQLite — GITIGNORED, created at first run
│
├── tickets/                      # GITIGNORED — generated QR PNG files
│
├── shared/                       # Code shared by all services
│   ├── config.py                 # Settings from .env
│   ├── database.py               # SQLAlchemy engine, session, init_db()
│   ├── models.py                 # ORM: IssuedTicket, PassengerChart, AuditLog
│   ├── crypto_utils.py           # ECDSA sign/verify, identity hash
│   └── payload.py                # Payload builder, JWT assemble/parse
│
├── services/
│   ├── cris_signer/main.py       # Port 8001 — signing microservice
│   ├── audit_server/main.py      # Port 8002 — audit and dedup
│   ├── hht_service/main.py       # Port 8003 — TTE verification
│   └── prs_booking/
│       ├── main.py               # Port 8000 — booking and ticket serving
│       └── templates/
│           └── ticket.html       # Phone-viewable ticket page
│
└── cli/
    ├── __init__.py
    ├── __main__.py               # Entry point for python -m cli
    └── main.py                   # All CLI commands
```

---

## Viewing Tickets on Your Phone

When the PRS service starts it binds to `127.0.0.1:8000` by default. To make it accessible on your phone over the same WiFi network, start it bound to `0.0.0.0`:

```bash
# Edit Procfile, change the prs_booking line to:
prs_booking: uvicorn services.prs_booking.main:app --host 0.0.0.0 --port 8000 --reload
```

Then find your machine's local IP:
```bash
ip addr show | grep "inet " | grep -v 127    # Linux
ipconfig getifaddr en0                        # macOS
```

Open `http://<your-local-ip>:8000/ticket/<PNR>` on your phone browser. The page shows the full ticket with a scannable QR code. Scan it with your phone camera — most camera apps will display the raw JWT string, showing that the cryptographic payload is directly embedded in the QR.

---

## Troubleshooting

**`RuntimeError: Private key not found`**
Run `python -m cli keygen` before starting services.

**`TypeError: Can't replace canonical symbol` (SQLAlchemy on Python 3.14)**
```bash
pip install --upgrade sqlalchemy
```

**`TypeError: Parameter.make_metavar() missing argument` (Typer)**
```bash
pip install --upgrade typer
```

**`pyzbar` not working / QR image decode fails**
Install the system library:
```bash
sudo apt install libzbar0          # Ubuntu/Debian
sudo pacman -S zbar                # Arch
brew install zbar                  # macOS
```

**Service won't start — port already in use**
```bash
lsof -i :8000                      # find what's using port 8000
kill <PID>
```

**Ticket shows `EXPIRED` immediately after booking**
The travel date is in the past. Use today's date (`2026-06-02`) and a departure time a few hours from now.

**Ticket shows `INVALID_PNR` despite being booked**
The chart sync to the HHT service failed during booking (check honcho logs for `⚠ HHT chart sync failed`). Re-add manually:
```bash
curl -X POST http://localhost:8003/chart/add \
  -H "Content-Type: application/json" \
  -d '{"pnr":"PNR123","uuid":"<uuid>","train":"12051","travel_date":"2026-06-02","ticket_class":"3A","passengers":[{"name":"Test","berth":"B2/14"}]}'
```

**`WRONG_DATE` result**
The JWT's `date` field must match today's date exactly. This is by design — a ticket for June 1st cannot be used on June 2nd.

---

## Notes for the Guide

This demo implements the cryptographic core of the proposal described in *Cryptographic Authentication and Anti-Forgery Framework for Printed Indian Railway Tickets*. The following aspects are simulated rather than production-grade:

- The **HSM** is simulated by a file-based private key in `keys/private_key.pem`. In production, the private key would reside in a Hardware Security Module and never exist as a file.
- The **HHT app** is simulated by the HHT microservice. In production, the public key would be compiled into the app binary with no runtime key loading.
- The **audit server** calls are synchronous in this demo. In production, they would be background tasks that do not block the verification result.
- **Physical security layers** (holographic strip, OVI patch, thermochromic zone) described in the proposal are not demonstrated here — they are paper manufacturing specifications.
- **Chart pre-download** is simulated by the shared SQLite database. In production, the HHT app would pre-download the chart over station WiFi before departure and store it locally in SQLite on the device.