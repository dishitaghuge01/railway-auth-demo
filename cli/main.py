import os
import shutil
import json
import base64
import time
from datetime import datetime
from typing import Optional

import typer
import httpx

from shared.config import settings
from shared.crypto_utils import (
    generate_keypair,
    load_public_key,
    get_public_key_fingerprint,
    compute_identity_hash,
)
from shared.payload import parse_jwt

# ── App + sub-apps ─────────────────────────────────────────────────────────────

app = typer.Typer(
    name="railway-cli",
    help="Railway Ticket Authentication Demo — management CLI",
    no_args_is_help=True,
)

audit_app = typer.Typer(help="Audit server commands.", no_args_is_help=True)
chart_app = typer.Typer(help="Passenger chart commands.", no_args_is_help=True)

app.add_typer(audit_app, name="audit")
app.add_typer(chart_app, name="chart")


@app.callback()
def root():
    """Railway Ticket Authentication Demo CLI."""
    pass


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _svc(url: str) -> str:
    """Strip trailing slash from service URL."""
    return url.rstrip("/")


def _http_get(url: str) -> dict:
    try:
        r = httpx.get(url, timeout=8.0)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        typer.secho(f"\n  ✗ Could not connect to {url}", fg=typer.colors.RED)
        typer.secho(
            "    Make sure all services are running: honcho start",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        typer.secho(f"\n  ✗ HTTP {e.response.status_code}: {e.response.text}", fg=typer.colors.RED)
        raise typer.Exit(1)


def _http_post(url: str, body: dict) -> dict:
    try:
        r = httpx.post(url, json=body, timeout=10.0)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        typer.secho(f"\n  ✗ Could not connect to {url}", fg=typer.colors.RED)
        typer.secho(
            "    Make sure all services are running: honcho start",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        typer.secho(f"\n  ✗ HTTP {e.response.status_code}: {e.response.text}", fg=typer.colors.RED)
        raise typer.Exit(1)


def _http_delete(url: str) -> dict:
    try:
        r = httpx.delete(url, timeout=8.0)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        typer.secho(f"\n  ✗ Could not connect to {url}", fg=typer.colors.RED)
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        typer.secho(f"\n  ✗ HTTP {e.response.status_code}: {e.response.text}", fg=typer.colors.RED)
        raise typer.Exit(1)


def _result_color(result: str) -> str:
    mapping = {
        "VALID":                   typer.colors.GREEN,
        "DUPLICATE":               typer.colors.YELLOW,
        "FORGED":                  typer.colors.RED,
        "EXPIRED":                 typer.colors.RED,
        "NOT_YET_VALID":           typer.colors.YELLOW,
        "WRONG_TRAIN":             typer.colors.RED,
        "WRONG_DATE":              typer.colors.RED,
        "INVALID_PNR":             typer.colors.RED,
    }
    return mapping.get(result, typer.colors.WHITE)


def _print_section(title: str):
    typer.echo("")
    typer.secho(f"  {'─' * 50}", fg=typer.colors.BRIGHT_BLACK)
    typer.secho(f"  {title}", fg=typer.colors.BRIGHT_WHITE, bold=True)
    typer.secho(f"  {'─' * 50}", fg=typer.colors.BRIGHT_BLACK)


def _print_kv(label: str, value: str, color=None):
    label_str = typer.style(f"  {label:<22}", fg=typer.colors.BRIGHT_BLACK)
    value_str = typer.style(str(value), fg=color) if color else str(value)
    typer.echo(label_str + value_str)


def _fetch_jwt_for_pnr(pnr: str) -> str:
    """Fetch full JWT from PRS service for a given PNR."""
    data = _http_get(f"{_svc(settings.PRS_URL)}/ticket/{pnr}/raw")
    jwt  = data.get("jwt")
    if not jwt:
        typer.secho(f"  ✗ No JWT found for PNR {pnr}", fg=typer.colors.RED)
        raise typer.Exit(1)
    return jwt


def _decode_qr_image(image_path: str) -> str:
    """Decode QR code from image file using pyzbar. Returns JWT string."""
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        from PIL import Image
    except ImportError:
        typer.secho(
            "  ✗ pyzbar / Pillow not installed. Run: pip install pyzbar Pillow",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if not os.path.exists(image_path):
        typer.secho(f"  ✗ Image file not found: {image_path}", fg=typer.colors.RED)
        raise typer.Exit(1)

    img     = Image.open(image_path)
    decoded = pyzbar_decode(img)

    if not decoded:
        typer.secho(
            f"  ✗ No QR code found in image: {image_path}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    jwt_str = decoded[0].data.decode("utf-8").strip()
    typer.secho(f"  ✓ QR decoded from {image_path}", fg=typer.colors.CYAN)
    return jwt_str


def _print_verify_result(data: dict):
    """Pretty-print a full HHT /verify response."""
    result = data.get("result", "UNKNOWN")

    _print_section("VERIFICATION RESULT")
    typer.echo("")
    typer.secho(
        f"  {'RESULT':<22}{result}",
        fg=_result_color(result),
        bold=True,
    )
    typer.echo("")

    # Ticket details
    td = data.get("ticket_details") or {}
    if td:
        _print_section("Ticket Details")
        _print_kv("Train",       td.get("train", "—"))
        _print_kv("From → To",   f"{td.get('from', '—')} → {td.get('to', '—')}")
        _print_kv("Class",       td.get("class", "—"))
        _print_kv("Date",        td.get("date", "—"))
        _print_kv("Type",        td.get("type", "—"))
        _print_kv("UUID",        td.get("uuid", "—"))

    # Checks
    _print_section("Security Checks")
    sig_ok    = data.get("signature_valid", False)
    chart_ok  = data.get("chart_matched",   False)
    is_dup    = data.get("is_duplicate",    False)
    key_used  = data.get("key_used",        "—")

    _print_kv(
        "Signature",
        "✓ VALID" if sig_ok else "✗ INVALID",
        typer.colors.GREEN if sig_ok else typer.colors.RED,
    )
    _print_kv(
        "Chart Match",
        "✓ MATCHED" if chart_ok else "✗ NOT FOUND",
        typer.colors.GREEN if chart_ok else typer.colors.RED,
    )
    _print_kv(
        "Duplicate",
        "⚠ YES — FLAGGED" if is_dup else "✓ NO",
        typer.colors.YELLOW if is_dup else typer.colors.GREEN,
    )
    _print_kv("Key Used", key_used or "—")

    # Passengers
    passengers = data.get("passengers", [])
    if passengers:
        _print_section("Passengers")
        for i, p in enumerate(passengers, 1):
            name    = p.get("name",           "—")
            berth   = p.get("berth",          "—")
            id_chk  = p.get("identity_check", "NOT_REQUIRED")

            id_color = {
                "PASSED":                 typer.colors.GREEN,
                "FAILED":                 typer.colors.RED,
                "NOT_ATTEMPTED":          typer.colors.YELLOW,
                "NOT_ATTEMPTED_MANDATORY":typer.colors.RED,
                "NOT_REQUIRED":           typer.colors.BRIGHT_BLACK,
            }.get(id_chk, typer.colors.WHITE)

            typer.echo(
                typer.style(f"  {i}. {name:<20}", bold=True)
                + typer.style(f"Berth: {berth:<10}", fg=typer.colors.BRIGHT_BLACK)
                + typer.style(f"Identity: {id_chk}", fg=id_color)
            )

    typer.echo("")


# ── 6.1  keygen ───────────────────────────────────────────────────────────────

@app.command("keygen")
def keygen(
    force: bool = typer.Option(
        False, "--force", "-f",
        help="Overwrite existing keys without prompting.",
    )
):
    """Generate a new ECDSA P-256 keypair and write to the keys/ directory."""
    private_path = os.path.join(settings.KEYS_DIR, "private_key.pem")
    public_path  = os.path.join(settings.KEYS_DIR, "public_key.pem")
    old_pub_path = os.path.join(settings.KEYS_DIR, "old_public_key.pem")

    os.makedirs(settings.KEYS_DIR, exist_ok=True)

    keys_exist = os.path.exists(private_path) or os.path.exists(public_path)

    if keys_exist and not force:
        typer.echo("")
        typer.secho("  ⚠  Existing keys detected.", fg=typer.colors.YELLOW, bold=True)
        typer.echo(f"     Private key : {private_path}")
        typer.echo(f"     Public key  : {public_path}")
        typer.echo("")
        typer.echo(
            "  Generating new keys will rotate the current public key to\n"
            "  old_public_key.pem and PERMANENTLY DELETE the current private key.\n"
        )
        confirmed = typer.confirm("  Proceed with key rotation?", default=False)
        if not confirmed:
            typer.secho("  Aborted. No changes made.", fg=typer.colors.RED)
            raise typer.Exit(0)

    if os.path.exists(public_path):
        shutil.move(public_path, old_pub_path)
        typer.secho(
            f"  ↳ Current public key rotated → {old_pub_path}",
            fg=typer.colors.CYAN,
        )

    if os.path.exists(private_path):
        os.remove(private_path)

    typer.echo("\n  Generating ECDSA P-256 keypair...")
    private_pem, public_pem = generate_keypair()

    with open(private_path, "wb") as f:
        f.write(private_pem)
    os.chmod(private_path, 0o600)

    with open(public_path, "wb") as f:
        f.write(public_pem)
    os.chmod(public_path, 0o644)

    fingerprint = get_public_key_fingerprint(public_pem)

    typer.echo("")
    typer.secho("  ✓ Keypair generated successfully.", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  Private key  : {private_path}  (permissions: 600)")
    typer.echo(f"  Public key   : {public_path}")
    if os.path.exists(old_pub_path):
        typer.echo(f"  Previous key : {old_pub_path}  (kept for grace window)")
    typer.echo("")
    typer.secho(
        f"  Public key fingerprint: {fingerprint}",
        fg=typer.colors.BRIGHT_WHITE, bold=True,
    )
    typer.echo("")
    typer.secho(
        "  ⚠  Private key simulates an HSM. In production it never exists as a file.",
        fg=typer.colors.YELLOW,
    )
    typer.echo("")


# ── 6.2  book ─────────────────────────────────────────────────────────────────

TICKET_TYPES  = ["R", "U", "T"]
TICKET_CLASSES = ["1A", "2A", "3A", "SL", "UR"]


@app.command("book")
def book(
    json_file: Optional[str] = typer.Option(
        None, "--json", "-j",
        help="Path to a JSON file containing the full booking request body.",
    )
):
    """
    Book a new ticket.

    Run interactively (no flags) or pass --json <file> for scripted/demo use.
    """
    if json_file:
        # ── JSON mode ────────────────────────────────────────────────────────
        if not os.path.exists(json_file):
            typer.secho(f"  ✗ File not found: {json_file}", fg=typer.colors.RED)
            raise typer.Exit(1)
        with open(json_file) as f:
            body = json.load(f)
        typer.echo(f"\n  Booking from file: {json_file}")
    else:
        # ── Interactive mode ─────────────────────────────────────────────────
        typer.echo("")
        typer.secho("  ╔══════════════════════════════╗", fg=typer.colors.BRIGHT_WHITE)
        typer.secho("  ║   NEW TICKET BOOKING         ║", fg=typer.colors.BRIGHT_WHITE, bold=True)
        typer.secho("  ╚══════════════════════════════╝", fg=typer.colors.BRIGHT_WHITE)
        typer.echo("")

        ticket_type = typer.prompt(
            "  Ticket type [R=Reserved, U=Unreserved, T=Tatkal]",
            default="R",
        ).strip().upper()
        if ticket_type not in TICKET_TYPES:
            typer.secho(f"  ✗ Invalid type. Choose from: {TICKET_TYPES}", fg=typer.colors.RED)
            raise typer.Exit(1)

        train         = typer.prompt("  Train number").strip()
        from_stn      = typer.prompt("  From station code (e.g. CSMT)").strip().upper()
        to_stn        = typer.prompt("  To station code (e.g. NDLS)").strip().upper()

        ticket_class  = typer.prompt(
            "  Class [1A / 2A / 3A / SL / UR]",
            default="3A",
        ).strip().upper()
        if ticket_class not in TICKET_CLASSES:
            typer.secho(f"  ✗ Invalid class. Choose from: {TICKET_CLASSES}", fg=typer.colors.RED)
            raise typer.Exit(1)

        travel_date    = typer.prompt("  Travel date (YYYY-MM-DD)").strip()
        departure_time = typer.prompt("  Departure time (HH:MM, 24h)").strip()
        arrival_time   = typer.prompt("  Arrival time  (HH:MM, 24h)").strip()

        # Passengers
        passengers = []
        typer.echo("")
        typer.secho("  Add passengers (Aadhaar optional for SL/UR):", fg=typer.colors.BRIGHT_BLACK)

        while True:
            typer.echo("")
            name  = typer.prompt(f"  Passenger {len(passengers)+1} — Full name").strip()
            berth = None
            if ticket_type != "U":
                berth = typer.prompt("  Berth (e.g. B2/14)").strip() or None

            aadhaar, dob = None, None
            if ticket_type in ("R", "T") and ticket_class in ("1A", "2A", "3A", "T"):
                want_id = typer.confirm("  Add Aadhaar for identity check?", default=False)
                if want_id:
                    aadhaar = typer.prompt("  Aadhaar number (12 digits)").strip()
                    dob     = typer.prompt("  Date of birth (YYYY-MM-DD)").strip()
            elif ticket_type == "T":
                typer.secho(
                    "  ⚠ Tatkal tickets require identity check at boarding.",
                    fg=typer.colors.YELLOW,
                )
                aadhaar = typer.prompt("  Aadhaar number (12 digits)").strip()
                dob     = typer.prompt("  Date of birth (YYYY-MM-DD)").strip()

            passengers.append({
                "name":    name,
                "berth":   berth,
                "aadhaar": aadhaar,
                "dob":     dob,
            })

            another = typer.confirm("\n  Add another passenger?", default=False)
            if not another:
                break

        body = {
            "ticket_type":    ticket_type,
            "train":          train,
            "from_stn":       from_stn,
            "to_stn":         to_stn,
            "ticket_class":   ticket_class,
            "travel_date":    travel_date,
            "departure_time": departure_time,
            "arrival_time":   arrival_time,
            "passengers":     passengers,
        }

    # ── POST to PRS service ───────────────────────────────────────────────────
    typer.echo("")
    typer.secho("  Sending booking request to PRS service...", fg=typer.colors.BRIGHT_BLACK)
    data = _http_post(f"{_svc(settings.PRS_URL)}/book", body)

    # ── Print result ─────────────────────────────────────────────────────────
    _print_section("BOOKING CONFIRMED")
    typer.echo("")
    _print_kv("PNR",        data["pnr"],        typer.colors.GREEN)
    _print_kv("UUID",       data["uuid"])
    _print_kv("Ticket URL", data["ticket_url"], typer.colors.CYAN)
    _print_kv("QR URL",     data["qr_url"],     typer.colors.CYAN)
    typer.echo("")
    typer.secho(
        "  Open the Ticket URL on your phone browser to view and scan the QR.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")


# ── 6.3  verify ───────────────────────────────────────────────────────────────

@app.command("verify")
def verify(
    pnr: Optional[str] = typer.Option(
        None, "--pnr", "-p",
        help="PNR number. Fetches JWT from PRS service automatically.",
    ),
    jwt_str: Optional[str] = typer.Option(
        None, "--jwt",
        help="Raw JWT string to verify directly.",
    ),
    image: Optional[str] = typer.Option(
        None, "--image", "-i",
        help="Path to a QR code PNG image. Decodes JWT from image.",
    ),
    tte: str = typer.Option(
        ..., "--tte",
        help="TTE ID, e.g. TTE-MUM-047",
    ),
    train: str = typer.Option(
        ..., "--train",
        help="Expected train number, e.g. 12051",
    ),
    aadhaar: bool = typer.Option(
        False, "--aadhaar", "-a",
        help="Prompt for Aadhaar+DOB for each passenger with an identity hash.",
    ),
):
    """
    Verify a ticket via the HHT service.

    Provide exactly one of --pnr, --jwt, or --image.
    """
    # ── Resolve JWT ───────────────────────────────────────────────────────────
    provided = sum([pnr is not None, jwt_str is not None, image is not None])
    if provided == 0:
        typer.secho(
            "  ✗ Provide one of: --pnr, --jwt, or --image",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    if provided > 1:
        typer.secho(
            "  ✗ Provide only one of: --pnr, --jwt, or --image",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if pnr:
        typer.echo(f"\n  Fetching JWT for PNR {pnr}...")
        jwt_string = _fetch_jwt_for_pnr(pnr)
    elif image:
        jwt_string = _decode_qr_image(image)
    else:
        jwt_string = jwt_str.strip()

    # ── Optionally collect Aadhaar inputs ─────────────────────────────────────
    aadhaar_inputs = []
    if aadhaar:
        try:
            payload, _, _ = parse_jwt(jwt_string)
        except ValueError as e:
            typer.secho(f"  ✗ Cannot parse JWT for Aadhaar prompting: {e}", fg=typer.colors.RED)
            raise typer.Exit(1)

        pax_list = payload.get("pax", [])
        typer.echo("")
        typer.secho(
            "  Identity check requested. Enter details for each passenger.",
            fg=typer.colors.BRIGHT_BLACK,
        )

        for i, pax in enumerate(pax_list):
            berth   = pax.get("b", f"PAX-{i+1}")
            id_hash = pax.get("id")
            if not id_hash:
                # No hash stored — identity check not applicable
                continue
            typer.echo(f"\n  Passenger at berth {berth}:")
            adh = typer.prompt("    Aadhaar number").strip()
            dob = typer.prompt("    Date of birth (YYYY-MM-DD)").strip()
            aadhaar_inputs.append({"berth": berth, "aadhaar": adh, "dob": dob})

    # ── POST to HHT service ───────────────────────────────────────────────────
    typer.echo("\n  Verifying with HHT service...")

    body = {
        "jwt":            jwt_string,
        "tte_id":         tte,
        "expected_train": train,
        "aadhaar_inputs": aadhaar_inputs if aadhaar_inputs else None,
    }
    data = _http_post(f"{_svc(settings.HHT_SERVICE_URL)}/verify", body)
    _print_verify_result(data)


# ── 6.4  audit ────────────────────────────────────────────────────────────────

@audit_app.callback()
def audit_root():
    """Audit server commands."""
    pass


@audit_app.command("stats")
def audit_stats():
    """Show verification statistics from the audit server."""
    data = _http_get(f"{_svc(settings.AUDIT_SERVER_URL)}/stats")

    _print_section("AUDIT SERVER STATS")
    typer.echo("")
    _print_kv("Total verifications", data.get("total_verifications", 0))
    _print_kv("Valid",               data.get("valid",               0), typer.colors.GREEN)
    _print_kv("Forged",              data.get("forged",              0), typer.colors.RED)
    _print_kv("Expired",             data.get("expired",             0), typer.colors.YELLOW)
    _print_kv("Duplicate UUIDs",     data.get("duplicate_uuids",     0), typer.colors.YELLOW)
    _print_kv("Wrong train",         data.get("wrong_train",         0), typer.colors.YELLOW)
    _print_kv("Wrong date",          data.get("wrong_date",          0), typer.colors.YELLOW)
    _print_kv("Invalid PNR",         data.get("invalid_pnr",         0), typer.colors.YELLOW)
    typer.echo("")


@audit_app.command("duplicates")
def audit_duplicates():
    """List all duplicate ticket scan events."""
    data = _http_get(f"{_svc(settings.AUDIT_SERVER_URL)}/duplicates")
    dupes = data.get("duplicates", [])

    _print_section("DUPLICATE TICKET REPORT")
    typer.echo("")

    if not dupes:
        typer.secho("  ✓ No duplicate ticket scans detected.", fg=typer.colors.GREEN)
        typer.echo("")
        return

    typer.secho(
        f"  ⚠  {len(dupes)} duplicate UUID(s) detected!",
        fg=typer.colors.YELLOW, bold=True,
    )

    for d in dupes:
        typer.echo("")
        typer.secho(f"  UUID: {d['uuid']}", fg=typer.colors.BRIGHT_WHITE, bold=True)
        _print_kv("Occurrences", d.get("occurrences", "—"), typer.colors.RED)

        first = d.get("first_seen", {})
        _print_kv("First seen — TTE",   first.get("tte_id",    "—"))
        _print_kv("First seen — Train", first.get("train",     "—"))
        ts = first.get("timestamp")
        if ts:
            _print_kv(
                "First seen — Time",
                datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            )

        events = d.get("all_events", [])
        if events:
            typer.echo("")
            typer.secho("  All scan events:", fg=typer.colors.BRIGHT_BLACK)
            for ev in events:
                ts_str = datetime.fromtimestamp(ev["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                typer.echo(
                    typer.style(f"    [{ts_str}]", fg=typer.colors.BRIGHT_BLACK)
                    + f"  TTE: {ev.get('tte_id','—'):<16}"
                    + f"  Train: {ev.get('train','—'):<8}"
                    + f"  Result: "
                    + typer.style(ev.get("result", "—"), fg=_result_color(ev.get("result", "")))
                )
    typer.echo("")


@audit_app.command("log")
def audit_log(
    uuid: str = typer.Argument(..., help="UUID to look up in the audit log."),
):
    """Show all audit log events for a specific ticket UUID."""
    data = _http_get(f"{_svc(settings.AUDIT_SERVER_URL)}/log/{uuid}")
    events = data.get("events", [])

    _print_section(f"AUDIT LOG — {uuid}")
    typer.echo("")

    if not events:
        typer.secho("  No events found for this UUID.", fg=typer.colors.YELLOW)
        typer.echo("")
        return

    for ev in events:
        ts_str = datetime.fromtimestamp(ev["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        is_dup = ev.get("is_duplicate", 0)
        dup_marker = typer.style(" ⚠ DUPLICATE", fg=typer.colors.YELLOW) if is_dup else ""

        typer.echo(
            typer.style(f"  [{ts_str}]", fg=typer.colors.BRIGHT_BLACK)
            + f"  TTE: {ev.get('tte_id','—'):<16}"
            + f"  Train: {ev.get('train','—'):<8}"
            + f"  Coach: {ev.get('coach') or '—':<6}"
            + f"  Result: "
            + typer.style(ev.get("result", "—"), fg=_result_color(ev.get("result", "")))
            + dup_marker
        )
    typer.echo("")


# ── 6.5  chart ────────────────────────────────────────────────────────────────

@chart_app.callback()
def chart_root():
    """Passenger chart commands."""
    pass


@chart_app.command("show")
def chart_show(
    train: str = typer.Option(..., "--train", "-t", help="Train number."),
    date:  str = typer.Option(..., "--date",  "-d", help="Travel date YYYY-MM-DD."),
):
    """Display the passenger chart for a train and date."""
    data = _http_get(f"{_svc(settings.HHT_SERVICE_URL)}/chart/{train}/{date}")

    _print_section(f"PASSENGER CHART — Train {train} | {date}")
    typer.echo("")
    _print_kv("Total passengers", data.get("total_passengers", 0))
    typer.echo("")

    coaches = data.get("coaches", {})
    if not coaches:
        typer.secho("  No passengers found for this train/date.", fg=typer.colors.YELLOW)
        typer.echo("")
        return

    for coach, rows in sorted(coaches.items()):
        typer.secho(f"  Coach {coach}", fg=typer.colors.BRIGHT_WHITE, bold=True)
        typer.secho(
            f"  {'Berth':<10} {'Name':<24} {'PNR':<14} {'Class':<6}",
            fg=typer.colors.BRIGHT_BLACK,
        )
        typer.secho(f"  {'─'*54}", fg=typer.colors.BRIGHT_BLACK)
        for row in rows:
            typer.echo(
                f"  {(row.get('berth') or '—'):<10}"
                f" {row.get('name','—'):<24}"
                f" {row.get('pnr','—'):<14}"
                f" {row.get('class','—'):<6}"
            )
        typer.echo("")


@chart_app.command("clear")
def chart_clear(
    train: str = typer.Option(..., "--train", "-t", help="Train number."),
    date:  str = typer.Option(..., "--date",  "-d", help="Travel date YYYY-MM-DD."),
):
    """Clear the passenger chart for a train (simulates end-of-journey wipe)."""
    confirmed = typer.confirm(
        f"\n  Clear chart for train {train} on {date}?", default=False
    )
    if not confirmed:
        typer.secho("  Aborted.", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    data = _http_delete(f"{_svc(settings.HHT_SERVICE_URL)}/chart/{train}/{date}")

    typer.echo("")
    typer.secho(
        f"  ✓ Chart cleared. {data.get('rows_deleted', 0)} row(s) deleted.",
        fg=typer.colors.GREEN,
    )
    typer.echo("")


# ── 6.6  clone ────────────────────────────────────────────────────────────────

@app.command("clone")
def clone(
    pnr: str = typer.Option(..., "--pnr", "-p", help="PNR of the ticket to clone."),
):
    """
    DEMO ATTACK: Clone a ticket.

    Copies a real ticket's JWT to a new QR image with the SAME UUID.
    When the clone is verified after the original, the audit server
    flags it as DUPLICATE.
    """
    import qrcode as qrcode_lib

    typer.echo("")
    typer.secho("  ╔══════════════════════════════════════╗", fg=typer.colors.RED)
    typer.secho("  ║  DEMO ATTACK: TICKET CLONING         ║", fg=typer.colors.RED, bold=True)
    typer.secho("  ╚══════════════════════════════════════╝", fg=typer.colors.RED)
    typer.echo("")
    typer.secho(
        "  This simulates an attacker copying a legitimate ticket's\n"
        "  QR code and printing it on a second piece of paper.\n"
        "  The JWT is identical — same UUID, same valid signature.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")

    # Fetch real JWT
    typer.echo(f"  Fetching JWT for PNR {pnr}...")
    jwt_string = _fetch_jwt_for_pnr(pnr)

    # Parse to show what's being cloned
    try:
        payload, _, _ = parse_jwt(jwt_string)
    except ValueError:
        payload = {}

    typer.secho("  ✓ JWT fetched. Creating clone...", fg=typer.colors.YELLOW)
    _print_kv("UUID being cloned", payload.get("uuid", "—"), typer.colors.YELLOW)
    _print_kv("Train",             payload.get("train", "—"))
    _print_kv("Class",             payload.get("class", "—"))

    # Generate new QR with same JWT
    os.makedirs(settings.TICKETS_DIR, exist_ok=True)
    uuid_short  = payload.get("uuid", pnr)[:8]
    clone_path  = os.path.join(settings.TICKETS_DIR, f"CLONED_{pnr}_qr.png")

    qr = qrcode_lib.QRCode(
        error_correction=qrcode_lib.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(jwt_string)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(clone_path)

    typer.echo("")
    typer.secho("  ✓ Clone QR created.", fg=typer.colors.YELLOW, bold=True)
    _print_kv("Clone QR saved to", clone_path, typer.colors.YELLOW)
    typer.echo("")
    typer.secho(
        "  What to do next:",
        fg=typer.colors.BRIGHT_WHITE, bold=True,
    )
    typer.echo(
        f"  1. Verify the original:  python -m cli verify --pnr {pnr} --tte TTE-001 --train {payload.get('train','?')}\n"
        f"  2. Verify the clone:     python -m cli verify --image {clone_path} --tte TTE-002 --train {payload.get('train','?')}\n"
        f"  3. Check audit:          python -m cli audit duplicates\n"
    )
    typer.echo(
        "  The second scan will return DUPLICATE and both events\n"
        "  will be flagged in the audit log.\n"
    )


# ── 6.7  forge ────────────────────────────────────────────────────────────────

FORGEABLE_FIELDS = ["class", "date", "from", "to", "train"]


@app.command("forge")
def forge(
    pnr: str = typer.Option(
        ..., "--pnr", "-p", help="PNR of the real ticket to forge from."
    ),
    field: str = typer.Option(
        "class", "--field",
        help=f"Payload field to tamper with. One of: {FORGEABLE_FIELDS}",
    ),
    value: str = typer.Option(
        ..., "--value", "-v",
        help="New value to substitute into the chosen field.",
    ),
):
    """
    DEMO ATTACK: Forge a ticket by tampering with a payload field.

    Modifies a field in the JWT payload and re-encodes WITHOUT re-signing.
    The original signature is kept but now covers the ORIGINAL bytes,
    so signature verification FAILS → result: FORGED.
    """
    import qrcode as qrcode_lib

    typer.echo("")
    typer.secho("  ╔══════════════════════════════════════╗", fg=typer.colors.RED)
    typer.secho("  ║  DEMO ATTACK: TICKET FORGERY         ║", fg=typer.colors.RED, bold=True)
    typer.secho("  ╚══════════════════════════════════════╝", fg=typer.colors.RED)
    typer.echo("")
    typer.secho(
        "  This simulates an attacker who intercepts a legitimate ticket\n"
        "  and modifies a field (e.g. upgrades class from SL → 1A).\n"
        "  The signature still exists but now covers DIFFERENT bytes,\n"
        "  so it fails cryptographic verification.",
        fg=typer.colors.BRIGHT_BLACK,
    )
    typer.echo("")

    if field not in FORGEABLE_FIELDS:
        typer.secho(
            f"  ✗ Invalid field '{field}'. Choose from: {FORGEABLE_FIELDS}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    # Fetch real JWT
    typer.echo(f"  Fetching JWT for PNR {pnr}...")
    original_jwt = _fetch_jwt_for_pnr(pnr)

    # Parse — we need the raw original signature
    try:
        original_payload, _, original_sig = parse_jwt(original_jwt)
    except ValueError as e:
        typer.secho(f"  ✗ Failed to parse JWT: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    original_value = original_payload.get(field, "—")

    typer.secho(
        f"  Tampering: '{field}'  {original_value}  →  {value}",
        fg=typer.colors.YELLOW, bold=True,
    )

    # Modify the payload
    forged_payload = dict(original_payload)
    forged_payload[field] = value

    # Re-encode payload WITHOUT re-signing
    import json as json_mod
    forged_json  = json_mod.dumps(forged_payload, sort_keys=False, separators=(",", ":"))
    forged_bytes = forged_json.encode("utf-8")
    forged_b64   = base64.urlsafe_b64encode(forged_bytes).decode("utf-8").rstrip("=")

    # Assemble forged JWT: modified payload + ORIGINAL signature
    forged_jwt = f"{forged_b64}.{original_sig}"

    # Generate QR from forged JWT
    os.makedirs(settings.TICKETS_DIR, exist_ok=True)
    forged_path = os.path.join(settings.TICKETS_DIR, f"FORGED_{pnr}_{field}_qr.png")

    qr = qrcode_lib.QRCode(
        error_correction=qrcode_lib.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(forged_jwt)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(forged_path)

    typer.echo("")
    typer.secho("  ✓ Forged QR created.", fg=typer.colors.RED, bold=True)
    _print_kv("Original value",  str(original_value))
    _print_kv("Forged value",    value,      typer.colors.RED)
    _print_kv("Forged QR saved", forged_path, typer.colors.YELLOW)
    typer.echo("")
    typer.secho(
        "  What to do next:",
        fg=typer.colors.BRIGHT_WHITE, bold=True,
    )
    train = original_payload.get("train", "?")
    typer.echo(
        f"  Verify the forged ticket:\n"
        f"  python -m cli verify --image {forged_path} --tte TTE-001 --train {train}\n"
    )
    typer.echo(
        "  Expected result: FORGED\n"
        "  The signature verification step will fail because the payload\n"
        "  bytes no longer match what was signed by the CRIS HSM.\n"
    )


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()