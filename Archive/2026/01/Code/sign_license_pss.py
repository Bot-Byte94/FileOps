# sign_license_pss.py
import base64
import json
import sys
from datetime import date
from pathlib import Path

import typer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

APP_NAME = "FileOps"

DEFAULT_PRIVATE_KEY = Path(__file__).resolve().parent / "fileops_private.pem"
DEFAULT_ROOT_OUT = Path("fileops.license")

app = typer.Typer(add_completion=False)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def detect_exe_dir(app_name: str = "fileops") -> Path:
    """
    Detect the directory containing fileops.exe.
    Works for PyInstaller, dev layouts, and arbitrary CWDs.
    """
    # 1) If signer itself is frozen (rare, but correct)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    here = Path(__file__).resolve().parent

    # 2) Common dev layout
    for candidate in (
        here / "dist" / f"{app_name}.exe",
        here / f"{app_name}.exe",
    ):
        if candidate.exists():
            return candidate.parent

    # 3) If run from inside the exe directory
    cwd = Path.cwd()
    if (cwd / f"{app_name}.exe").exists():
        return cwd

    # 4) Fallback
    return cwd


def canonical_payload_bytes(lic: dict) -> bytes:
    """Stable JSON for signing (sort keys, no whitespace). Excludes signature."""
    lic2 = dict(lic)
    lic2.pop("signature", None)
    return json.dumps(
        lic2,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_pss(private_key, payload: bytes) -> bytes:
    return private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

@app.command()
def main(
    email: str = typer.Option("customer@example.com", help="Customer email."),
    issued_at: str = typer.Option(str(date.today()), help="YYYY-MM-DD (default: today)."),
    expires: str = typer.Option("2027-01-14", help='YYYY-MM-DD or "none".'),
    portable: bool = typer.Option(True, help="Portable license (machine_id = null)."),
    machine_lock: str = typer.Option("", help="Explicit machine_id hash (overrides --portable)."),
    private_key_path: Path = typer.Option(DEFAULT_PRIVATE_KEY, help="Path to RSA private key PEM."),
    also_write_root: bool = typer.Option(True, help="Also write ./fileops.license."),
    show_payload: bool = typer.Option(True, help="Print canonical payload being signed."),
):
    # Load private key
    private_key_path = private_key_path.expanduser().resolve()
    if not private_key_path.exists():
        typer.secho("❌ Missing private key", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None,
    )

    # Machine ID logic
    if machine_lock.strip():
        machine_id_value = machine_lock.strip()
    else:
        machine_id_value = None  # portable license

    # Expiry logic
    expires_value = None if expires.lower() in ("none", "null", "") else expires

    lic = {
        "license_version": 1,
        "product": APP_NAME,
        "edition": "pro",
        "email": email,
        "issued_at": issued_at,
        "expires_at": expires_value,
        "machine_id": machine_id_value,
    }

    payload = canonical_payload_bytes(lic)
    sig = sign_pss(private_key, payload)
    lic["signature"] = base64.b64encode(sig).decode("ascii")

    # ------------------------------------------------------------
    # Write license next to EXE (auto-detected)
    # ------------------------------------------------------------
    exe_dir = detect_exe_dir("fileops")
    exe_out = exe_dir / "fileops.license"
    exe_out.write_text(json.dumps(lic, ensure_ascii=False, indent=2), encoding="utf-8")

    typer.secho(f"✅ Wrote: {exe_out}", fg=typer.colors.GREEN)

    if also_write_root:
        DEFAULT_ROOT_OUT.write_text(json.dumps(lic, ensure_ascii=False, indent=2), encoding="utf-8")
        typer.echo(f"✅ Also wrote: {DEFAULT_ROOT_OUT.resolve()}")

    if show_payload:
        typer.echo("\nPayload signed (canonical):")
        typer.echo(payload.decode("utf-8"))

if __name__ == "__main__":
    app()
