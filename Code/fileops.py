# fileops.py

import sys
import json
import base64
import os
import shutil
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Literal

import typer
import platform
import subprocess

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

# =========================
# Embedded public key removed
# =========================
# No built-in license verification key is shipped in this copy.
# License signature validation will fail until a public key is provided externally.
FILEOPS_PUBLIC_KEY_PEM = b""

APP_NAME = "FileOps"
APP_VERSION = "0.3.6"

# =========================
# Machine ID (privacy-preserving)
# =========================

MACHINE_ID_SALT = "fileops-machine-id-v1"  # bump ONLY if you want to invalidate old locks


def _read_text_file(p: Path) -> Optional[str]:
    try:
        if p.exists():
            s = p.read_text(encoding="utf-8", errors="ignore").strip()
            return s or None
    except Exception:
        return None
    return None


def _windows_machine_guid() -> Optional[str]:
    # Uses built-in 'reg' command (no extra deps)
    try:
        out = subprocess.check_output(
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        # output contains: MachineGuid    REG_SZ    xxxxxxxx-xxxx-....
        for line in out.splitlines():
            if "MachineGuid" in line:
                parts = line.split()
                if parts:
                    return parts[-1].strip()
    except Exception:
        return None
    return None


def _macos_platform_uuid() -> Optional[str]:
    # IOPlatformUUID via ioreg
    try:
        out = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        # Look for: "IOPlatformUUID" = "XXXXXXXX-...."
        for line in out.splitlines():
            if "IOPlatformUUID" in line:
                # crude parse, reliable enough
                q1 = line.find('"', line.find("="))
                q2 = line.find('"', q1 + 1)
                if q1 != -1 and q2 != -1:
                    return line[q1 + 1 : q2].strip()
    except Exception:
        return None
    return None


def _linux_machine_id() -> Optional[str]:
    return _read_text_file(Path("/etc/machine-id")) or _read_text_file(Path("/var/lib/dbus/machine-id"))


def get_machine_id_raw() -> Optional[str]:
    sysname = platform.system().lower()

    if "windows" in sysname:
        return _windows_machine_guid()
    if "darwin" in sysname or "mac" in sysname:
        return _macos_platform_uuid()
    # assume linux/others
    return _linux_machine_id()


def compute_machine_id() -> Optional[str]:
    """
    Returns a stable, privacy-preserving machine fingerprint.
    - Not personal info
    - Offline
    - Same value on same machine
    """
    raw = get_machine_id_raw()
    if not raw:
        return None
    # hash it so you never store raw machine identifiers
    payload = f"{MACHINE_ID_SALT}|{raw}".encode("utf-8", errors="ignore")
    return hashlib.sha256(payload).hexdigest()


# =========================
# License (RSA-PSS offline)
# =========================

LICENSE_FILENAME = "fileops.license"
ENV_LICENSE_JSON = "FILEOPS_LICENSE_JSON"


def load_public_key():
    if not FILEOPS_PUBLIC_KEY_PEM.strip():
        raise ValueError("No public key configured")
    return serialization.load_pem_public_key(FILEOPS_PUBLIC_KEY_PEM, backend=default_backend())


def canonical_payload_bytes(lic: dict) -> bytes:
    """Canonical JSON (stable) for signing/verifying. Excludes signature."""
    lic2 = dict(lic)
    lic2.pop("signature", None)
    return json.dumps(
        lic2,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify_license_signature_pss(lic: dict) -> tuple[bool, str]:
    sig_b64 = lic.get("signature")
    if not sig_b64:
        return False, "Missing signature"

    payload = canonical_payload_bytes(lic)

    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False, "Signature is not valid base64"

    try:
        pub = load_public_key()
    except ValueError:
        return False, "No public key configured"

    try:
        pub.verify(
            sig,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True, "OK"
    except InvalidSignature:
        return False, "Invalid signature"
    except Exception as e:
        return False, f"Verify error: {e}"


def _utc_today() -> str:
    # license dates are YYYY-MM-DD; compare as strings
    return datetime.utcnow().strftime("%Y-%m-%d")


def _load_license_text(license_path: Optional[Path] = None) -> Optional[str]:
    # 1) env var
    env = os.environ.get(ENV_LICENSE_JSON)
    if env and env.strip():
        return env.strip()

    # 2) explicit path
    if license_path:
        p = license_path.expanduser().resolve()
        if p.exists():
            return p.read_text(encoding="utf-8", errors="ignore").strip()

    # 3) next to executable
    exe_dir = Path(sys.argv[0]).resolve().parent
    p1 = exe_dir / LICENSE_FILENAME
    if p1.exists():
        return p1.read_text(encoding="utf-8", errors="ignore").strip()

    # 4) current working directory
    p2 = Path.cwd() / LICENSE_FILENAME
    if p2.exists():
        return p2.read_text(encoding="utf-8", errors="ignore").strip()

    return None


def verify_license(license_text: str) -> tuple[bool, str, Optional[dict]]:
    # -------------------------
    # Parse JSON
    # -------------------------
    try:
        lic = json.loads(license_text)
    except Exception as e:
        return False, f"License JSON parse error: {e}", None

    if not isinstance(lic, dict):
        return False, "License must be a JSON object", lic

    # -------------------------
    # Basic schema
    # -------------------------
    required = [
        "license_version",
        "product",
        "edition",
        "issued_at",
        "expires_at",
        "signature",
    ]
    missing = [k for k in required if k not in lic]
    if missing:
        return False, f"Missing fields: {', '.join(missing)}", lic

    if str(lic.get("product")) != APP_NAME:
        return False, f"Wrong product (expected {APP_NAME})", lic

    if str(lic.get("edition", "")).lower() != "pro":
        return False, "Edition is not 'pro'", lic

    # -------------------------
    # Date checks (UTC, YYYY-MM-DD)
    # -------------------------
    today = _utc_today()
    issued = str(lic.get("issued_at"))
    expires = str(lic.get("expires_at"))

    if issued > today:
        return False, f"License not valid yet (issued_at {issued})", lic

    if expires < today:
        return False, f"License expired (expires_at {expires})", lic

    # -------------------------
    # Machine lock (optional)
    # -------------------------
    machine_id = lic.get("machine_id")

    # null / "" / "null" => portable license
    if machine_id not in (None, "", "null"):
        local_id = compute_machine_id()
        if not local_id:
            return False, "Machine ID unavailable on this system", lic

        if str(machine_id) != str(local_id):
            return False, "License is locked to a different machine", lic

    # -------------------------
    # Signature verification (RSA-PSS)
    # -------------------------
    ok_sig, sig_msg = verify_license_signature_pss(lic)
    if not ok_sig:
        return False, sig_msg, lic

    # -------------------------
    # All checks passed
    # -------------------------
    return True, "OK", lic


def is_pro_unlocked(license_path: Optional[Path] = None) -> tuple[bool, str]:
    # This build intentionally does not enforce a commercial Pro gate.
    # Local ownership means the full feature set is always available.
    return True, "License checks disabled"


def require_pro(pro_enabled: bool, feature: str, reason: str = "") -> None:
    # Pro gating has been disabled for local ownership.
    return None


def is_owner_mode_enabled(ctx: Optional[typer.Context], explicit: bool = False) -> bool:
    if not ctx:
        return explicit
    owner_mode = bool(ctx.obj.get("owner_mode", False)) if ctx.obj else False
    return owner_mode or explicit


# =========================
# App / CLI
# =========================

app = typer.Typer(
    add_completion=False,
    help=f"{APP_NAME} — Safe file organization & duplicate cleanup",
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit.", is_eager=True),
    license_info: bool = typer.Option(False, "--license-info", help="Show license status and exit.", is_eager=True),
    license_path: Optional[Path] = typer.Option(None, "--license-path", help="Path to fileops.license (optional).", is_eager=True),
    owner_mode: bool = typer.Option(False, "--owner-mode", help="Enable owner mode for local, unrestricted file organization.", is_eager=True),
):
    ok, msg = is_pro_unlocked(license_path)
    ctx.obj = {"pro": ok, "license_msg": msg, "owner_mode": owner_mode}

    if version:
        typer.echo(f"{APP_NAME} {APP_VERSION}")
        raise typer.Exit()

    if license_info:
        typer.echo(f"{APP_NAME} {APP_VERSION}")
        typer.echo(f"Unlocked: {ok}")
        typer.echo(f"Owner mode: {'on' if owner_mode else 'off'}")
        typer.echo(f"Status: {msg}")
        raise typer.Exit()


# =========================
# Helpers
# =========================

DEFAULT_CATEGORIES: Dict[str, List[str]] = {
    "Images": [".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".tiff", ".bmp", ".svg"],
    "Videos": [".mp4", ".mov", ".mkv", ".avi", ".wmv", ".webm", ".m4v", ".mpeg", ".mpg"],
    "Audio": [".mp3", ".wav", ".m4a", ".flac", ".aac", ".ogg", ".opus", ".wma"],
    "Docs": [".pdf", ".doc", ".docx", ".txt", ".md", ".rtf", ".odt"],
    "Spreadsheets": [".xls", ".xlsx", ".csv", ".tsv", ".ods"],
    "Presentations": [".ppt", ".pptx", ".key", ".odp"],
    "Archives": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz"],
    "Installers": [".dmg", ".pkg", ".exe", ".msi", ".deb", ".rpm", ".app", ".apk"],
    "Code": [".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".c", ".cpp", ".cs", ".go", ".rs", ".html", ".css", ".scss", ".json", ".yaml", ".yml", ".xml", ".sql", ".sh", ".bat", ".ps1", ".php"],
    "Data": [".csv", ".json", ".yaml", ".yml", ".xml", ".sqlite", ".db", ".parquet", ".feather"],
    "System": [".ds_store", ".localized", ".thumbs.db", ".tmp", ".part"],
}

JOURNAL_DIRNAME = ".fileops_journals"


@dataclass
class Action:
    kind: str  # "move" | "rename" | "delete"
    src: str
    dst: Optional[str]
    reason: str
    ts: str


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def categorize(path: Path, categories: Dict[str, List[str]]) -> str:
    name = path.name.lower()
    for cat, exts in categories.items():
        if name in {".ds_store", "thumbs.db", ".localized"} and cat == "System":
            return "System"
        ext = path.suffix.lower()
        if ext in exts:
            return cat
    return "Other"


def safe_unique_path(dst: Path) -> Path:
    """If dst exists, append ' (n)' before suffix."""
    if not dst.exists():
        return dst
    stem, suffix = dst.stem, dst.suffix
    parent = dst.parent
    n = 2
    while True:
        candidate = parent / f"{stem} ({n}){suffix}"
        if not candidate.exists():
            return candidate
        n += 1


def file_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def bytes_to_human(n: int) -> str:
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"


# -------------------------
# Progress bar (lightweight)
# -------------------------
def progress_print(i: int, total: int, prefix: str) -> None:
    if total <= 0:
        return
    pct = (i / total) * 100
    bar_len = 24
    filled = int((i / total) * bar_len)
    bar = "█" * filled + "·" * (bar_len - filled)
    print(f"\r{prefix} [{bar}] {pct:6.2f}% ({i}/{total})", end="", flush=True)


def progress_done() -> None:
    print("")


# =========================
# Duplicates
# =========================
def find_duplicate_groups(
    root: Path,
    include_subfolders: bool,
    min_size_kb: int,
) -> List[List[Path]]:
    """
    Returns groups of duplicate files (each group length >= 2),
    based on SHA-256 hash, after grouping by file size.
    """
    it = root.rglob("*") if include_subfolders else root.glob("*")

    size_map: Dict[int, List[Path]] = {}
    for p in it:
        if not p.is_file():
            continue
        if JOURNAL_DIRNAME in p.parts:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size < (min_size_kb * 1024):
            continue
        size_map.setdefault(size, []).append(p)

    dup_groups: List[List[Path]] = []
    for _size, files in size_map.items():
        if len(files) < 2:
            continue

        hash_map: Dict[str, List[Path]] = {}

        to_hash = len(files)
        show_hash_progress = to_hash >= 2000

        for j, p in enumerate(files, start=1):
            if show_hash_progress and (j % 25 == 0 or j == to_hash):
                progress_print(j, to_hash, "Hashing")
            try:
                h = file_sha256(p)
            except OSError:
                continue
            hash_map.setdefault(h, []).append(p)

        if show_hash_progress:
            progress_done()

        for _h, same in hash_map.items():
            if len(same) >= 2:
                dup_groups.append(same)

    return dup_groups


def choose_keeper(files: List[Path], keep: str) -> Path:
    if keep == "first":
        return files[0]
    if keep == "newest":
        return max(files, key=lambda p: p.stat().st_mtime)
    if keep == "oldest":
        return min(files, key=lambda p: p.stat().st_mtime)
    return files[0]


# =========================
# Planning / Journals
# =========================
def build_plan(
    root: Path,
    organize_into: Path,
    days_to_archive: int,
    categories: Dict[str, List[str]],
    include_subfolders: bool,
    owner_mode: bool = False,
) -> List[Tuple[Path, Path, str]]:
    plan: List[Tuple[Path, Path, str]] = []
    cutoff = datetime.now() - timedelta(days=days_to_archive)

    excluded_roots = {
        (organize_into / "Archive").resolve(),
        (organize_into / "Duplicates").resolve(),
        (root / JOURNAL_DIRNAME).resolve(),
    }
    excluded_roots.update((organize_into / category).resolve() for category in categories)

    def is_excluded(path: Path) -> bool:
        resolved = path.resolve()
        return any(resolved == excluded or excluded in resolved.parents for excluded in excluded_roots)

    it = root.rglob("*") if include_subfolders else root.glob("*")
    files = [p for p in it if p.is_file() and not is_excluded(p)]

    total = len(files)
    show_progress = total >= 2000  # only show for big scans

    for idx, p in enumerate(files, start=1):
        if show_progress and (idx % 50 == 0 or idx == total):
            progress_print(idx, total, "Scanning")

        try:
            cat = categorize(p, categories)
            if owner_mode and p.name.lower() in {".ds_store", "thumbs.db", ".localized"}:
                cat = "System"
            mtime = datetime.fromtimestamp(p.stat().st_mtime)
        except OSError:
            continue

        if mtime < cutoff:
            dst_dir = organize_into / "Archive" / f"{mtime.year:04d}" / f"{mtime.month:02d}" / cat
            reason = f"older_than_{days_to_archive}d -> Archive/{mtime.year:04d}/{mtime.month:02d}/{cat}"
        else:
            dst_dir = organize_into / cat
            reason = f"categorized_as_{cat}"

        dst = safe_unique_path(dst_dir / p.name)

        if p.resolve() == dst.resolve():
            continue

        plan.append((p, dst, reason))

    if show_progress:
        progress_done()

    return plan


def write_journal(root: Path, actions: List[Action]) -> Path:
    journals_dir = root / JOURNAL_DIRNAME
    ensure_dir(journals_dir)
    jid = datetime.now().strftime("%Y%m%d-%H%M%S")
    jpath = journals_dir / f"journal-{jid}.jsonl"
    with jpath.open("w", encoding="utf-8") as f:
        for a in actions:
            f.write(json.dumps(asdict(a), ensure_ascii=False) + "\n")
    return jpath


def read_journal(journal_path: Path) -> List[Action]:
    actions: List[Action] = []
    with journal_path.open("r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            actions.append(Action(**d))
    return actions


# =========================
# Commands
# =========================
@app.command()
def organize(
    ctx: typer.Context,
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    organize_into: Optional[Path] = typer.Option(None, help="Destination root. Default: Desktop."),
    days_to_archive: int = typer.Option(60, help="Files older than this go to Archive/YYYY/MM/<Category>."),
    include_subfolders: bool = typer.Option(False, help="Scan recursively."),
    dry_run: bool = typer.Option(False, help="Preview only; do not move files."),
):
    """Run a smarter local organization pass using owner-mode defaults."""
    root = path.expanduser().resolve()
    dest_root = (organize_into or (Path.home() / "Desktop")).expanduser().resolve()
    effective_owner_mode = True

    plan = build_plan(root, dest_root, days_to_archive, DEFAULT_CATEGORIES, include_subfolders, effective_owner_mode)
    if not plan:
        typer.echo("No changes suggested.")
        raise typer.Exit()

    typer.echo(f"Planned actions: {len(plan)}")
    for src, dst, reason in plan[:200]:
        typer.echo(f"- MOVE  {src}  ->  {dst}   ({reason})")
    if len(plan) > 200:
        typer.echo(f"... and {len(plan)-200} more")

    if dry_run:
        return

    require_pro(ctx.obj.get("pro", False), "organize", ctx.obj.get("license_msg", ""))

    actions: List[Action] = []
    total = len(plan)
    show_progress = total >= 2000

    for i, (src, dst, reason) in enumerate(plan, start=1):
        if show_progress and (i % 50 == 0 or i == total):
            progress_print(i, total, "Organizing")
        ensure_dir(dst.parent)
        final_dst = safe_unique_path(dst)
        shutil.move(str(src), str(final_dst))
        actions.append(Action(kind="move", src=str(src), dst=str(final_dst), reason=reason, ts=now_iso()))

    if show_progress:
        progress_done()

    journal_path = write_journal(root, actions)
    typer.echo(f"Organized {len(actions)} files.")
    typer.echo(f"Journal saved: {journal_path}")


@app.command()
def scan(
    ctx: typer.Context,
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    organize_into: Optional[Path] = typer.Option(None, help="Destination root. Default: same as path."),
    days_to_archive: int = typer.Option(60, help="Files older than this go to Archive/YYYY/MM/<Category>."),
    include_subfolders: bool = typer.Option(False, help="Scan recursively."),
    owner_mode: bool = typer.Option(False, help="Use owner-mode sorting preferences for smarter organization."),
):
    """Preview what would happen (dry-run)."""
    root = path.expanduser().resolve()
    dest_root = (organize_into or root).expanduser().resolve()
    effective_owner_mode = is_owner_mode_enabled(ctx, owner_mode)

    plan = build_plan(root, dest_root, days_to_archive, DEFAULT_CATEGORIES, include_subfolders, effective_owner_mode)

    if not plan:
        typer.echo("No changes suggested.")
        raise typer.Exit()

    typer.echo(f"Planned actions: {len(plan)}")
    for src, dst, reason in plan[:200]:
        typer.echo(f"- MOVE  {src}  ->  {dst}   ({reason})")
    if len(plan) > 200:
        typer.echo(f"... and {len(plan)-200} more (use apply to execute).")


@app.command()
def apply(
    ctx: typer.Context,
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    organize_into: Optional[Path] = typer.Option(None, help="Destination root. Default: same as path."),
    days_to_archive: int = typer.Option(60),
    include_subfolders: bool = typer.Option(False),
    owner_mode: bool = typer.Option(False, help="Use owner-mode sorting preferences for smarter organization."),
):
    """Execute the plan and write a journal for undo."""
    require_pro(ctx.obj.get("pro", False), "apply", ctx.obj.get("license_msg", ""))

    root = path.expanduser().resolve()
    dest_root = (organize_into or root).expanduser().resolve()
    effective_owner_mode = is_owner_mode_enabled(ctx, owner_mode)

    plan = build_plan(root, dest_root, days_to_archive, DEFAULT_CATEGORIES, include_subfolders, effective_owner_mode)
    if not plan:
        typer.echo("No changes to apply.")
        raise typer.Exit()

    actions: List[Action] = []
    total = len(plan)
    show_progress = total >= 2000

    for i, (src, dst, reason) in enumerate(plan, start=1):
        if show_progress and (i % 50 == 0 or i == total):
            progress_print(i, total, "Moving")
        ensure_dir(dst.parent)
        final_dst = safe_unique_path(dst)
        shutil.move(str(src), str(final_dst))
        actions.append(Action(kind="move", src=str(src), dst=str(final_dst), reason=reason, ts=now_iso()))

    if show_progress:
        progress_done()

    journal_path = write_journal(root, actions)
    typer.echo(f"Applied {len(actions)} moves.")
    typer.echo(f"Journal saved: {journal_path}")


@app.command()
def dupes(
    ctx: typer.Context,
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    include_subfolders: bool = typer.Option(True, help="Search inside subfolders (recommended)."),
    min_size_kb: int = typer.Option(32, help="Ignore files smaller than this size (KB)."),
    keep: Literal["newest", "oldest", "first"] = typer.Option("newest", help="Which duplicate to keep."),
    move: bool = typer.Option(False, help="Move duplicates into Duplicates/ instead of just reporting."),
):
    """
    Find duplicate files by SHA-256 hash.
    All duplicate scanning and moving features are available locally.
    """
    root = path.expanduser().resolve()
    groups = find_duplicate_groups(root, include_subfolders, min_size_kb)

    if not groups:
        typer.echo("No duplicates found.")
        raise typer.Exit()

    # Reclaimable = all bytes except one copy per group
    reclaimable_bytes = 0
    for g in groups:
        sizes = [p.stat().st_size for p in g]
        reclaimable_bytes += sum(sizes) - max(sizes)

    total_dupe_files = sum(len(g) for g in groups)
    total_groups = len(groups)

    typer.echo(f"Duplicate groups: {total_groups}")
    typer.echo(f"Duplicate files (counting all copies): {total_dupe_files}")
    typer.echo(f"Reclaimable space: {bytes_to_human(reclaimable_bytes)}")

    # Print groups (cap to avoid huge spam)
    max_groups_to_print = 200
    for i, g in enumerate(groups[:max_groups_to_print], start=1):
        typer.echo(f"\nGroup {i} ({len(g)} copies):")
        for p in g:
            typer.echo(f"  {p}")
    if len(groups) > max_groups_to_print:
        typer.echo(f"\n... plus {len(groups)-max_groups_to_print} more groups (not printed).")

    # Report-only mode
    if not move:
        typer.echo(
            f"\nReport only: you can reclaim {bytes_to_human(reclaimable_bytes)}. "
            "Run with --move to move extra copies into Duplicates/."
        )
        raise typer.Exit()

    # Move mode is always enabled for local ownership.
    require_pro(ctx.obj.get("pro", False), "dupes --move", ctx.obj.get("license_msg", ""))

    dup_dir = root / "Duplicates"
    ensure_dir(dup_dir)

    actions: List[Action] = []
    moved = 0
    total_groups = len(groups)
    show_progress = total_groups >= 2000

    for gi, g in enumerate(groups, start=1):
        if show_progress and (gi % 25 == 0 or gi == total_groups):
            progress_print(gi, total_groups, "Processing dupes")

        keeper = choose_keeper(g, keep)
        extras = [p for p in g if p != keeper]

        for p in extras:
            target = safe_unique_path(dup_dir / p.name)
            shutil.move(str(p), str(target))
            actions.append(
                Action(
                    kind="move",
                    src=str(p),
                    dst=str(target),
                    reason=f"duplicate_of_kept={keeper.name} keep={keep}",
                    ts=now_iso(),
                )
            )
            moved += 1

    if show_progress:
        progress_done()

    journal_path = write_journal(root, actions)
    typer.echo(f"\nMoved {moved} duplicate files into: {dup_dir}")
    typer.echo(f"Journal saved: {journal_path}")
    exe_path = Path(sys.argv[0])
    exe_name = exe_path.name
    prefix = f"./{exe_name}" if os.name != "nt" and exe_path.parent == Path.cwd() else exe_name
    typer.echo(f"You can undo with: {prefix} undo <journal_file>")


@app.command()
def undo(
    ctx: typer.Context,
    journal: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
):
    """
    Undo an apply/dupes --move run using its journal file.
    """
    require_pro(ctx.obj.get("pro", False), "undo", ctx.obj.get("license_msg", ""))

    journal = journal.expanduser().resolve()
    actions = read_journal(journal)

    undone = 0
    for a in reversed(actions):
        if a.kind == "move" and a.dst:
            src_now = Path(a.dst)
            dst_back = Path(a.src)
            if src_now.exists():
                ensure_dir(dst_back.parent)
                dst_back = safe_unique_path(dst_back)
                shutil.move(str(src_now), str(dst_back))
                undone += 1

    typer.echo(f"Undid {undone} moves from {journal.name}")


if __name__ == "__main__":
    app()
