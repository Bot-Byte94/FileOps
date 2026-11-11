# fileops.py

import sys
import json
import os
import shutil
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Literal

import typer

APP_NAME = "ReconFile"
APP_VERSION = "0.3.5"

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
):
    if version:
        typer.echo(f"{APP_NAME} {APP_VERSION}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        # No arguments at all -- e.g. someone double-clicked the executable.
        # Drop into a guided, no-CLI-experience-required walkthrough instead
        # of silently exiting or dumping a --help wall of text.
        run_wizard()
        raise typer.Exit()


# =========================
# Helpers
# =========================

DEFAULT_CATEGORIES: Dict[str, List[str]] = {
    "Images": [
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".tiff", ".tif",
        ".bmp", ".svg", ".ico", ".avif", ".raw", ".cr2", ".nef", ".arw", ".dng", ".psd",
    ],
    "Videos": [
        ".mp4", ".mov", ".mkv", ".avi", ".wmv", ".webm", ".flv", ".m4v", ".3gp",
        ".mpg", ".mpeg", ".ts",
    ],
    "Audio": [
        ".mp3", ".wav", ".m4a", ".flac", ".aac", ".ogg", ".wma", ".opus", ".aiff", ".mid", ".midi",
    ],
    "Docs": [
        ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".txt", ".md", ".rtf",
        ".odt", ".ods", ".odp", ".csv", ".pages", ".key", ".numbers", ".tex",
    ],
    "Ebooks": [".epub", ".mobi", ".azw", ".azw3", ".fb2"],
    "Subtitles": [".srt", ".vtt", ".sub", ".ass"],
    "Fonts": [".ttf", ".otf", ".woff", ".woff2", ".eot"],
    "Archives": [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst", ".tgz", ".tbz2", ".lz", ".lzma", ".iso",
    ],
    "Installers": [".dmg", ".pkg", ".exe", ".msi", ".deb", ".rpm", ".apk", ".appimage"],
    "Code": [
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".h", ".cs", ".go", ".rs",
        ".html", ".css", ".scss", ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf",
        ".php", ".rb", ".swift", ".kt", ".kts", ".sh", ".bash", ".zsh", ".sql", ".r", ".lua", ".pl",
        ".vue", ".dart", ".ipynb",
    ],
}

RESERVED_CATEGORY_NAMES = {"archive", "duplicates", "other"}

JOURNAL_DIRNAME = ".reconfile_journals"


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


def sniff_category(path: Path) -> Optional[str]:
    """
    Best-effort content-based categorization by file signature ("magic bytes"),
    used as a fallback when a file's extension is missing, wrong, or just not
    in the category list. This is what lets a JPEG saved as '.download' or a
    renamed installer end up in the right folder instead of dumped into
    'Other' -- something plain extension-matching file managers can't do.
    Reads only the first ~32 bytes, so it's cheap even across a whole tree.
    """
    try:
        with path.open("rb") as f:
            head = f.read(32)
    except OSError:
        return None

    if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or head[:6] in (b"GIF87a", b"GIF89a"):
        return "Images"
    if head[:5] == b"%PDF-":
        return "Docs"
    if head[:4] == b"RIFF":
        subtype = head[8:12]
        if subtype == b"WAVE":
            return "Audio"
        if subtype.startswith(b"AVI"):
            return "Videos"
    if head[4:8] == b"ftyp":
        return "Audio" if head[8:12] in (b"M4A ", b"M4B ") else "Videos"
    if head[:3] == b"ID3" or head[:2] == b"\xff\xfb":
        return "Audio"
    if head[:4] == b"OggS" or head[:4] == b"fLaC":
        return "Audio"
    if head[:4] == b"PK\x03\x04":
        return "Archives"
    if head[:6] == b"Rar!\x1a\x07":  # covers both RAR4 (...\x00) and RAR5 (...\x01\x00)
        return "Archives"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "Archives"
    if head[:2] == b"\x1f\x8b":
        return "Archives"
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF" or head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        return "Installers"
    return None


def categorize(path: Path, categories: Dict[str, List[str]], sniff: bool = True) -> str:
    ext = path.suffix.lower()
    for cat, exts in categories.items():
        if ext in exts:
            return cat
    if sniff:
        guessed = sniff_category(path)
        if guessed:
            return guessed
    return "Other"


def load_categories(categories_path: Optional[Path]) -> Dict[str, List[str]]:
    """
    Returns DEFAULT_CATEGORIES, or a user-supplied override loaded from a JSON
    file of the form {"CategoryName": [".ext1", ".ext2"], ...} -- lets people
    customize how files get sorted without touching the source.
    """
    if categories_path is None:
        return DEFAULT_CATEGORIES

    categories_path = categories_path.expanduser().resolve()
    try:
        raw = json.loads(categories_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise typer.BadParameter(f"Categories file not found: {categories_path}")
    except json.JSONDecodeError as e:
        raise typer.BadParameter(f"Categories file is not valid JSON: {e}")

    if not isinstance(raw, dict) or not raw:
        raise typer.BadParameter("Categories file must be a non-empty JSON object of {category: [extensions]}.")

    categories: Dict[str, List[str]] = {}
    for cat, exts in raw.items():
        if not isinstance(cat, str) or not cat.strip():
            raise typer.BadParameter("Category names must be non-empty strings.")
        if cat.strip().lower() in RESERVED_CATEGORY_NAMES:
            raise typer.BadParameter(
                f"'{cat}' is a reserved name (used for the Archive/Duplicates/Other folders) "
                "and can't be used as a category."
            )
        if not isinstance(exts, list) or not all(isinstance(e, str) for e in exts):
            raise typer.BadParameter(f"Category '{cat}' must map to a list of extension strings.")
        categories[cat.strip()] = [
            e.strip().lower() if e.strip().startswith(".") else f".{e.strip().lower()}" for e in exts
        ]

    return categories


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


QUICK_HASH_SAMPLE_BYTES = 65536


def file_quick_hash(path: Path, sample_bytes: int = QUICK_HASH_SAMPLE_BYTES) -> str:
    """
    Cheap fingerprint: hashes the first and last `sample_bytes` of the file
    instead of the whole thing. Used to skip full SHA-256 reads for same-size
    files that clearly differ, which matters most on large media/installers.
    """
    size = path.stat().st_size
    h = hashlib.sha256()
    with path.open("rb") as f:
        h.update(f.read(sample_bytes))
        if size > sample_bytes:
            f.seek(max(size - sample_bytes, 0))
            h.update(f.read(sample_bytes))
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

        # Cheap prefilter: same-size files with different first/last bytes can't
        # be duplicates, so skip the full SHA-256 read for them entirely.
        quick_map: Dict[str, List[Path]] = {}
        for p in files:
            try:
                qh = file_quick_hash(p)
            except OSError:
                continue
            quick_map.setdefault(qh, []).append(p)

        candidates = [p for same in quick_map.values() if len(same) >= 2 for p in same]

        hash_map: Dict[str, List[Path]] = {}

        to_hash = len(candidates)
        show_hash_progress = to_hash >= 2000

        for j, p in enumerate(candidates, start=1):
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
                # Sorted so "keep first" and newest/oldest ties (e.g. files copied
                # together with identical mtimes) resolve the same way every run,
                # rather than depending on unspecified OS directory-enumeration order.
                dup_groups.append(sorted(same, key=str))

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
    sniff_content: bool = True,
) -> List[Tuple[Path, Path, str]]:
    plan: List[Tuple[Path, Path, str]] = []
    cutoff = datetime.now() - timedelta(days=days_to_archive)

    it = root.rglob("*") if include_subfolders else root.glob("*")
    files = [p for p in it if p.is_file() and JOURNAL_DIRNAME not in p.parts]

    total = len(files)
    show_progress = total >= 2000  # only show for big scans

    for idx, p in enumerate(files, start=1):
        if show_progress and (idx % 50 == 0 or idx == total):
            progress_print(idx, total, "Scanning")

        cat = categorize(p, categories, sniff=sniff_content)
        mtime = datetime.fromtimestamp(p.stat().st_mtime)

        if mtime < cutoff:
            dst_dir = organize_into / "Archive" / f"{mtime.year:04d}" / f"{mtime.month:02d}" / cat
            reason = f"older_than_{days_to_archive}d -> Archive/{mtime.year:04d}/{mtime.month:02d}/{cat}"
        else:
            dst_dir = organize_into / cat
            reason = f"categorized_as_{cat}"

        naive_dst = dst_dir / p.name
        if p.resolve() == naive_dst.resolve():
            # Already exactly where it belongs -- don't let safe_unique_path treat
            # the file's own current path as a name collision with itself.
            continue

        # Note: dst_dir is deliberately not created here. Planning must have zero
        # filesystem side effects (scan is a dry-run); apply() creates directories
        # itself right before each move.
        dst = safe_unique_path(naive_dst)
        plan.append((p, dst, reason))

    if show_progress:
        progress_done()

    return plan


def execute_plan(plan: List[Tuple[Path, Path, str]]) -> List[Action]:
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

    return actions


def execute_dupes_move(groups: List[List[Path]], keep: str, dup_dir: Path) -> List[Action]:
    ensure_dir(dup_dir)
    actions: List[Action] = []
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

    if show_progress:
        progress_done()

    return actions


def remove_empty_dirs(root: Path, scope_dirs: Optional[Iterable[Path]] = None) -> List[Path]:
    """
    Bottom-up removal of directories left empty after files were moved out of
    them. Never touches root itself or the journal directory. Nothing here is
    journaled/undoable -- an empty directory holds no data, so there's nothing
    for undo to restore.

    If scope_dirs is given, only those directories and their ancestors (up to
    root) are considered -- i.e. folders this specific operation emptied.
    Without it, the entire tree under root is swept, which would also remove
    empty folders that had nothing to do with this run.
    """
    root = root.resolve()

    if scope_dirs is None:
        candidates = {d for d in root.rglob("*") if d.is_dir()}
    else:
        candidates = set()
        for start in scope_dirs:
            d = start.resolve()
            while d != root and d != d.parent:
                candidates.add(d)
                d = d.parent

    ordered = sorted(
        (d for d in candidates if JOURNAL_DIRNAME not in d.parts),
        key=lambda d: len(d.parts),
        reverse=True,  # deepest first, so a parent can become empty in the same pass
    )

    removed: List[Path] = []
    for d in ordered:
        try:
            next(d.iterdir())
        except StopIteration:
            d.rmdir()
            removed.append(d)
        except OSError:
            continue
    return removed


def write_journal(root: Path, actions: List[Action]) -> Path:
    journals_dir = root / JOURNAL_DIRNAME
    ensure_dir(journals_dir)
    jid = datetime.now().strftime("%Y%m%d-%H%M%S")
    jpath = journals_dir / f"journal-{jid}.jsonl"
    n = 2
    while jpath.exists():
        # Guards against two journal-writing commands landing in the same second,
        # which would otherwise silently overwrite the earlier run's undo history.
        jpath = journals_dir / f"journal-{jid}-{n}.jsonl"
        n += 1
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
# Interactive wizard (zero-argument mode)
# =========================
DAYS_TO_ARCHIVE_DEFAULT = 60
MIN_SIZE_KB_DEFAULT = 32


def _wizard_prompt_folder() -> Optional[Path]:
    default = str(Path.cwd())
    while True:
        raw = typer.prompt("Which folder should I look at? (or 'q' to quit)", default=default)
        if raw.strip().lower() in ("q", "quit", "exit"):
            return None
        candidate = Path(raw).expanduser().resolve()
        if candidate.is_dir():
            return candidate
        typer.secho(f"Can't find a folder at '{candidate}'. Try again.", fg=typer.colors.RED)


def _wizard_prompt_choice(prompt: str, options: List[Tuple[str, str]]) -> str:
    typer.echo(f"\n{prompt}")
    for i, (_, label) in enumerate(options, start=1):
        typer.echo(f"  {i}) {label}")
    while True:
        raw = typer.prompt("Enter a number").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        typer.echo(f"Please enter a number from 1 to {len(options)}.")


def _wizard_organize(root: Path) -> None:
    plan = build_plan(root, root, DAYS_TO_ARCHIVE_DEFAULT, DEFAULT_CATEGORIES, True)
    if not plan:
        typer.echo("Nothing to organize -- every file is already where it belongs.")
        return

    typer.echo(f"\nAbout to move {len(plan)} file(s) under {root}:")
    for src, dst, reason in plan[:20]:
        typer.echo(f"- MOVE  {src}  ->  {dst}   ({reason})")
    if len(plan) > 20:
        typer.echo(f"... and {len(plan) - 20} more.")
    if not typer.confirm("Proceed?", default=True):
        typer.echo("Skipped organizing.")
        return

    actions = execute_plan(plan)
    journal_path = write_journal(root, actions)
    typer.echo(f"Done -- moved {len(actions)} file(s). Journal saved: {journal_path}")

    removed = remove_empty_dirs(root, scope_dirs={src.parent for src, _, _ in plan})
    if removed:
        typer.echo(f"Also tidied up {len(removed)} now-empty folder(s).")


def _wizard_dedupe(root: Path) -> None:
    groups = find_duplicate_groups(root, True, MIN_SIZE_KB_DEFAULT)
    if not groups:
        typer.echo("No duplicates found.")
        return

    extra_files = sum(len(g) - 1 for g in groups)
    reclaimable = sum(sum(p.stat().st_size for p in g) - max(p.stat().st_size for p in g) for g in groups)
    typer.echo(
        f"\nFound {extra_files} duplicate file(s) across {len(groups)} group(s) "
        f"-- moving the extras could free up {bytes_to_human(reclaimable)}."
    )
    keep = _wizard_prompt_choice(
        "Which copy should be kept in each group?",
        [("newest", "Keep the newest copy"), ("oldest", "Keep the oldest copy"), ("first", "Keep whichever comes first")],
    )
    if not typer.confirm("Move the rest into a Duplicates/ folder?", default=True):
        typer.echo("Skipped duplicate cleanup.")
        return

    dup_dir = root / "Duplicates"
    actions = execute_dupes_move(groups, keep, dup_dir)
    journal_path = write_journal(root, actions)
    typer.echo(f"Done -- moved {len(actions)} duplicate file(s) into {dup_dir}. Journal saved: {journal_path}")


def run_wizard() -> None:
    typer.echo(f"{APP_NAME} {APP_VERSION} -- interactive mode")
    typer.echo("No commands needed here -- just answer the prompts. Nothing changes until you say so.")

    try:
        root = _wizard_prompt_folder()
        if root is None:
            typer.echo("Okay, nothing changed. Bye!")
            return

        typer.echo("\nLooking around...")
        plan = build_plan(root, root, DAYS_TO_ARCHIVE_DEFAULT, DEFAULT_CATEGORIES, True)
        groups = find_duplicate_groups(root, True, MIN_SIZE_KB_DEFAULT)

        if not plan and not groups:
            typer.echo(f"\n{root} already looks tidy -- nothing to organize and no duplicates found.")
            return

        typer.echo(f"\nHere's what I found in {root}:")
        if plan:
            typer.echo(f"  - {len(plan)} file(s) could be organized into folders (Images, Docs, Videos, ...)")
        if groups:
            extra_files = sum(len(g) - 1 for g in groups)
            typer.echo(f"  - {extra_files} duplicate file(s) that could be cleaned up")

        options: List[Tuple[str, str]] = []
        if plan:
            options.append(("organize", "Organize files into folders"))
        if groups:
            options.append(("dedupe", "Clean up duplicates"))
        if plan and groups:
            options.append(("both", "Do both"))
        options.append(("quit", "Quit without changing anything"))

        action = _wizard_prompt_choice("What would you like to do?", options)

        if action == "quit":
            typer.echo("Okay, nothing changed. Bye!")
            return
        if action in ("organize", "both"):
            _wizard_organize(root)
        if action in ("dedupe", "both"):
            # Re-scan for duplicates after organizing, since files may have moved.
            _wizard_dedupe(root)

        typer.echo("\nAll done!")

    except (typer.Abort, KeyboardInterrupt):
        typer.echo("\nCancelled -- nothing changed.")

    finally:
        try:
            input("\nPress Enter to exit...")
        except (EOFError, KeyboardInterrupt):
            pass


# =========================
# Commands
# =========================
@app.command(name="categories")
def show_categories(
    categories: Optional[Path] = typer.Option(
        None, "--categories", help="Inspect a custom JSON category file instead of the built-in scheme."
    ),
):
    """Show the category scheme that scan/apply would use (built-in, or --categories)."""
    active = load_categories(categories)
    for cat, exts in active.items():
        typer.echo(f"{cat}: {', '.join(exts)}")


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    organize_into: Optional[Path] = typer.Option(None, help="Destination root. Default: same as path."),
    days_to_archive: int = typer.Option(60, help="Files older than this go to Archive/YYYY/MM/<Category>."),
    include_subfolders: bool = typer.Option(False, help="Scan recursively."),
    categories: Optional[Path] = typer.Option(
        None, "--categories", help="JSON file of {category: [extensions]} to use instead of the built-in scheme."
    ),
    sniff_content: bool = typer.Option(
        True, help="Peek at file headers to correctly categorize files with missing/wrong extensions."
    ),
):
    """Preview what would happen (dry-run)."""
    root = path.expanduser().resolve()
    dest_root = (organize_into or root).expanduser().resolve()

    plan = build_plan(root, dest_root, days_to_archive, load_categories(categories), include_subfolders, sniff_content)

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
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    organize_into: Optional[Path] = typer.Option(None, help="Destination root. Default: same as path."),
    days_to_archive: int = typer.Option(60, help="Files older than this go to Archive/YYYY/MM/<Category>."),
    include_subfolders: bool = typer.Option(False, help="Scan recursively."),
    categories: Optional[Path] = typer.Option(
        None, "--categories", help="JSON file of {category: [extensions]} to use instead of the built-in scheme."
    ),
    clean_empty_dirs: bool = typer.Option(
        False, "--clean-empty-dirs", help="Remove source folders left empty after organizing (not undoable, but they're empty)."
    ),
    sniff_content: bool = typer.Option(
        True, help="Peek at file headers to correctly categorize files with missing/wrong extensions."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
):
    """Execute the plan and write a journal for undo."""
    root = path.expanduser().resolve()
    dest_root = (organize_into or root).expanduser().resolve()

    plan = build_plan(root, dest_root, days_to_archive, load_categories(categories), include_subfolders, sniff_content)
    if not plan:
        typer.echo("No changes to apply.")
        raise typer.Exit()

    if not yes:
        typer.echo(f"About to move {len(plan)} file(s) under {root}")
        for src, dst, reason in plan[:20]:
            typer.echo(f"- MOVE  {src}  ->  {dst}   ({reason})")
        if len(plan) > 20:
            typer.echo(f"... and {len(plan) - 20} more.")
        typer.confirm("Proceed?", abort=True)

    actions = execute_plan(plan)

    journal_path = write_journal(root, actions)
    typer.echo(f"Applied {len(actions)} moves.")
    typer.echo(f"Journal saved: {journal_path}")

    if clean_empty_dirs:
        removed = remove_empty_dirs(root, scope_dirs={src.parent for src, _, _ in plan})
        if removed:
            typer.echo(f"Removed {len(removed)} now-empty folder(s).")


@app.command()
def dupes(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    include_subfolders: bool = typer.Option(True, help="Search inside subfolders (recommended)."),
    min_size_kb: int = typer.Option(32, help="Ignore files smaller than this size (KB)."),
    keep: Literal["newest", "oldest", "first"] = typer.Option("newest", help="Which duplicate to keep."),
    move: bool = typer.Option(False, help="Move duplicates into Duplicates/ instead of just reporting."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt (only relevant with --move)."),
):
    """
    Find duplicate files by SHA-256 hash.
    Use --move to move extra copies into Duplicates/ (keeps one per group).
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
            f"\n(Report only) You can reclaim {bytes_to_human(reclaimable_bytes)}. "
            "Run with --move to move extra copies into Duplicates/."
        )
        raise typer.Exit()

    total_extras = total_dupe_files - total_groups
    if not yes:
        typer.echo(f"\nAbout to move {total_extras} duplicate file(s) into {root / 'Duplicates'} (keep={keep}).")
        typer.confirm("Proceed?", abort=True)

    dup_dir = root / "Duplicates"
    actions = execute_dupes_move(groups, keep, dup_dir)
    moved = len(actions)

    journal_path = write_journal(root, actions)
    typer.echo(f"\nMoved {moved} duplicate files into: {dup_dir}")
    typer.echo(f"Journal saved: {journal_path}")
    exe_path = Path(sys.argv[0])
    exe_name = exe_path.name
    prefix = f"./{exe_name}" if os.name != "nt" and exe_path.parent == Path.cwd() else exe_name
    typer.echo(f"You can undo with: {prefix} undo <journal_file>")


@app.command()
def undo(
    journal: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
):
    """
    Undo an apply/dupes --move run using its journal file.
    """
    journal = journal.expanduser().resolve()
    actions = read_journal(journal)
    move_actions = [a for a in actions if a.kind == "move" and a.dst]

    if not yes:
        typer.echo(f"About to reverse {len(move_actions)} move(s) recorded in {journal.name}")
        typer.confirm("Proceed?", abort=True)

    undone = 0
    skipped = 0
    for a in reversed(move_actions):
        src_now = Path(a.dst)
        dst_back = Path(a.src)
        if src_now.exists():
            ensure_dir(dst_back.parent)
            dst_back = safe_unique_path(dst_back)
            shutil.move(str(src_now), str(dst_back))
            undone += 1
        else:
            skipped += 1

    typer.echo(f"Undid {undone} moves from {journal.name}")
    if skipped:
        typer.echo(f"Skipped {skipped} move(s) whose file was no longer at its recorded location.")


if __name__ == "__main__":
    app()
