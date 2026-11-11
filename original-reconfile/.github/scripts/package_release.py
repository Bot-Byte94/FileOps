#!/usr/bin/env python3
"""Package the PyInstaller build output into a versioned, checksummed release asset.

Cross-platform by design (no shell-specific tools like zip/sha256sum/Compress-Archive)
so it runs identically on the Linux, macOS, and Windows GitHub-hosted runners.
"""
import hashlib
import os
import platform
import shutil
import sys
import zipfile
from pathlib import Path

APP_NAME = "ReconFile"
BUILD_NAME = "reconfile"  # matches fileops.spec's EXE(name=...)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_checksum(path: Path) -> None:
    digest = sha256_file(path)
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")


def main() -> None:
    ref_name = os.environ.get("GITHUB_REF_NAME", "0.0.0-dev")
    version = ref_name[1:] if ref_name.startswith("v") else ref_name
    # Pull request refs such as "1/merge" must not become path separators.
    version = "".join(c if c.isalnum() or c in ".-_" else "-" for c in version)

    os_name = os.environ.get("RUNNER_OS") or platform.system()
    is_windows = os_name == "Windows"
    arch = platform.machine() or "unknown"

    src = Path("dist") / (f"{BUILD_NAME}.exe" if is_windows else BUILD_NAME)
    if not src.exists():
        sys.exit(f"Build output not found: {src}")

    release_dir = Path("release")
    release_dir.mkdir(exist_ok=True)

    stem = f"{APP_NAME}-{version}-{os_name}-{arch}"
    binary_name = stem + (".exe" if is_windows else "")
    dst = release_dir / binary_name
    shutil.copy2(src, dst)
    if not is_windows:
        dst.chmod(0o755)
    write_checksum(dst)
    print(f"Packaged: {dst}")

    zip_path = release_dir / f"{stem}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(dst, arcname=binary_name)
    write_checksum(zip_path)
    print(f"Packaged: {zip_path}")


if __name__ == "__main__":
    main()
