# FileOps

FileOps 0.3.6 is a free, offline, preview-first file organizer and duplicate finder for Windows, macOS, and Linux. No license key, account, or subscription is required.

## Run from source

```sh
python -m pip install -r requirements.txt
python fileops.py
```

Running with no arguments opens the guided interactive wizard. Use `python fileops.py --help` for CLI commands.

## Test and build

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q tests
python -m PyInstaller --noconfirm fileops.spec
```

GitHub Actions builds and tests on all three operating systems. Download build artifacts from the Actions run after checks pass. These are not yet public GitHub Release assets.

## Previous implementations

- `original-reconfile/` preserves the original ReconFile 0.3.5 source and documentation.
- `Code/` and `Archive/` contain legacy FileOps 0.3.6 premium/license-key implementations and archived materials; they are **not** the supported executable and are **not** included in the new builds.
- The supported entry point is now the root `fileops.py`.

Do not commit private keys, licenses, personal journals, or other user data. This software moves files: preview before applying changes and keep backups.

## License

The original ReconFile license remains in `original-reconfile/LICENSE.md`. As the rights holder, update distribution terms explicitly before republishing or redistributing this project.
