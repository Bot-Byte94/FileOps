# FileOps unified workspace

This repository now preserves two related Python applications:

- `Code/fileops.py`: FileOps 0.3.6 with machine-bound license verification.
- `original-reconfile/fileops.py`: ReconFile 0.3.5 with preview-first file organization, duplicate detection, and undo.
- `original-reconfile/tests/`: original test suite.
- `.github/workflows/validate-cross-platform.yml`: tests and builds the original ReconFile implementation on Windows, macOS, and Linux.

## Run the original ReconFile CLI

```bash
cd original-reconfile
python -m pip install -r requirements.txt
python fileops.py --help
```

See `original-reconfile/README.md` for usage.

## Release status

This is a source consolidation, **not yet a fully integrated single application**. Workflow artifacts are for validation and are not automatically published as GitHub Releases. The newer FileOps code has an empty embedded license verification public key and cannot verify signed licenses as configured.

The original `original-reconfile/LICENSE.md` prohibits redistribution without permission. Confirm redistribution rights before publishing binaries or source in a new distribution. Also review the committed `.fileops_journals/` data for sensitive paths before promoting the repository.

Do not delete either original repository until the unified application is tested and approved.
