# ReconFile

**ReconFile** is a safe, **preview-first** CLI tool that helps you organize messy folders and find duplicate files — **without risking your data**.

No accounts. No network access. No license required. Full undo support.

---

## 🖱️ Zero command-line knowledge required

Just double-click `reconfile.exe` (Windows) or run `./reconfile` with no arguments
(macOS/Linux). It asks a few plain-English questions — which folder, what to do,
are you sure — and does the rest. Nothing changes until you explicitly say yes.

```
ReconFile 0.3.4 -- interactive mode
Which folder should I look at? (or 'q' to quit) [/Users/you/Downloads]:
Here's what I found in /Users/you/Downloads:
  - 214 file(s) could be organized into folders (Images, Docs, Videos, ...)
  - 12 duplicate file(s) that could be cleaned up
What would you like to do?
  1) Organize files into folders
  2) Clean up duplicates
  3) Do both
  4) Quit without changing anything
```

Everyone else can use the full flag-based commands below (`scan`, `apply`, `dupes`,
`undo`, `categories`) for scripting, automation, or finer control.

---

## ✨ Why ReconFile?

- **Preview-first** — see exactly what will happen before files move
- **Undo journals** — roll back changes safely
- **Duplicate detection** using SHA-256, with a fast prefilter for large files
- **Content-aware categorization** — sniffs file signatures so a JPEG saved as
  `.download` or a renamed installer still ends up in the right folder, not a junk drawer
- **Offline & private** — no telemetry, no phone-home

---

## 🧰 What it does

### 📁 Organize files
- Sorts files by extension into folders: Images, Videos, Audio, Docs, Ebooks,
  Subtitles, Fonts, Archives, Installers, Code (30+ file types covered out of the box)
- Falls back to sniffing file signatures for files with a missing/wrong extension
  (disable with `--no-sniff-content` if you want pure extension matching)
- Optionally archives old files into:

Archive/YYYY/MM/

- Prevents overwrites by auto-renaming
- Works recursively on large folders
- `apply --clean-empty-dirs` removes source folders left empty after organizing

---

### 🗂️ Custom categories
Don't like the built-in scheme? Point `scan`/`apply` at your own JSON file instead:

```bash
./reconfile categories                                  # show the active scheme
./reconfile categories --categories my_categories.json   # preview a custom one
./reconfile scan ~/Downloads --categories my_categories.json
```

A category file is `{"CategoryName": [".ext1", ".ext2"], ...}` — see
[categories.example.json](categories.example.json) for a template. Order matters:
the first category whose extension list contains a file's extension wins, so put
more specific categories first (e.g. a `Screenshots` category before a general
`Images` one if both list `.png`). `Archive`, `Duplicates`, and `Other` are
reserved names and can't be used as category names.

---

### 🔁 Find duplicates
- Detects duplicates by **SHA-256 hash**
- Shows duplicate groups and reclaimable disk space
- `--move` moves extra copies into `Duplicates/`, keeping exactly one per group

---

### ↩️ Undo support
- Every destructive operation writes a **journal**
- Journals can be replayed to undo changes
- No guessing — everything is recorded

---

### ✅ Confirmation prompts
`apply`, `dupes --move`, and `undo` show a summary and ask for confirmation before
touching any files. Pass `--yes` / `-y` to skip the prompt (useful in scripts).

---

## 🚀 Quick start (Windows)

Open **PowerShell** in the folder containing `reconfile.exe`.

> Windows may show a **"Windows protected your PC"** SmartScreen warning the first time you
> run a downloaded, unsigned executable. Click **More info → Run anyway** to proceed.

### Preview changes
```powershell
.\reconfile.exe scan C:\Users\You\Downloads
```
Find duplicates
```powershell
.\reconfile.exe dupes C:\Users\You\Downloads
```
Apply changes
```powershell
.\reconfile.exe apply C:\Users\You\Downloads
.\reconfile.exe dupes C:\Users\You\Downloads --move
```

- Applies the previewed plan safely
- Prevents overwrites with conflict-free naming
- Writes a journal for undo

Undo a run
```powershell
.\reconfile.exe undo .reconfile_journals\journal-YYYYMMDD-HHMMSS.jsonl
```
- Restores files to original locations
- Uses recorded journal entries
- Safe and deterministic

---

## 🍎 Quick start (macOS)

Open **Terminal** in the folder containing the downloaded `reconfile` binary.

```bash
chmod +x reconfile
```

> macOS Gatekeeper quarantines binaries downloaded from a browser and will refuse to run them
> ("cannot be opened because the developer cannot be verified"), since this build isn't
> Apple-notarized. Clear the quarantine flag once, then it runs normally:
> ```bash
> xattr -d com.apple.quarantine reconfile
> ```
> (Alternatively: right-click the binary → **Open** → **Open** in the confirmation dialog.)

### Preview changes
```bash
./reconfile scan ~/Downloads
```
Find duplicates
```bash
./reconfile dupes ~/Downloads
```
Apply changes
```bash
./reconfile apply ~/Downloads
./reconfile dupes ~/Downloads --move
```
Undo a run
```bash
./reconfile undo .reconfile_journals/journal-YYYYMMDD-HHMMSS.jsonl
```

---

## 🐧 Quick start (Linux)

```bash
chmod +x reconfile
./reconfile scan ~/Downloads
./reconfile dupes ~/Downloads
./reconfile apply ~/Downloads
./reconfile dupes ~/Downloads --move
./reconfile undo .reconfile_journals/journal-YYYYMMDD-HHMMSS.jsonl
```

---

## 🧪 Development

```bash
pip install -r requirements-dev.txt
pytest
```

---
🛠 Built with
Python · Typer · PyInstaller
Windows · macOS · Linux

---
📄 License

ReconFile is source-available and distributed under a proprietary license.
See [LICENSE.md](LICENSE.md) for details.
