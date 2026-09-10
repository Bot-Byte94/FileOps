# FileOps

**FileOps** is a safe, **preview-first** CLI tool that helps you organize messy folders and find duplicate files — **without risking your data**.

No accounts. No network access. Full undo support.

---

## ✨ Why FileOps?

- **Preview-first** — see exactly what will happen before files move
- **Undo journals** — roll back changes safely
- **Duplicate detection** using SHA-256
- **Offline & private** — no telemetry, no phone-home

---

## 🧰 What it does

### 📁 Organize files
- Sorts files into folders like Images, Docs, Videos, Code, Archives
- Optionally archives old files into:

Archive/YYYY/MM/

- Prevents overwrites by auto-renaming
- Works recursively on large folders

---

### 🔁 Find duplicates
- Detects duplicates by **SHA-256 hash**
- Shows duplicate groups and reclaimable disk space
- Keeps exactly one copy per group
- **Pro mode** can move extra copies into `Duplicates/`

---

### ↩️ Undo support
- Every destructive operation writes a **journal**
- Journals can be replayed to undo changes
- No guessing — everything is recorded

---

## 🆓 Free vs Pro

| Feature | Basic (Free) | Pro |
|--------|--------------|-----|
| Scan & preview | ✅ | ✅ |
| File categorization | Preview | Apply |
| Archive old files | Preview | Apply |
| Duplicate detection | Report only | Move duplicates |
| Journaling | ❌ | ✅ |
| Undo support | ❌ | ✅ |
| Offline licensing | ❌ | ✅ |

Pro features are unlocked with an **offline license file**.
---

## 🚀 Quick start (Windows)

Open **PowerShell** in the folder containing `fileops.exe`.

### Preview changes
```powershell
.\fileops.exe scan C:\Users\You\Downloads
```
Find duplicates
```
.\fileops.exe dupes C:\Users\You\Downloads
```
✅ Apply changes (Pro)
```
.\fileops.exe apply C:\Users\You\Downloads
.\fileops.exe dupes C:\Users\You\Downloads --move
```

- Applies the previewed plan safely
- Prevents overwrites with conflict-free naming
- Writes a journal for undo

↩️ Undo a run (Pro)
```
.\fileops.exe undo .fileops_journals\journal-YYYYMMDD-HHMMSS.jsonl
```
- Restores files to original locations
- Uses recorded journal entries
- Safe and deterministic

---
🔐 Licensing & security

- Fully offline license verification
- RSA-PSS (SHA-256) cryptographic signatures
- Optional machine-locked licenses
- No internet required
---
🛠 Built with
Python · Typer · PyInstaller
Windows · macOS · Linux

---
📄 License

FileOps is source-available and distributed under a proprietary license.
Licenses for using the software are issued separately.
