import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import fileops
from typer.testing import CliRunner

runner = CliRunner()

def test_version():
    r = runner.invoke(fileops.app, ["--version"])
    assert r.exit_code == 0
    assert "FileOps 0.3.6" in r.output

def test_safe_mode_organizes_top_level_document_only(tmp_path):
    (tmp_path / "note.txt").write_text("hello")
    (tmp_path / "installer.exe").write_text("installer")
    (tmp_path / "mod.jar").write_text("mod")
    (tmp_path / "pack.zip").write_text("archive")
    (tmp_path / "unknown.data").write_text("unknown")
    plan = fileops.build_plan(tmp_path, tmp_path, 100000, fileops.DEFAULT_CATEGORIES, True)
    assert [src.name for src, _, _ in plan] == ["note.txt"]

def test_safe_mode_never_touches_nested_files(tmp_path):
    nested = tmp_path / "CurseForge" / "mods"
    nested.mkdir(parents=True)
    (nested / "readme.txt").write_text("do not move")
    assert fileops.build_plan(tmp_path, tmp_path, 100000, fileops.DEFAULT_CATEGORIES, True) == []

def test_duplicate_move_is_disabled(tmp_path):
    (tmp_path / "a.txt").write_text("same"*10000)
    (tmp_path / "b.txt").write_text("same"*10000)
    result = runner.invoke(fileops.app, ["dupes", str(tmp_path), "--move", "--yes"])
    assert result.exit_code != 0
    assert (tmp_path / "a.txt").exists()
    assert (tmp_path / "b.txt").exists()

def test_symlink_is_excluded(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside.txt")
    outside.write_text("important")
    link = tmp_path / "linked.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        return
    assert fileops.is_protected(link, tmp_path)

def test_scan_has_no_side_effects(tmp_path):
    (tmp_path / "note.txt").write_text("hello")
    before = sorted(p.name for p in tmp_path.iterdir())
    result = runner.invoke(fileops.app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == before

def test_custom_protected_folder(tmp_path, monkeypatch):
    config = tmp_path / "protected.txt"
    config.write_text(str(tmp_path) + "\n")
    monkeypatch.setattr(fileops, "PROTECTED_CONFIG", config)
    (tmp_path / "note.txt").write_text("hello")
    assert fileops.safe_candidates(tmp_path) == []

def test_executable_sidecar_is_protected(tmp_path):
    (tmp_path / "game.exe").write_text("placeholder")
    (tmp_path / "game.png").write_text("asset")
    (tmp_path / "holiday.png").write_text("personal photo")
    names = {p.name for p in fileops.safe_candidates(tmp_path)}
    assert "game.png" not in names
    assert "holiday.png" in names

def test_manifest_protects_managed_directory(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "asset.png").write_text("asset")
    assert fileops.safe_candidates(tmp_path) == []

def test_loose_game_artwork_without_dependency_evidence_is_eligible(tmp_path):
    (tmp_path / "sprite.png").write_text("personal artwork")
    assert [p.name for p in fileops.safe_candidates(tmp_path)] == ["sprite.png"]
