import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fileops
from typer.testing import CliRunner

runner = CliRunner()


def write(path: Path, content: bytes = b"x") -> Path:
    path.write_bytes(content)
    return path


# =========================
# categorize()
# =========================


def test_categorize_known_extension():
    assert fileops.categorize(Path("photo.JPG"), fileops.DEFAULT_CATEGORIES) == "Images"


def test_categorize_unknown_extension_falls_back_to_other():
    assert fileops.categorize(Path("weird.xyz123"), fileops.DEFAULT_CATEGORIES) == "Other"


def test_categorize_new_extensions_added_to_default_scheme():
    assert fileops.categorize(Path("book.epub"), fileops.DEFAULT_CATEGORIES) == "Ebooks"
    assert fileops.categorize(Path("movie.srt"), fileops.DEFAULT_CATEGORIES) == "Subtitles"
    assert fileops.categorize(Path("font.woff2"), fileops.DEFAULT_CATEGORIES) == "Fonts"


# =========================
# sniff_category() / content-based fallback
# =========================


def test_sniff_category_detects_png_signature(tmp_path):
    p = write(tmp_path / "mystery.download", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
    assert fileops.sniff_category(p) == "Images"


def test_sniff_category_detects_pdf_signature(tmp_path):
    p = write(tmp_path / "weird.xyz", b"%PDF-1.4\n" + b"\x00" * 50)
    assert fileops.sniff_category(p) == "Docs"


def test_sniff_category_detects_zip_signature(tmp_path):
    p = write(tmp_path / "noext", b"PK\x03\x04" + b"\x00" * 50)
    assert fileops.sniff_category(p) == "Archives"


def test_sniff_category_detects_rar4_and_rar5(tmp_path):
    """Regression test: RAR5 (WinRAR's default format since v5) has a longer
    signature than RAR4 and was previously not recognized at all."""
    rar4 = write(tmp_path / "old.dat", b"Rar!\x1a\x07\x00" + b"\x00" * 20)
    rar5 = write(tmp_path / "new.dat", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 20)
    assert fileops.sniff_category(rar4) == "Archives"
    assert fileops.sniff_category(rar5) == "Archives"


def test_sniff_category_distinguishes_riff_wav_from_avi(tmp_path):
    wav = write(tmp_path / "a.dat", b"RIFF" + b"\x00" * 4 + b"WAVE" + b"\x00" * 20)
    avi = write(tmp_path / "b.dat", b"RIFF" + b"\x00" * 4 + b"AVI " + b"\x00" * 20)
    assert fileops.sniff_category(wav) == "Audio"
    assert fileops.sniff_category(avi) == "Videos"


def test_sniff_category_returns_none_for_unrecognized_content(tmp_path):
    p = write(tmp_path / "plain.dat", b"just some random text, not a known format")
    assert fileops.sniff_category(p) is None


def test_categorize_falls_back_to_content_sniff_for_unknown_extension(tmp_path):
    p = write(tmp_path / "mystery.download", b"%PDF-1.4\n" + b"\x00" * 50)
    assert fileops.categorize(p, fileops.DEFAULT_CATEGORIES) == "Docs"


def test_categorize_with_sniff_disabled_ignores_content(tmp_path):
    p = write(tmp_path / "mystery.download", b"%PDF-1.4\n" + b"\x00" * 50)
    assert fileops.categorize(p, fileops.DEFAULT_CATEGORIES, sniff=False) == "Other"


# =========================
# load_categories()
# =========================


def test_load_categories_defaults_when_no_path_given():
    assert fileops.load_categories(None) == fileops.DEFAULT_CATEGORIES


def test_load_categories_from_custom_file(tmp_path):
    custom = tmp_path / "cats.json"
    custom.write_text('{"Screenshots": [".PNG"]}', encoding="utf-8")
    loaded = fileops.load_categories(custom)
    assert loaded == {"Screenshots": [".png"]}


def test_load_categories_strips_whitespace_around_extensions(tmp_path):
    custom = tmp_path / "cats.json"
    custom.write_text('{"Screenshots": [" .PNG ", " jpg "]}', encoding="utf-8")
    loaded = fileops.load_categories(custom)
    assert loaded == {"Screenshots": [".png", ".jpg"]}


def test_load_categories_rejects_reserved_name(tmp_path):
    custom = tmp_path / "cats.json"
    custom.write_text('{"Archive": [".zip"]}', encoding="utf-8")
    try:
        fileops.load_categories(custom)
        assert False, "expected BadParameter"
    except Exception as e:
        assert "reserved" in str(e).lower()


def test_load_categories_rejects_malformed_json(tmp_path):
    custom = tmp_path / "cats.json"
    custom.write_text("not json", encoding="utf-8")
    try:
        fileops.load_categories(custom)
        assert False, "expected BadParameter"
    except Exception as e:
        assert "json" in str(e).lower()


def test_load_categories_missing_file(tmp_path):
    try:
        fileops.load_categories(tmp_path / "missing.json")
        assert False, "expected BadParameter"
    except Exception as e:
        assert "not found" in str(e).lower()


# =========================
# safe_unique_path()
# =========================


def test_safe_unique_path_no_collision(tmp_path):
    target = tmp_path / "a.txt"
    assert fileops.safe_unique_path(target) == target


def test_safe_unique_path_collision_appends_counter(tmp_path):
    write(tmp_path / "a.txt")
    write(tmp_path / "a (2).txt")
    result = fileops.safe_unique_path(tmp_path / "a.txt")
    assert result == tmp_path / "a (3).txt"


# =========================
# build_plan() -- organizing
# =========================


def test_build_plan_categorizes_files(tmp_path):
    write(tmp_path / "note.txt")
    write(tmp_path / "script.py")
    plan = fileops.build_plan(tmp_path, tmp_path, 60, fileops.DEFAULT_CATEGORIES, False)
    dsts = {src.name: dst.parent.name for src, dst, _ in plan}
    assert dsts == {"note.txt": "Docs", "script.py": "Code"}


def test_build_plan_is_idempotent_on_already_organized_files(tmp_path):
    """Regression test: re-scanning an already-organized tree must not propose
    renaming files to '(2)' just because the destination path equals their
    current path."""
    docs = tmp_path / "Docs"
    docs.mkdir()
    write(docs / "note.txt")

    plan = fileops.build_plan(tmp_path, tmp_path, 60, fileops.DEFAULT_CATEGORIES, True)
    assert plan == []


def test_build_plan_has_no_filesystem_side_effects(tmp_path):
    """Regression test: planning (used by the dry-run `scan` command) must not
    create destination directories on disk."""
    write(tmp_path / "note.txt")
    fileops.build_plan(tmp_path, tmp_path, 60, fileops.DEFAULT_CATEGORIES, False)
    assert not (tmp_path / "Docs").exists()


def test_build_plan_archives_old_files(tmp_path):
    import os
    import time

    old_file = write(tmp_path / "old.txt")
    old_time = time.time() - 200 * 86400
    os.utime(old_file, (old_time, old_time))

    plan = fileops.build_plan(tmp_path, tmp_path, 60, fileops.DEFAULT_CATEGORIES, False)
    assert len(plan) == 1
    _, dst, reason = plan[0]
    assert "Archive" in dst.parts
    assert reason.startswith("older_than_60d")


# =========================
# remove_empty_dirs()
# =========================


def test_remove_empty_dirs_removes_nested_empty_dirs_bottom_up(tmp_path):
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    removed = fileops.remove_empty_dirs(tmp_path)
    assert set(removed) == {tmp_path / "a", tmp_path / "a" / "b", tmp_path / "a" / "b" / "c"}
    assert not (tmp_path / "a").exists()


def test_remove_empty_dirs_leaves_non_empty_dirs_and_root_alone(tmp_path):
    keep = tmp_path / "keep"
    keep.mkdir()
    write(keep / "file.txt")
    (tmp_path / "empty").mkdir()

    removed = fileops.remove_empty_dirs(tmp_path)

    assert tmp_path.exists()
    assert keep.exists()
    assert not (tmp_path / "empty").exists()
    assert removed == [tmp_path / "empty"]


def test_remove_empty_dirs_never_touches_journal_dir(tmp_path):
    journals = tmp_path / fileops.JOURNAL_DIRNAME
    journals.mkdir()
    removed = fileops.remove_empty_dirs(tmp_path)
    assert journals.exists()
    assert removed == []


def test_remove_empty_dirs_with_scope_ignores_unrelated_empty_dirs(tmp_path):
    """Regression test: --clean-empty-dirs must only remove folders this
    operation emptied, not sweep the whole tree for any empty folder."""
    touched = tmp_path / "touched"
    touched.mkdir()
    unrelated = tmp_path / "unrelated_empty_folder"
    unrelated.mkdir()

    removed = fileops.remove_empty_dirs(tmp_path, scope_dirs={touched})

    assert removed == [touched]
    assert not touched.exists()
    assert unrelated.exists()


# =========================
# find_duplicate_groups()
# =========================


def test_find_duplicate_groups_detects_true_duplicates(tmp_path):
    write(tmp_path / "a.bin", b"A" * 1000)
    write(tmp_path / "b.bin", b"A" * 1000)
    groups = fileops.find_duplicate_groups(tmp_path, False, 0)
    assert len(groups) == 1
    assert {p.name for p in groups[0]} == {"a.bin", "b.bin"}


def test_find_duplicate_groups_returns_deterministic_order(tmp_path):
    """Regression test: group file order (and therefore 'keep first'/mtime-tie
    behavior) must not depend on unspecified OS directory-enumeration order."""
    write(tmp_path / "z.bin", b"A" * 1000)
    write(tmp_path / "a.bin", b"A" * 1000)
    write(tmp_path / "m.bin", b"A" * 1000)
    groups = fileops.find_duplicate_groups(tmp_path, False, 0)
    assert [p.name for p in groups[0]] == ["a.bin", "m.bin", "z.bin"]


def test_find_duplicate_groups_quick_hash_prefilter_does_not_false_positive(tmp_path):
    """Regression test: same-size files with different content (even if they
    share prefix/suffix bytes) must not be reported as duplicates."""
    write(tmp_path / "a.bin", b"A" * 500 + b"1" * 1000 + b"A" * 500)
    write(tmp_path / "b.bin", b"A" * 500 + b"2" * 1000 + b"A" * 500)
    groups = fileops.find_duplicate_groups(tmp_path, False, 0)
    assert groups == []


def test_find_duplicate_groups_respects_min_size(tmp_path):
    write(tmp_path / "a.bin", b"A" * 10)
    write(tmp_path / "b.bin", b"A" * 10)
    groups = fileops.find_duplicate_groups(tmp_path, False, min_size_kb=1)
    assert groups == []


# =========================
# Journals
# =========================


def test_write_journal_round_trip(tmp_path):
    actions = [fileops.Action(kind="move", src="a", dst="b", reason="r", ts=fileops.now_iso())]
    jpath = fileops.write_journal(tmp_path, actions)
    loaded = fileops.read_journal(jpath)
    assert loaded == actions


def test_write_journal_never_collides(tmp_path):
    """Regression test: two journal-writing operations must never overwrite
    each other, even when they land in the same wall-clock second."""
    actions_a = [fileops.Action(kind="move", src="a", dst="a2", reason="first", ts=fileops.now_iso())]
    actions_b = [fileops.Action(kind="move", src="b", dst="b2", reason="second", ts=fileops.now_iso())]

    path_a = fileops.write_journal(tmp_path, actions_a)
    path_b = fileops.write_journal(tmp_path, actions_b)

    assert path_a != path_b
    assert fileops.read_journal(path_a) == actions_a
    assert fileops.read_journal(path_b) == actions_b


# =========================
# CLI integration
# =========================


def test_cli_version():
    result = runner.invoke(fileops.app, ["--version"])
    assert result.exit_code == 0
    assert "FileOps 0.3.6" in result.output


def test_cli_categories_shows_default_scheme():
    result = runner.invoke(fileops.app, ["categories"])
    assert result.exit_code == 0
    assert "Images:" in result.output


def test_cli_scan_uses_custom_categories(tmp_path):
    custom = tmp_path / "cats.json"
    custom.write_text('{"Screenshots": [".png"]}', encoding="utf-8")
    write(tmp_path / "shot.png")

    result = runner.invoke(fileops.app, ["scan", str(tmp_path), "--categories", str(custom)])
    assert result.exit_code == 0
    assert "Screenshots" in result.output


def test_cli_scan_rejects_reserved_category_name(tmp_path):
    custom = tmp_path / "cats.json"
    custom.write_text('{"Archive": [".zip"]}', encoding="utf-8")

    result = runner.invoke(fileops.app, ["scan", str(tmp_path), "--categories", str(custom)])
    assert result.exit_code != 0
    assert "reserved" in result.output.lower()


def test_cli_scan_reports_plan_without_moving(tmp_path):
    write(tmp_path / "note.txt")
    result = runner.invoke(fileops.app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "note.txt" in result.output
    assert (tmp_path / "note.txt").exists()
    assert not (tmp_path / "Docs").exists()


def test_cli_apply_requires_confirmation_by_default(tmp_path):
    write(tmp_path / "note.txt")
    result = runner.invoke(fileops.app, ["apply", str(tmp_path)], input="n\n")
    assert result.exit_code != 0
    assert (tmp_path / "note.txt").exists()


def test_cli_apply_with_yes_moves_files(tmp_path):
    write(tmp_path / "note.txt")
    result = runner.invoke(fileops.app, ["apply", str(tmp_path), "--yes"])
    assert result.exit_code == 0
    assert (tmp_path / "Docs" / "note.txt").exists()


def test_cli_apply_clean_empty_dirs_removes_leftover_folder(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    write(sub / "note.txt")
    unrelated = tmp_path / "unrelated_empty_folder"
    unrelated.mkdir()

    result = runner.invoke(
        fileops.app, ["apply", str(tmp_path), "--include-subfolders", "--clean-empty-dirs", "--yes"]
    )
    assert result.exit_code == 0
    assert (tmp_path / "Docs" / "note.txt").exists()
    assert not sub.exists()
    assert unrelated.exists()  # untouched by this run -- clean-empty-dirs must not sweep the whole tree


def test_cli_apply_without_clean_empty_dirs_leaves_leftover_folder(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    write(sub / "note.txt")

    result = runner.invoke(fileops.app, ["apply", str(tmp_path), "--include-subfolders", "--yes"])
    assert result.exit_code == 0
    assert (tmp_path / "Docs" / "note.txt").exists()
    assert sub.exists()


def test_cli_apply_undo_round_trip(tmp_path):
    write(tmp_path / "note.txt")
    runner.invoke(fileops.app, ["apply", str(tmp_path), "--yes"])
    assert (tmp_path / "Docs" / "note.txt").exists()

    journal = next((tmp_path / fileops.JOURNAL_DIRNAME).glob("*.jsonl"))
    result = runner.invoke(fileops.app, ["undo", str(journal), "--yes"])
    assert result.exit_code == 0
    assert (tmp_path / "note.txt").exists()
    assert not (tmp_path / "Docs" / "note.txt").exists()


def test_cli_dupes_move_and_undo(tmp_path):
    write(tmp_path / "a.txt", b"same")
    write(tmp_path / "b.txt", b"same")
    result = runner.invoke(
        fileops.app, ["dupes", str(tmp_path), "--min-size-kb", "0", "--move", "--yes"]
    )
    assert result.exit_code == 0
    assert (tmp_path / "Duplicates").exists()
    assert sum(1 for _ in (tmp_path / "Duplicates").iterdir()) == 1

    journal = next((tmp_path / fileops.JOURNAL_DIRNAME).glob("*.jsonl"))
    result = runner.invoke(fileops.app, ["undo", str(journal), "--yes"])
    assert result.exit_code == 0
    assert not list((tmp_path / "Duplicates").iterdir())


# =========================
# Interactive wizard (zero-argument mode)
# =========================


def test_wizard_quit_immediately_does_nothing(tmp_path):
    write(tmp_path / "note.txt")
    result = runner.invoke(fileops.app, [], input="q\n")
    assert result.exit_code == 0
    assert "nothing changed" in result.output.lower()
    assert (tmp_path / "note.txt").exists()


def test_wizard_retries_on_invalid_folder_then_reports_tidy(tmp_path):
    result = runner.invoke(fileops.app, [], input=f"/no/such/folder\n{tmp_path}\n\n")
    assert result.exit_code == 0
    assert "can't find a folder" in result.output.lower()
    assert "already looks tidy" in result.output.lower()


def test_wizard_organize_only_flow(tmp_path):
    write(tmp_path / "note.txt")
    result = runner.invoke(fileops.app, [], input=f"{tmp_path}\n1\ny\n\n")
    assert result.exit_code == 0
    assert (tmp_path / "Docs" / "note.txt").exists()
    assert "all done" in result.output.lower()


def test_wizard_can_decline_at_menu(tmp_path):
    write(tmp_path / "note.txt")
    result = runner.invoke(fileops.app, [], input=f"{tmp_path}\n2\n\n")
    assert result.exit_code == 0
    assert (tmp_path / "note.txt").exists()
    assert not (tmp_path / "Docs").exists()


def test_wizard_both_flow_organizes_and_dedupes(tmp_path):
    write(tmp_path / "a.bin", b"x" * 50000)
    write(tmp_path / "a_copy.bin", b"x" * 50000)
    write(tmp_path / "script.py", b"print(1)")

    result = runner.invoke(fileops.app, [], input=f"{tmp_path}\n3\ny\n1\ny\n\n")
    assert result.exit_code == 0
    assert (tmp_path / "Code" / "script.py").exists()
    assert (tmp_path / "Duplicates").exists()
    assert sum(1 for _ in (tmp_path / "Duplicates").iterdir()) == 1
