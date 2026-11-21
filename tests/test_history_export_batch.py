import json
from pathlib import Path
from hash_identifier.detector import analyze_hash
from hash_identifier.history import add_history, load_history, delete_history, clear_history
from hash_identifier.export import export_records
from hash_identifier.batch import read_hashes, analyze_file

def test_history_roundtrip(tmp_path):
    p = tmp_path / "history.json"
    add_history(analyze_hash("a"*64), p)
    assert len(load_history(p)) == 1
    assert delete_history(1, p) == 1
    clear_history(p)
    assert load_history(p) == []

def test_exports(tmp_path):
    record = analyze_hash("a"*64).to_dict()
    for ext in ("json", "csv", "txt"):
        out = tmp_path / f"out.{ext}"
        export_records([record], out)
        assert out.exists() and out.stat().st_size > 0

def test_batch_reader_and_analysis(tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text("# comment\n" + "a"*64 + "\n\n" + "b"*40 + "\n")
    assert len(list(read_hashes(f))) == 2
    assert len(analyze_file(f)) == 2
