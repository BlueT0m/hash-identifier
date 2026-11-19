
import json

from src.hash_identifier import history


def sample_result(value="abc123"):
    return {
        "input": value,
        "length": len(value),
        "possible_algorithms": ["MD5"],
        "confidence": "Low",
    }


def test_load_history_when_file_does_not_exist(tmp_path, monkeypatch):
    monkeypatch.setattr(
        history,
        "HISTORY_FILE",
        tmp_path / "history.json"
    )

    assert history.load_history() == []


def test_save_and_load_history(tmp_path, monkeypatch):
    monkeypatch.setattr(
        history,
        "HISTORY_FILE",
        tmp_path / "history.json"
    )

    result = sample_result()

    assert history.save_analysis(result) is True
    assert history.load_history() == [result]


def test_save_multiple_analyses(tmp_path, monkeypatch):
    monkeypatch.setattr(
        history,
        "HISTORY_FILE",
        tmp_path / "history.json"
    )

    first = sample_result("first")
    second = sample_result("second")

    history.save_analysis(first)
    history.save_analysis(second)

    assert history.load_history() == [first, second]


def test_invalid_json_returns_empty_history(tmp_path, monkeypatch):
    file = tmp_path / "history.json"
    file.write_text("{invalid json", encoding="utf-8")

    monkeypatch.setattr(history, "HISTORY_FILE", file)

    assert history.load_history() == []


def test_delete_history_entry(tmp_path, monkeypatch):
    file = tmp_path / "history.json"

    monkeypatch.setattr(history, "HISTORY_FILE", file)

    first = sample_result("first")
    second = sample_result("second")

    history.save_analysis(first)
    history.save_analysis(second)

    assert history.delete_history_entry(1) is True
    assert history.load_history() == [second]


def test_delete_invalid_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(
        history,
        "HISTORY_FILE",
        tmp_path / "history.json"
    )

    history.save_analysis(sample_result())

    assert history.delete_history_entry(0) is False
    assert history.delete_history_entry(2) is False


def test_clear_history(tmp_path, monkeypatch):
    monkeypatch.setattr(
        history,
        "HISTORY_FILE",
        tmp_path / "history.json"
    )

    history.save_analysis(sample_result())

    assert history.clear_history() is True
    assert history.load_history() == []


def test_invalid_json_structure_returns_empty_history(tmp_path, monkeypatch):
    file = tmp_path / "history.json"
    file.write_text(json.dumps({"input": "abc"}), encoding="utf-8")

    monkeypatch.setattr(history, "HISTORY_FILE", file)

    assert history.load_history() == []
