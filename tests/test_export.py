
import csv

from src.hash_identifier import export


def sample_result(value="abc123", algorithms=None):
    return {
        "input": value,
        "length": len(value),
        "possible_algorithms": algorithms or ["MD5"],
        "confidence": "Low",
        "is_hexadecimal": True,
    }


def test_export_history(tmp_path, monkeypatch):
    file = tmp_path / "export.csv"
    monkeypatch.setattr(export, "EXPORT_FILE", file)

    history = [
        sample_result("abc123", ["MD5"]),
        sample_result("password", ["bcrypt"]),
    ]

    assert export.export_history(history) is True

    with file.open("r", encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert len(rows) == 2
    assert rows[0]["input"] == "abc123"
    assert rows[1]["input"] == "password"


def test_export_overwrites_previous_data(tmp_path, monkeypatch):
    file = tmp_path / "export.csv"
    monkeypatch.setattr(export, "EXPORT_FILE", file)

    export.export_history([sample_result("first")])
    export.export_history([sample_result("second")])

    with file.open("r", encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert len(rows) == 1
    assert rows[0]["input"] == "second"


def test_export_empty_history(tmp_path, monkeypatch):
    file = tmp_path / "export.csv"
    monkeypatch.setattr(export, "EXPORT_FILE", file)

    assert export.export_history([]) is False
    assert not file.exists()


def test_get_category():
    assert export.get_category(["MD5"]) == "General hash"
    assert export.get_category(["bcrypt"]) == "Password hash"
    assert export.get_category(["MD5", "bcrypt"]) == "Mixed formats"
    assert export.get_category([]) == "Unknown"


def test_export_csv_columns(tmp_path, monkeypatch):
    file = tmp_path / "export.csv"
    monkeypatch.setattr(export, "EXPORT_FILE", file)

    export.export_history([sample_result()])

    with file.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)

        assert reader.fieldnames == [
            "date",
            "input",
            "length",
            "algorithms",
            "algorithm_count",
            "category",
            "confidence",
            "is_hexadecimal",
        ]

