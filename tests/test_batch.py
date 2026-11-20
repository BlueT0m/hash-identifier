
from src.hash_identifier.batch import analyze_file


def test_batch_export(tmp_path):
    source = tmp_path / "hashes.txt"
    output = tmp_path / "results.csv"

    source.write_text(
        "5d41402abc4b2a76b9719d911017c592\n"
        "invalidhash\n",
        encoding="utf-8",
    )

    assert analyze_file(source, output) is True
    assert output.exists()


def test_batch_missing_file(tmp_path):
    source = tmp_path / "missing.txt"
    output = tmp_path / "results.csv"

    assert analyze_file(source, output) is False


def test_batch_empty_file(tmp_path):
    source = tmp_path / "empty.txt"
    output = tmp_path / "results.csv"
    source.write_text("", encoding="utf-8")

    assert analyze_file(source, output) is False

