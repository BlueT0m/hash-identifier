"""Batch processing helpers."""
from pathlib import Path
from .detector import analyze_hash

def read_hashes(filename):
    with Path(filename).open(encoding="utf-8") as f:
        for line in f:
            value = line.strip()
            if value and not value.startswith("#"):
                yield value

def analyze_file(filename):
    return [analyze_hash(value).to_dict() for value in read_hashes(filename)]
