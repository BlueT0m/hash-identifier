
import csv
from pathlib import Path
from datetime import datetime

from src.hash_identifier.detector import analyze_hash


def analyze_file(input_file, output_file="batch_results.csv"):
    """Analyze hashes from a text file and export results to CSV."""

    source = Path(input_file)
    destination = Path(output_file)

    if not source.is_file():
        print(f"[!] File not found: {source}")
        return False

    results = []

    try:
        with source.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                value = line.strip()

                if not value:
                    continue

                result = analyze_hash(value)
                result["line"] = line_number
                results.append(result)

        if not results:
            print("[!] No hashes found in the file.")
            return False

        fieldnames = [
            "line",
            "input",
            "length",
            "possible_algorithms",
            "confidence",
            "is_hexadecimal",
            "explanation",
        ]

        with destination.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                row = result.copy()
                row["possible_algorithms"] = ", ".join(
                    row["possible_algorithms"]
                )
                writer.writerow(row)

        print(f"\n[+] {len(results)} hashes analyzed.")
        print(f"[+] Results exported to: {destination}")
        return True

    except (OSError, UnicodeError, csv.Error) as error:
        print(f"[!] Batch analysis failed: {error}")
        return False
