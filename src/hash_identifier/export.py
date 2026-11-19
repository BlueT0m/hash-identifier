
import csv
from pathlib import Path
from datetime import datetime

EXPORT_FILE = Path("hash_export.csv")

PASSWORD_HASHES = {
    "bcrypt",
    "Argon2",
    "PBKDF2",
    "MD5-crypt",
    "SHA-256-crypt",
    "SHA-512-crypt",
}


def get_category(algorithms):
    if not algorithms:
        return "Unknown"

    categories = {
        "Password hash" if algorithm in PASSWORD_HASHES
        else "General hash"
        for algorithm in algorithms
    }

    if len(categories) > 1:
        return "Mixed formats"

    return categories.pop()


def export_history(history):
    if not history:
        print("\n[!] No data to export.")
        return False

    fieldnames = [
        "date",
        "input",
        "length",
        "algorithms",
        "algorithm_count",
        "category",
        "confidence",
        "is_hexadecimal",
    ]

    try:
        with EXPORT_FILE.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames
            )

            writer.writeheader()

            for item in history:
                algorithms = item.get(
                    "possible_algorithms", []
                )

                writer.writerow({
                    "date": datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "input": item.get("input", ""),
                    "length": item.get("length", 0),
                    "algorithms": ", ".join(algorithms),
                    "algorithm_count": len(algorithms),
                    "category": get_category(algorithms),
                    "confidence": item.get("confidence", ""),
                    "is_hexadecimal": item.get(
                        "is_hexadecimal", False
                    ),
                })

        print(f"\n[+] Export completed: {EXPORT_FILE}")
        return True

    except (OSError, csv.Error) as error:
        print(f"\n[!] Export failed: {error}")
        return False
