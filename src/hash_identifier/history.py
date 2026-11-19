
import json
from pathlib import Path

HISTORY_FILE = Path("hash_history.json")


def load_history():
    """Load analysis history from the JSON file."""

    if not HISTORY_FILE.exists():
        return []

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except (json.JSONDecodeError, OSError):
        return []


def save_analysis(result):
    """Save one analysis result to history."""

    history = load_history()
    history.append(result)

    try:
        with HISTORY_FILE.open("w", encoding="utf-8") as file:
            json.dump(history, file, indent=4, ensure_ascii=False)

        return True

    except OSError as error:
        print(f"\n[!] History save failed: {error}")
        return False


def display_history():
    """Display all saved analyses."""

    history = load_history()

    if not history:
        print("\n[!] No analysis history.")
        return

    print("\n========== ANALYSIS HISTORY ==========")

    for index, item in enumerate(history, start=1):
        algorithms = ", ".join(
            item.get("possible_algorithms", [])
        ) or "Unknown"

        print(f"\n[{index}]")
        print(f"Input: {item.get('input', 'N/A')}")
        print(f"Length: {item.get('length', 'N/A')}")
        print(f"Algorithms: {algorithms}")
        print(f"Confidence: {item.get('confidence', 'N/A')}")

    print("\n======================================")


def delete_history_entry(index):
    """Delete one history entry using its displayed number."""

    history = load_history()

    if not history:
        print("\n[!] History is empty.")
        return False

    if not isinstance(index, int) or index < 1 or index > len(history):
        print("\n[!] Invalid entry number.")
        return False

    deleted = history.pop(index - 1)

    try:
        with HISTORY_FILE.open("w", encoding="utf-8") as file:
            json.dump(history, file, indent=4, ensure_ascii=False)

        print(f"\n[+] Entry deleted: {deleted.get('input', 'N/A')}")
        return True

    except OSError as error:
        print(f"\n[!] History update failed: {error}")
        return False


def clear_history():
    """Delete all saved history entries."""

    try:
        with HISTORY_FILE.open("w", encoding="utf-8") as file:
            json.dump([], file, indent=4)

        return True

    except OSError as error:
        print(f"\n[!] History clearing failed: {error}")
        return False

