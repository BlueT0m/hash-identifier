
import argparse

from src.hash_identifier.detector import analyze_hash
from src.hash_identifier.batch import analyze_file
from src.hash_identifier.main import display_analysis
from src.hash_identifier.history import (
    display_history,
    save_analysis,
    delete_history_entry,
    clear_history,
    load_history,
)
from src.hash_identifier.export import export_history


def main():
    parser = argparse.ArgumentParser(
        description="Hash Identifier CLI"
    )

    subparsers = parser.add_subparsers(dest="command")

    identify_parser = subparsers.add_parser("identify")
    identify_parser.add_argument("hash")

    batch_parser = subparsers.add_parser("batch")
    batch_parser.add_argument("input")
    batch_parser.add_argument(
        "-o", "--output",
        default="batch_results.csv"
    )

    subparsers.add_parser("history")

    export_parser = subparsers.add_parser("export")
    export_parser.add_argument(
        "-o", "--output",
        default="hash_export.csv"
    )

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("index", type=int)

    subparsers.add_parser("clear")

    args = parser.parse_args()

    if args.command == "identify":
        result = analyze_hash(args.hash)

        if save_analysis(result):
            print("\n[+] Analysis saved.")

        display_analysis(result)

    elif args.command == "batch":
        analyze_file(args.input, args.output)

    elif args.command == "history":
        display_history()

    elif args.command == "export":
        export_history(load_history())

    elif args.command == "delete":
        delete_history_entry(args.index)

    elif args.command == "clear":
        if clear_history():
            print("[+] History cleared.")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
