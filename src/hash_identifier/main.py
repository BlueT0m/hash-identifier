from src.hash_identifier.batch import analyze_file
from src.hash_identifier.detector import analyze_hash
from src.hash_identifier.history import (
    save_analysis,
    display_history,
    clear_history,
    load_history,
    delete_history_entry,
)
from src.hash_identifier.export import export_history, get_category


def display_banner():
    print("\033[96m")
    print("=" * 50)
    print("              HASH IDENTIFIER")
    print("          CYBERSECURITY TOOL v4.0")
    print("=" * 50)
    print("\033[0m")


def display_menu():
    print("\n========== MAIN MENU ==========")
    print("1. Identify hash")
    print("2. View history")
    print("3. Delete history entry")
    print("4. Export CSV")
    print("5. Clear history")
    print("6. Batch hash analysis")
    print("7. Exit")
    print("=" * 31)


def display_analysis(result):
    algorithms = result["possible_algorithms"]

    print("\n" + "=" * 50)
    print("                 ANALYSIS")
    print("=" * 50)

    print(f"Input            : {result['input']}")
    print(f"Input length     : {result['length']}")
    print(f"Hexadecimal      : {result['is_hexadecimal']}")
    print(f"Confidence       : {result['confidence']}")
    print(f"Candidates found : {len(algorithms)}")
    print(f"Category         : {get_category(algorithms)}")
    print(f"Explanation      : {result['explanation']}")

    print("\nPossible algorithms:")

    if algorithms:
        for algorithm in algorithms:
            print(f"\033[92m  [+] {algorithm}\033[0m")
    else:
        print("\033[91m  [-] Unknown format\033[0m")

    print("=" * 50)


def identify_hash():
    value = input("\n[?] Enter hash: ").strip()

    if not value:
        print("\033[91m[!] Empty input.\033[0m")
        return

    result = analyze_hash(value)

    if save_analysis(result):
        print("\n[+] Analysis saved.")

    display_analysis(result)


def delete_entry():
    display_history()

    try:
        index = int(input("\n[?] Entry number to delete: "))
        delete_history_entry(index)

    except ValueError:
        print("\n[!] Enter a valid number.")


def clear_all_history():
    confirm = input(
        "\n[?] Clear all history? (y/n): "
    ).strip().lower()

    if confirm == "y":
        if clear_history():
            print("\n[+] History cleared.")
    else:
        print("\n[*] Operation cancelled.")



def main():
    display_banner()

    while True:
        try:
            display_menu()
            choice = input("\n[?] Select an option: ").strip()

            if choice == "1":
                identify_hash()
            elif choice == "2":
                display_history()
            elif choice == "3":
                delete_entry()
            elif choice == "4":
                export_history(load_history())
            elif choice == "5":
                clear_all_history()
            elif choice == "6":
                input_file = input(
                    "\n[?] Input TXT file: "
                ).strip()

                output_file = input(
                    "[?] Output CSV file (default: batch_results.csv): "
                ).strip()

                if not output_file:
                    output_file = "batch_results.csv"

                analyze_file(input_file, output_file)
            elif choice == "7":
                print("\n[*] Closing Hash Identifier...")
                break
            else:
                print("\n[!] Invalid option. Choose 1 to 7.")

        except KeyboardInterrupt:
            print("\n\n[*] Operation interrupted.")

        except EOFError:
            print("\n\n[*] Closing Hash Identifier...")
            break


if __name__ == "__main__":
    main()
