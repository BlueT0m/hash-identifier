"""Command-line interface."""
import argparse
import json
from pathlib import Path
from . import __version__
from .detector import analyze_hash
from .history import DEFAULT_PATH, add_history, load_history, delete_history, clear_history
from .batch import analyze_file
from .export import export_records

def _print_analysis(data, verbose=False):
    print(f"Confiance : {data['confidence']}")
    if data["candidates"]:
        print("Formats possibles :")
        for c in data["candidates"]:
            print(f"  - {c['name']} ({c['confidence']})")
            if verbose:
                print(f"    {c['reason']}")
    else:
        print("Aucun format reconnu.")
    if verbose:
        print(f"Explication : {data['explanation']}")

def build_parser():
    p = argparse.ArgumentParser(prog="hash-identifier", description="Identification structurelle de formats de hash.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    i = sub.add_parser("identify", help="Analyser une valeur")
    i.add_argument("hash")
    i.add_argument("--json", action="store_true")
    i.add_argument("--verbose", action="store_true")
    i.add_argument("--quiet", action="store_true")
    i.add_argument("--no-history", action="store_true")
    b = sub.add_parser("batch", help="Analyser un fichier, une valeur par ligne")
    b.add_argument("file")
    b.add_argument("--output")
    b.add_argument("--format", choices=["json", "csv", "txt"])
    b.add_argument("--json", action="store_true")
    b.add_argument("--verbose", action="store_true")
    b.add_argument("--quiet", action="store_true")
    b.add_argument("--no-history", action="store_true")
    h = sub.add_parser("history", help="Afficher l'historique")
    s = sub.add_parser("search", help="Rechercher dans l'historique")
    s.add_argument("term")
    sub.add_parser("stats", help="Statistiques de l'historique")
    e = sub.add_parser("export", help="Exporter l'historique")
    e.add_argument("file")
    e.add_argument("--format", choices=["json", "csv", "txt"])
    d = sub.add_parser("delete", help="Supprimer une entrée")
    d.add_argument("id", type=int)
    c = sub.add_parser("clear", help="Vider l'historique")
    c.add_argument("--yes", action="store_true")
    return p

def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "identify":
        result = analyze_hash(args.hash).to_dict()
        if not args.no_history:
            add_history(analyze_hash(args.hash))
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif not args.quiet:
            _print_analysis(result, args.verbose)
    elif args.command == "batch":
        results = analyze_file(args.file)
        if not args.no_history:
            for r in results:
                from .detector import Analysis, Candidate
                add_history(Analysis(r["input"], [Candidate(**x) for x in r["candidates"]], r["confidence"], r["explanation"]))
        if args.output:
            export_records(results, args.output, args.format)
        elif args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        elif not args.quiet:
            for r in results:
                print(f"{r['input']} : {', '.join(c['name'] for c in r['candidates']) or 'Inconnu'}")
    elif args.command == "history":
        print(json.dumps(load_history(), indent=2, ensure_ascii=False))
    elif args.command == "search":
        term = args.term.lower()
        matches = [r for r in load_history() if term in r.get("input", "").lower() or term in json.dumps(r.get("candidates", [])).lower()]
        print(json.dumps(matches, indent=2, ensure_ascii=False))
    elif args.command == "stats":
        records = load_history()
        counts = {}
        for r in records:
            for c in r.get("candidates", []):
                counts[c.get("name", "Unknown")] = counts.get(c.get("name", "Unknown"), 0) + 1
        print(json.dumps({"total": len(records), "formats": counts}, indent=2, ensure_ascii=False))
    elif args.command == "export":
        export_records(load_history(), args.file, args.format)
        print(f"Export terminé : {args.file}")
    elif args.command == "delete":
        print(f"Entrées supprimées : {delete_history(args.id)}")
    elif args.command == "clear":
        if args.yes:
            clear_history()
            print("Historique vidé.")
        else:
            answer = input("Vider tout l'historique ? [y/N] ").strip().lower()
            if answer == "y":
                clear_history()
                print("Historique vidé.")
            else:
                print("Annulé.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
