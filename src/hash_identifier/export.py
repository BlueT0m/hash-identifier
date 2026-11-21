"""Export analysis records to JSON, CSV or plain text."""
import csv
import json
from pathlib import Path

def export_records(records, destination, fmt=None):
    path = Path(destination)
    kind = (fmt or path.suffix.lstrip(".") or "txt").lower()
    if kind == "json":
        path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    elif kind == "csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["id", "timestamp", "input", "confidence", "candidates", "explanation"])
            writer.writeheader()
            for r in records:
                row = dict(r)
                row["candidates"] = "; ".join(c.get("name", "") for c in r.get("candidates", []))
                writer.writerow({k: row.get(k, "") for k in writer.fieldnames})
    elif kind == "txt":
        lines = []
        for r in records:
            names = ", ".join(c.get("name", "") for c in r.get("candidates", [])) or "Aucun"
            lines.append(f"ID: {r.get('id', '-')}\nHash: {r.get('input', '')}\nConfiance: {r.get('confidence', '')}\nFormats: {names}\nExplication: {r.get('explanation', '')}\n")
        path.write_text("\n".join(lines), encoding="utf-8")
    else:
        raise ValueError("Format non pris en charge. Utilise json, csv ou txt.")
    return path
