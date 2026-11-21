"""Small local JSON history store."""
import json
from pathlib import Path
from datetime import datetime, timezone

DEFAULT_PATH = Path("history.json")

def load_history(path=DEFAULT_PATH):
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []

def save_history(entries, path=DEFAULT_PATH):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)

def add_history(analysis, path=DEFAULT_PATH):
    entries = load_history(path)
    item = analysis.to_dict()
    item["id"] = max((e.get("id", 0) for e in entries), default=0) + 1
    item["timestamp"] = datetime.now(timezone.utc).isoformat()
    entries.append(item)
    save_history(entries, path)
    return item

def delete_history(entry_id, path=DEFAULT_PATH):
    entries = load_history(path)
    kept = [e for e in entries if e.get("id") != entry_id]
    save_history(kept, path)
    return len(entries) - len(kept)

def clear_history(path=DEFAULT_PATH):
    save_history([], path)
