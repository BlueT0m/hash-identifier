
import re


HASH_PATTERNS = {
    "MD5": r"[a-fA-F0-9]{32}",
    "NTLM": r"[a-fA-F0-9]{32}",

    "SHA-1": r"[a-fA-F0-9]{40}",

    "SHA-224": r"[a-fA-F0-9]{56}",
    "SHA3-224": r"[a-fA-F0-9]{56}",

    "SHA-256": r"[a-fA-F0-9]{64}",
    "SHA3-256": r"[a-fA-F0-9]{64}",

    "SHA-384": r"[a-fA-F0-9]{96}",
    "SHA3-384": r"[a-fA-F0-9]{96}",

    "SHA-512": r"[a-fA-F0-9]{128}",
    "SHA3-512": r"[a-fA-F0-9]{128}",

    "bcrypt": (
        r"\$2[aby]\$"
        r"(?:0[4-9]|[12]\d|3[01])\$"
        r"[./A-Za-z0-9]{53}"
    ),

    "Argon2": (
        r"\$argon2(?:id|i|d)"
        r"\$v=\d+"
        r"\$m=[1-9]\d*,t=[1-9]\d*,p=[1-9]\d*"
        r"\$[A-Za-z0-9+/]+"
        r"\$[A-Za-z0-9+/]+"
    ),

    "PBKDF2": (
        r"\$pbkdf2-(?:sha1|sha256|sha512)"
        r"\$[1-9]\d*"
        r"\$[./A-Za-z0-9]+"
        r"\$[./A-Za-z0-9]+"
    ),

    "MD5-crypt": (
        r"\$1\$"
        r"[./A-Za-z0-9]{1,8}"
        r"\$[./A-Za-z0-9]{22}"
    ),

    "SHA-256-crypt": (
        r"\$5\$"
        r"(?:rounds=(?:[1-9]\d{3,8})\$)?"
        r"[./A-Za-z0-9]{1,16}"
        r"\$[./A-Za-z0-9]{43}"
    ),

    "SHA-512-crypt": (
        r"\$6\$"
        r"(?:rounds=(?:[1-9]\d{3,8})\$)?"
        r"[./A-Za-z0-9]{1,16}"
        r"\$[./A-Za-z0-9]{86}"
    ),
}


def identify_hash(value: str) -> list[str]:
    value = value.strip()

    if not value:
        return []

    return [
        algorithm
        for algorithm, pattern in HASH_PATTERNS.items()
        if re.fullmatch(pattern, value)
    ]


def analyze_hash(value: str) -> dict:
    value = value.strip()
    algorithms = identify_hash(value)

    if not value:
        confidence = "None"
        explanation = "Empty input"

    elif not algorithms:
        confidence = "None"
        explanation = "Unknown hash format"

    elif len(algorithms) > 1:
        confidence = "Ambiguous"
        explanation = (
            "Multiple algorithms share this format. "
            "The original algorithm cannot be determined "
            "from length and characters alone."
        )

    elif algorithms[0] in (
        "bcrypt",
        "Argon2",
        "PBKDF2",
        "MD5-crypt",
        "SHA-256-crypt",
        "SHA-512-crypt",
    ):
        confidence = "High"
        explanation = "Recognized password-hash structure"

    else:
        confidence = "Low"
        explanation = (
            "Length and character pattern match, "
            "but other algorithms may share this format."
        )

    return {
        "input": value,
        "length": len(value),
        "possible_algorithms": algorithms,
        "is_hexadecimal": bool(
            re.fullmatch(r"[a-fA-F0-9]+", value)
        ),
        "confidence": confidence,
        "explanation": explanation,
    }
