
import base64
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


def is_valid_argon2_base64(value: str) -> bool:
    """Validate unpadded Base64 used in Argon2 PHC strings."""

    if not value:
        return False

    try:
        padding = "=" * (-len(value) % 4)

        decoded = base64.b64decode(
            value + padding,
            validate=True
        )

        encoded = base64.b64encode(decoded).decode("ascii").rstrip("=")

        return encoded == value

    except (ValueError, base64.binascii.Error):
        return False


def is_argon2(value: str) -> bool:
    """Validate the structure of an Argon2 PHC string."""

    parts = value.split("$")

    if len(parts) not in (5, 6) or parts[0] != "":
        return False

    if parts[1] not in ("argon2id", "argon2i", "argon2d"):
        return False

    if len(parts) == 6:
        if not re.fullmatch(r"v=(?:16|19)", parts[2]):
            return False

        parameters = parts[3]
        salt = parts[4]
        digest = parts[5]

    else:
        parameters = parts[2]
        salt = parts[3]
        digest = parts[4]

    values = {}

    for parameter in parameters.split(","):
        match = re.fullmatch(r"(m|t|p)=([1-9]\d*)", parameter)

        if not match:
            return False

        key, number = match.groups()

        if key in values:
            return False

        values[key] = int(number)

    if set(values) != {"m", "t", "p"}:
        return False

    if values["m"] < 8 * values["p"]:
        return False

    if not is_valid_argon2_base64(salt):
        return False

    if not is_valid_argon2_base64(digest):
        return False

    return True


def is_pbkdf2(value: str) -> bool:
    """Validate Passlib-style PBKDF2 hash strings."""

    pattern = (
        r"\$pbkdf2-(?:sha1|sha256|sha512)"
        r"\$[1-9]\d*"
        r"\$[./A-Za-z0-9]+"
        r"\$[./A-Za-z0-9]+"
    )

    return bool(re.fullmatch(pattern, value))


def identify_hash(value: str) -> list[str]:
    value = value.strip()

    if not value:
        return []

    results = []

    for algorithm, pattern in HASH_PATTERNS.items():
        if re.fullmatch(pattern, value):
            results.append(algorithm)

    if is_argon2(value):
        results.append("Argon2")

    if is_pbkdf2(value):
        results.append("PBKDF2")

    return results


def analyze_hash(value: str) -> dict:
    value = value.strip()
    algorithms = identify_hash(value)

    password_hashes = {
        "bcrypt",
        "Argon2",
        "PBKDF2",
        "MD5-crypt",
        "SHA-256-crypt",
        "SHA-512-crypt",
    }

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
            "from structure alone."
        )

    elif algorithms[0] in password_hashes:
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
