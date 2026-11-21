"""Structural hash-format detection. This module never cracks or verifies hashes."""
from __future__ import annotations
import base64
import re
from dataclasses import asdict, dataclass
from typing import Optional

@dataclass
class Candidate:
    name: str
    confidence: str
    reason: str

@dataclass
class Analysis:
    input: str
    candidates: list[Candidate]
    confidence: str
    explanation: str

    def to_dict(self):
        return {"input": self.input, "candidates": [asdict(c) for c in self.candidates],
                "confidence": self.confidence, "explanation": self.explanation}

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

def _b64_valid(value: str, min_bytes: int) -> bool:
    if not value or not _B64.fullmatch(value):
        return False
    try:
        raw = base64.b64decode(value + "=" * ((-len(value)) % 4), validate=True)
        return len(raw) >= min_bytes and base64.b64encode(raw).decode().rstrip("=") == value.rstrip("=")
    except Exception:
        return False

def _argon2(value: str) -> Optional[str]:
    parts = value.split("$")
    if len(parts) not in (5, 6) or parts[0] != "" or parts[1] not in ("argon2id", "argon2i", "argon2d"):
        return None
    i = 2
    if len(parts) == 6:
        if not re.fullmatch(r"v=(16|19)", parts[2]):
            return None
        i = 3
    params = parts[i].split(",")
    if len(params) != 3:
        return None
    values = {}
    for item in params:
        if not re.fullmatch(r"[mtp]=[1-9][0-9]*", item):
            return None
        k, v = item.split("=")
        if k in values:
            return None
        values[k] = int(v)
    if set(values) != {"m", "t", "p"} or values["m"] < 8 * values["p"]:
        return None
    if not _b64_valid(parts[i+1], 8) or not _b64_valid(parts[i+2], 4):
        return None
    return parts[1]

def _pbkdf2(value: str) -> Optional[str]:
    # Passlib/Django-style: $pbkdf2-sha256$rounds$salt$checksum
    m = re.fullmatch(r"\$(pbkdf2-(?:sha1|sha256|sha512))\$([1-9][0-9]*)\$([A-Za-z0-9./]+)\$([A-Za-z0-9./+=]+)", value)
    if m and int(m.group(2)) >= 1:
        return m.group(1)
    # Werkzeug-style: pbkdf2:sha256:iterations$salt$hex-digest
    m = re.fullmatch(r"pbkdf2:(sha256|sha512|sha1):([1-9][0-9]*)\$([^$]+)\$([0-9a-fA-F]+)", value)
    if m and len(m.group(4)) >= 32 and len(m.group(4)) % 2 == 0:
        return "PBKDF2-" + m.group(1).upper()
    return None

def _scrypt(value: str) -> bool:
    if value.startswith("$scrypt$"):
        return bool(re.fullmatch(r"\$scrypt\$ln=[0-9]{1,2},r=[1-9][0-9]*,p=[1-9][0-9]*\$[^$]+\$[^$]+", value))
    if value.startswith("scrypt$"):
        return len(value.split("$")) == 4
    return False

def analyze_hash(value: str) -> Analysis:
    raw = value.strip()
    candidates: list[Candidate] = []
    if not raw:
        return Analysis(raw, [], "None", "Entrée vide.")

    def add(name, confidence, reason):
        candidates.append(Candidate(name, confidence, reason))

    argon = _argon2(raw)
    if argon:
        add(argon.upper(), "High", "Préfixe Argon2 reconnu et paramètres/base64 valides.")
    elif raw.startswith(("$argon2", "$argon")):
        pass

    pb = _pbkdf2(raw)
    if pb:
        add(pb.upper(), "High", "Structure PBKDF2 reconnue.")
    if _scrypt(raw):
        add("scrypt", "High", "Structure scrypt reconnue.")

    if re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", raw):
        add("bcrypt", "High", "Préfixe, coût et longueur bcrypt reconnus.")
    if re.fullmatch(r"\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}", raw):
        add("MD5-crypt", "High", "Structure MD5-crypt reconnue.")
    if re.fullmatch(r"\$5\$(?:rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{43}", raw):
        add("SHA-256-crypt", "High", "Structure SHA-256-crypt reconnue.")
    if re.fullmatch(r"\$6\$(?:rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{86}", raw):
        add("SHA-512-crypt", "High", "Structure SHA-512-crypt reconnue.")

    low = raw.lower()
    if re.fullmatch(r"\*[0-9a-f]{40}", low):
        add("MySQL 4.1+", "High", "Format MySQL 4.1+ : astérisque suivi de 40 caractères hexadécimaux.")
    if re.fullmatch(r"[0-9a-f]{16}", low):
        add("MySQL 3.23", "Low", "16 caractères hexadécimaux, format partagé avec d'autres empreintes.")
        add("DES crypt", "Low", "Longueur compatible avec certaines représentations DES crypt.")
    if re.fullmatch(r"[0-9a-f]{32}", low):
        add("MD5", "Ambiguous", "32 caractères hexadécimaux.")
        add("NTLM", "Ambiguous", "NTLM utilise également 32 caractères hexadécimaux.")
        add("LM", "Low", "Une empreinte LM est représentée par 32 caractères hexadécimaux.")
    if re.fullmatch(r"[0-9a-f]{40}", low):
        add("SHA-1", "High", "40 caractères hexadécimaux.")
    if re.fullmatch(r"[0-9a-f]{56}", low):
        add("SHA-224", "High", "56 caractères hexadécimaux.")
    if re.fullmatch(r"[0-9a-f]{64}", low):
        add("SHA-256", "High", "64 caractères hexadécimaux.")
    if re.fullmatch(r"[0-9a-f]{96}", low):
        add("SHA-384", "High", "96 caractères hexadécimaux.")
    if re.fullmatch(r"[0-9a-f]{128}", low):
        add("SHA-512", "High", "128 caractères hexadécimaux.")
    if re.fullmatch(r"[0-9a-f]{64}", low):
        add("SHA3-256", "Low", "Longueur compatible avec SHA3-256, indistinguable de SHA-256 sur la seule longueur.")
    if re.fullmatch(r"[0-9a-f]{56}", low):
        add("SHA3-224", "Low", "Longueur compatible avec SHA3-224, indistinguable de SHA-224 sur la seule longueur.")
    if re.fullmatch(r"[0-9a-f]{96}", low):
        add("SHA3-384", "Low", "Longueur compatible avec SHA3-384, indistinguable de SHA-384 sur la seule longueur.")
    if re.fullmatch(r"[0-9a-f]{128}", low):
        add("SHA3-512", "Low", "Longueur compatible avec SHA3-512, indistinguable de SHA-512 sur la seule longueur.")

    # NetNTLMv2 capture form: USER::DOMAIN:challenge:response:blob
    if re.fullmatch(r"[^:\s]+::[^:\s]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32,}:[0-9a-fA-F]+", raw):
        add("NetNTLMv2", "High", "Structure de capture NetNTLMv2 reconnue.")
    # NetNTLMv1 capture form: USER::DOMAIN:response:response:challenge
    if re.fullmatch(r"[^:\s]+::[^:\s]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}", raw):
        add("NetNTLMv1", "High", "Structure de capture NetNTLMv1 reconnue.")

    if not candidates:
        explanation = "Aucun format pris en charge n'a été reconnu."
        confidence = "None"
    elif len(candidates) == 1:
        confidence = candidates[0].confidence
        explanation = candidates[0].reason
    else:
        confidence = "Ambiguous"
        explanation = "Plusieurs formats correspondent à cette structure. Une valeur seule ne suffit pas à les départager."
    return Analysis(raw, candidates, confidence, explanation)

def identify_hash(value: str) -> list[str]:
    return [c.name for c in analyze_hash(value).candidates]
