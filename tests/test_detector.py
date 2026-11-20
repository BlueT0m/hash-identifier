
import pytest

from src.hash_identifier.detector import identify_hash, analyze_hash


@pytest.mark.parametrize(
    "value, expected",
    [
        ("5d41402abc4b2a76b9719d911017c592", ["MD5", "NTLM"]),
        ("a" * 40, ["SHA-1"]),
        ("a" * 56, ["SHA-224", "SHA3-224"]),
        ("a" * 64, ["SHA-256", "SHA3-256"]),
        ("a" * 96, ["SHA-384", "SHA3-384"]),
        ("a" * 128, ["SHA-512", "SHA3-512"]),
    ],
)
def test_identify_hash(value, expected):
    assert identify_hash(value) == expected


def test_empty_hash():
    assert identify_hash("") == []


def test_analyze_hash():
    result = analyze_hash("5d41402abc4b2a76b9719d911017c592")

    assert result["length"] == 32
    assert result["possible_algorithms"] == ["MD5", "NTLM"]
    assert result["confidence"] == "Ambiguous"


def test_bcrypt_detection():
    value = "$2b$12$" + "a" * 53
    assert identify_hash(value) == ["bcrypt"]


def test_argon2_detection():
    value = "$argon2id$v=19$m=65536,t=3,p=4$abc$def"
    assert identify_hash(value) == ["Argon2"]


def test_pbkdf2_detection():
    value = "$pbkdf2-sha256$29000$salt$hash"
    assert identify_hash(value) == ["PBKDF2"]


def test_unknown_hash():
    assert identify_hash("hello123") == []


def test_sha3_256_length():
    result = analyze_hash("a" * 64)
    assert "SHA3-256" in result["possible_algorithms"]


def test_md5_crypt():
    value = "$1$salt$" + "a" * 22
    assert identify_hash(value) == ["MD5-crypt"]


def test_sha256_crypt():
    value = "$5$salt$" + "a" * 43
    assert identify_hash(value) == ["SHA-256-crypt"]


def test_sha512_crypt():
    value = "$6$salt$" + "a" * 86
    assert identify_hash(value) == ["SHA-512-crypt"]


# ADVANCED TESTS


def test_bcrypt_invalid_cost():
    assert identify_hash("$2b$03$" + "a" * 53) == []
    assert identify_hash("$2b$32$" + "a" * 53) == []


def test_bcrypt_valid_cost():
    assert identify_hash("$2b$04$" + "a" * 53) == ["bcrypt"]
    assert identify_hash("$2b$31$" + "a" * 53) == ["bcrypt"]


def test_argon2_invalid_prefix():
    value = "$ARGON2id$v=19$m=65536,t=3,p=4$abc$def"
    assert identify_hash(value) == []


def test_argon2_invalid_parameters():
    assert identify_hash(
        "$argon2id$v=19$m=0,t=3,p=4$abc$def"
    ) == []

    assert identify_hash(
        "$argon2id$v=19$m=65536,t=0,p=4$abc$def"
    ) == []


def test_pbkdf2_invalid_iterations():
    assert identify_hash(
        "$pbkdf2-sha256$0$salt$hash"
    ) == []


def test_sha256_crypt_with_rounds():
    value = "$5$rounds=10000$salt$" + "a" * 43
    assert identify_hash(value) == ["SHA-256-crypt"]


def test_sha512_crypt_with_rounds():
    value = "$6$rounds=10000$salt$" + "a" * 86
    assert identify_hash(value) == ["SHA-512-crypt"]


def test_sha_crypt_invalid_rounds():
    value = "$5$rounds=100$salt$" + "a" * 43
    assert identify_hash(value) == []


def test_password_hash_confidence():
    result = analyze_hash("$2b$12$" + "a" * 53)
    assert result["confidence"] == "High"


def test_hash_prefix_case_sensitivity():
    assert identify_hash("$2B$12$" + "a" * 53) == []

    assert identify_hash(
        "$ARGON2id$v=19$m=65536,t=3,p=4$abc$def"
    ) == []

def test_argon2_unsupported_version():
    value = "$argon2id$v=99$m=65536,t=3,p=4$abc$def"
    assert identify_hash(value) == []


def test_argon2_duplicate_parameters():
    value = "$argon2id$v=19$m=65536,m=32768,t=3,p=4$abc$def"
    assert identify_hash(value) == []


def test_argon2_missing_parameter():
    value = "$argon2id$v=19$m=65536,t=3$abc$def"
    assert identify_hash(value) == []


def test_argon2_invalid_base64():
    value = "$argon2id$v=19$m=65536,t=3,p=4$abc!$def"
    assert identify_hash(value) == []


def test_argon2_empty_salt():
    value = "$argon2id$v=19$m=65536,t=3,p=4$$def"
    assert identify_hash(value) == []


def test_argon2_empty_digest():
    value = "$argon2id$v=19$m=65536,t=3,p=4$abc$"
    assert identify_hash(value) == []

def test_argon2_memory_below_minimum():
    value = "$argon2id$v=19$m=16,t=3,p=4$abc$def"
    assert identify_hash(value) == []

def test_argon2_memory_at_minimum():
    value = "$argon2id$v=19$m=32,t=3,p=4$abc$def"
    assert identify_hash(value) == ["Argon2"]

def test_argon2_zero_iterations():
    value = "$argon2id$v=19$m=65536,t=0,p=4$abc$def"
    assert identify_hash(value) == []


def test_argon2_zero_parallelism():
    value = "$argon2id$v=19$m=65536,t=3,p=0$abc$def"
    assert identify_hash(value) == []

def test_argon2_negative_parameter():
    value = "$argon2id$v=19$m=-1,t=3,p=4$abc$def"
    assert identify_hash(value) == []

def test_argon2_without_explicit_version():
    value = "$argon2id$m=65536,t=3,p=4$abc$def"
    assert identify_hash(value) == ["Argon2"]

