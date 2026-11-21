from hash_identifier.detector import analyze_hash, identify_hash

def names(value):
    return identify_hash(value)

def test_md5_ntlm_ambiguous():
    result = analyze_hash("5d41402abc4b2a76b9719d911017c592")
    assert {"MD5", "NTLM"} <= set(names(result.input))
    assert result.confidence == "Ambiguous"

def test_sha_families():
    assert "SHA-1" in names("a" * 40)
    assert "SHA-256" in names("a" * 64)
    assert "SHA-512" in names("a" * 128)

def test_mysql():
    assert "MySQL 4.1+" in names("*" + "a" * 40)

def test_bcrypt():
    assert "bcrypt" in names("$2b$12$" + "." * 53)

def test_argon2_valid():
    value = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$ZGlnZXN0"
    assert "ARGON2ID" in names(value)

def test_argon2_rejects_duplicate_params():
    value = "$argon2id$v=19$m=65536,m=65536,t=3,p=4$c2FsdHNhbHQ$ZGlnZXN0"
    assert names(value) == []

def test_pbkdf2():
    assert "PBKDF2-SHA256" in names("$pbkdf2-sha256$29000$c2FsdA$YWJjZGVm")
    assert "PBKDF2-SHA256" in names("pbkdf2:sha256:260000$salt$" + "a" * 64)

def test_scrypt():
    assert "scrypt" in names("$scrypt$ln=16,r=8,p=1$c2FsdA$ZGlnZXN0")

def test_mysql_old():
    assert "MySQL 3.23" in names("0123456789abcdef")

def test_empty_unknown():
    assert analyze_hash("").confidence == "None"
    assert analyze_hash("not-a-hash").candidates == []

def test_netntlmv2():
    sample = "User::Domain:0123456789abcdef:" + "a"*32 + ":" + "b"*20
    assert "NetNTLMv2" in names(sample)
