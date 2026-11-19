
# Hash Identifier

A Python cybersecurity tool designed to identify possible hash algorithms based on their structure, length and character patterns.

## Features

- Identify common hashing algorithms.
- Detect password hash formats.
- Analyze hash structure.
- Estimate detection confidence.
- Store analysis history in JSON.
- Delete individual history entries.
- Clear analysis history.
- Export analysis results to CSV.
- Validate hash formats using regular expressions.

## Supported Algorithms

### General Hashes

- MD5
- NTLM
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512

### Password Hashes

- bcrypt
- Argon2
- PBKDF2
- MD5-crypt
- SHA-256-crypt
- SHA-512-crypt

## Project Structure

```text
hash-identifier/
├── src/
│   └── hash_identifier/
│       ├── detector.py
│       ├── export.py
│       ├── history.py
│       └── main.py
├── tests/
│   ├── test_detector.py
│   ├── test_export.py
│   └── test_history.py
├── hash_export.csv
├── hash_history.json
├── README.md
└── .gitignore
```

## Requirements

- Python 3.10 or newer
- pytest for testing

## Installation

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
cd hash-identifier
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

Linux / Kali Linux:

```bash
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

Install pytest:

```bash
pip install pytest
```

## Usage

Launch the application:

```bash
python -m src.hash_identifier.main
```

## Main Menu

1. Identify hash
2. View history
3. Delete history entry
4. Export CSV
5. Clear history
6. Exit

## Run Tests

Execute the test suite:

```bash
python -m pytest -v
```

## Detection Confidence

- High: Recognized password-hash structure.
- Low: Length and character pattern match.
- Ambiguous: Multiple algorithms share the same format.
- None: Unknown or empty input.

## Limitations

Hash identification is based on structural patterns.

It does not crack hashes or verify the original algorithm.

Different algorithms can share the same format and length.

## Author

Cybersecurity learning project.
