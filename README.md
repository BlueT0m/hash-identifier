# Hash Identifier v1.0.0

**An offline command-line tool for structural hash identification.**

Hash Identifier analyzes hash strings and identifies possible hash formats based on their structure, length, character set, and format-specific patterns.

It is designed for cybersecurity learning, technical analysis, and authorized security workflows.

**Important:** Hash Identifier identifies possible formats. It does not crack passwords, recover plaintext, or verify password hashes.

## Features

- **Hash detection:** MD5, NTLM, SHA-1, SHA-2, SHA-3 and other supported formats.
- **Password hash formats:** bcrypt, Argon2, PBKDF2, scrypt and common Unix `crypt` formats.
- **Additional formats:** MySQL 3.23, MySQL 4.1+, LM and NetNTLMv1/v2.
- **Confidence levels:** Results include confidence information and explanations.
- **Batch analysis:** Analyze multiple hashes from a text file.
- **Multiple export formats:** JSON, CSV and TXT.
- **Local history:** Save and review previous analyses.
- **History search:** Search previous results.
- **Statistics:** Display analysis statistics.
- **Offline operation:** No external API or internet connection required for detection.
- **Lightweight:** Python 3.10+ with no runtime dependencies.

## Supported platforms

- Kali Linux
- Debian
- Ubuntu
- Windows
- Other Python-compatible platforms

## Installation

### Kali Linux / Debian / Ubuntu

Install Python and the virtual environment package:

```bash
sudo apt update
sudo apt install -y python3 python3-venv git
```

Clone the repository:

```bash
git clone https://github.com/BlueT0m/hash-identifier.git
cd hash-identifier
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Hash Identifier:

```bash
python -m pip install --upgrade pip
python -m pip install .
```

Verify the installation:

```bash
hash-identifier --version
hash-identifier --help
```

## Usage

### Identify a hash

```bash
hash-identifier identify 5d41402abc4b2a76b9719d911017c592
```

### JSON output

```bash
hash-identifier identify --json 5d41402abc4b2a76b9719d911017c592
```

### Batch analysis

Create a file named `hashes.txt` containing one hash per line.

```bash
hash-identifier batch hashes.txt
```

Export batch results:

```bash
hash-identifier batch hashes.txt --output results.csv --format csv
```

### View history

```bash
hash-identifier history
```

### Search history

```bash
hash-identifier search sha256
```

### View statistics

```bash
hash-identifier stats
```

### Export history

```bash
hash-identifier export results.csv
```

### Delete a history entry

```bash
hash-identifier delete ID
```

### Clear history

```bash
hash-identifier clear
```

Use `--yes` to confirm without an interactive prompt.

## Available commands

| Command | Description |
|---|---|
| `identify` | Analyze a single hash |
| `batch` | Analyze hashes from a file |
| `history` | Display analysis history |
| `search` | Search saved analyses |
| `stats` | Display history statistics |
| `export` | Export saved history |
| `delete` | Delete a history entry |
| `clear` | Clear saved history |

### Additional options

The CLI provides:

- `--version` to display the installed version.
- `--json` for JSON output.
- `--verbose` for additional information.
- `--quiet` for reduced output.
- `--no-history` to prevent saving an analysis.
- `--output` and `--format` for batch exports.

Use `hash-identifier COMMAND --help` to inspect the options for a specific command.

## Detection methodology

Hash Identifier uses structural analysis to identify possible hash formats.

It evaluates characteristics such as:

- String length.
- Character set.
- Prefix and separators.
- Encoded parameters.
- Format-specific structure.

Some formats share identical characteristics.

For example, a 32-character hexadecimal string can correspond to MD5 or NTLM.

In such cases, Hash Identifier reports multiple candidates instead of claiming an unsupported identification.

**Detection is not password cracking.** The tool does not attempt to recover passwords or execute password verification.

## Privacy and security

Hash Identifier works locally.

- No external API is required.
- No hash is sent to a remote server by the detection engine.
- Analysis history is stored locally in `history.json`.
- Use `--no-history` to disable history storage for an analysis.

Only analyze hashes and files you are authorized to handle.

## Development

Clone the repository and activate your virtual environment.

Install development dependencies:

```bash
python -m pip install -e ".[test]"
```

Run the test suite:

```bash
python -m pytest -v
```

Run tests with coverage:

```bash
python -m pytest --cov=hash_identifier --cov-report=term-missing
```

## Project structure

```text
hash-identifier/
├── .github/
│   └── workflows/
├── src/
│   └── hash_identifier/
│       ├── __init__.py
│       ├── __main__.py
│       ├── batch.py
│       ├── detector.py
│       ├── export.py
│       ├── history.py
│       └── main.py
├── tests/
├── LICENSE
├── README.md
├── pyproject.toml
└── run_hash_identifier.py
```

## Roadmap

Planned improvements for future releases:

- Expanded hash signature database.
- Improved detection accuracy.
- More comprehensive automated tests.
- Advanced batch analysis.
- Interactive terminal interface.
- Extensible detection architecture.

These improvements are planned and are not part of v1.0.0.

## Contributing

Contributions, bug reports, and suggestions are welcome.

Before submitting changes:

1. Test your modifications.
2. Add tests for new functionality.
3. Keep the code readable.
4. Document changes when necessary.

## License

Hash Identifier is distributed under the MIT License.

See [LICENSE](LICENSE) for details.

## Repository

GitHub: https://github.com/BlueT0m/hash-identifier

**Current release:** v1.0.0
