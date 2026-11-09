# Project Cybertron: File Integrity Checker

A beginner-friendly, local cybersecurity project that records SHA-256 hashes of files and reports when files are added, changed, or missing. It uses only the Python standard library.

## Learning goals

- Work with Python's filesystem and command-line APIs.
- Understand cryptographic hashes and why a baseline is needed for integrity monitoring.
- Practice tests, input validation, documentation, and safe defaults.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Quick start

```bash
python3 --version
python3 integrity_checker.py --help

# Create a baseline for a directory you own or are authorized to monitor.
python3 integrity_checker.py init ./sample-data

# Later, compare its current contents with that baseline.
python3 integrity_checker.py check ./sample-data
```

By default, the baseline is saved as `.integrity-baseline.json` inside the scanned directory and is excluded from the scan. You can store it elsewhere with `--baseline`:

```bash
mkdir -p ./baselines
python3 integrity_checker.py init ./sample-data --baseline ./baselines/sample.json
python3 integrity_checker.py check ./sample-data --baseline ./baselines/sample.json
```

Exit codes: `0` means the scan completed and matched (or initialization succeeded), `1` means differences were found, and `2` means an operational or input error prevented a complete check.

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

## Important limitations

- This is a learning project, not an endpoint security product or a forensic tool.
- The baseline is ordinary JSON. An attacker who can change both the files and the baseline can hide changes. For stronger protection, keep a trusted copy of the baseline somewhere the monitored account cannot modify, or sign it with a separately managed key.
- The baseline records the absolute scan directory, so move the directory only when you intend to initialize a new baseline.
- Symbolic links are skipped; this tool does not follow them. It hashes regular files, not permissions, ownership, timestamps, or extended attributes.
- A file can change immediately after a check. Run checks on a schedule appropriate to your use case.
- Use only on files and systems you own or have permission to monitor. Don’t put secrets, private logs, or sensitive sample files in this public repository.

## Project roadmap

1. Add configurable ignore patterns and tests for them.
2. Add JSON and human-readable output options.
3. Add a CI workflow to run tests on each change.
4. Document design decisions and review the limitations before adding features.

## License

MIT. See [LICENSE](LICENSE).
