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

To make the CLI show line-level diffs for changed text files, opt in when creating the baseline:

```bash
python3 integrity_checker.py init ./sample-data --include-text-snapshots
python3 integrity_checker.py check ./sample-data
```

Only valid UTF-8 text files up to 64 KiB each are eligible, and snapshots are capped at 2 MiB total per baseline. Older baselines without snapshots can still detect changes, but cannot show the previous text; recreate the baseline with snapshots enabled to get content diffs.

## Web dashboard

A small browser dashboard is included. It calls the same Python integrity-checking logic as the CLI and scans exactly one directory configured when the server starts; the browser cannot submit a different path.

For a local machine, bind it to loopback and open the displayed local URL:

```bash
python3 web_app.py --directory ~/cybertron-lab --host 127.0.0.1 --port 8000
```

For an isolated development preview that needs to proxy the app, use `--host 0.0.0.0` and the preview URL provided by your environment. The dashboard stores its baseline in `.integrity-baseline.json` inside the configured directory. Creating a baseline replaces the previous baseline and asks for confirmation. The **Save text snapshots for diffs** option is unchecked by default; enable it before creating a baseline to see line-level content changes later.

**Web safety:** this educational dashboard has no user authentication. Only run it in a trusted, private environment; do not expose it to a public network or point it at sensitive directories. The server only accepts same-origin action requests and only scans its startup-configured directory. Use synthetic or non-sensitive files for demos. Text snapshots are stored as plaintext in the JSON baseline (not encrypted); never enable them for secrets or private data. Diffs are shown only for eligible UTF-8 text files, not binaries or oversized files.

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
