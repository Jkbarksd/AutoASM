# AutoASM

AutoASM is a Python script that automates reconnaissance of HackerOne assets. For each target domain it:

- enumerates subdomains
- probes for live hosts
- checks for potential subdomain takeovers
- performs port scanning
- optionally fingerprints technologies using Wappalyzer
- provides an optional AI-powered summary of high-risk assets using NVD CVE data

Results are stored under `output/<domain>/`.

## Dependencies

The script requires Python 3 and the following external tools to be installed and available in your `PATH`:

- `assetfinder`
- `httprobe`
- `subjack`
- `nmap`
- `python-Wappalyzer` (optional, for technology fingerprinting)
- `requests` (for CVE lookups used by the AI summary)

Each tool has its own installation method; consult their respective documentation. For example:

```bash
pip install python-Wappalyzer
```

## Usage

```bash
python optimized_recon.py <target-domain or file>
```

Run `python optimized_recon.py --help` to see all options. The AI summary is enabled by default; disable it with `--no-ai`.

