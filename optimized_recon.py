import argparse
import os
import subprocess
from pathlib import Path
import csv
import re
import json
from urllib.parse import urlparse

# --- Wappalyzer (optional import with friendly error) --------------------
try:
    from Wappalyzer import Wappalyzer, WebPage
    HAS_WAPPALYZER = True
except Exception:
    HAS_WAPPALYZER = False

def run_command(command, output_file=None):
    """Run shell command and optionally save output to a file."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if output_file:
            with open(output_file, "w") as f:
                f.write(result.stdout)
        return result.stdout.strip()
    except Exception as e:
        print(f"[ERROR] Failed to run command: {command}\n{e}")
        return ""

def load_domains(input_path):
    """Load domains from a file or single domain input."""
    if input_path.endswith(".txt"):
        with open(input_path, "r") as f:
            return sorted(set(line.strip() for line in f if line.strip()))
    else:
        return [input_path.strip()]

def load_eligible_assets_from_csv(csv_path):
    """Load domains from CSV where eligible_for_submission is TRUE."""
    domains = []
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row.get("eligible_for_submission", "").strip().lower() == "true":
                domains.append(row.get("asset", "").strip())
    return sorted(set(d for d in domains if d))

def filter_out_of_scope(domains, exclude_path):
    if not exclude_path:
        return domains
    with open(exclude_path, "r") as f:
        excluded = set(line.strip() for line in f if line.strip())
    return [d for d in domains if d not in excluded]

def prepare_dirs(base_dir):
    Path(base_dir).mkdir(parents=True, exist_ok=True)
    (Path(base_dir) / "recon" / "scans").mkdir(parents=True, exist_ok=True)
    (Path(base_dir) / "recon" / "httprobe").mkdir(parents=True, exist_ok=True)
    (Path(base_dir) / "recon" / "potential_takeovers").mkdir(parents=True, exist_ok=True)

def parse_nmap_output(nmap_file, omit_ports):
    """Parse nmap output to show open ports excluding specified ones."""
    results = []
    current_ip = None
    omit_ports = set(omit_ports)
    with open(nmap_file, 'r') as f:
        for line in f:
            if line.startswith("Nmap scan report for"):
                current_ip = line.split()[-1]
            elif "/tcp" in line and "open" in line:
                port = line.split("/")[0]
                if port not in omit_ports:
                    results.append(f"{current_ip}: {port} open")
    return results

# ---------------- Wappalyzer helpers ----------------

CRIT_WORDS = re.compile(r"(login|signin|oauth|sso|account|admin|dashboard|payment|billing|auth)", re.I)

def _extract_title(html_text: str) -> str:
    if not html_text:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]

def _score_row(url_used: str, title: str, techs_count: int) -> int:
    score = 0
    hay = f"{url_used} {title}"
    if CRIT_WORDS.search(hay):
        score += 30
    if "/api" in url_used.lower():
        score += 10
    score += min(techs_count, 20)
    return score

def wappalyze_host(hostname: str, timeout=20):
    results = {
        "host": hostname,
        "url": None,
        "title": "",
        "technologies": [],
        "score": 0
    }
    if not HAS_WAPPALYZER:
        return results

    wapp = Wappalyzer.latest()
    tried = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        tried.append(url)
        try:
            page = WebPage.new_from_url(url, timeout=timeout)
            tech_map = {}
            try:
                tech_map = wapp.analyze_with_versions(page) or {}
                techs = [f"{k} {v}" if v else k for k, v in tech_map.items()]
            except Exception:
                techs = sorted(list(wapp.analyze(page) or []))
            title = _extract_title(getattr(page, "html", "") or "")
            results.update({
                "url": url,
                "title": title,
                "technologies": sorted(techs, key=str.lower),
            })
            results["score"] = _score_row(url, title, len(results["technologies"]))
            return results
        except Exception:
            continue
    results["url"] = tried[-1]
    return results

def wappalyze_alive_list(alive_file: str, out_csv: str, out_json: str = None):
    if not os.path.exists(alive_file):
        print(f"[!] Alive file not found: {alive_file}")
        return

    with open(alive_file) as f:
        hosts = [h.strip() for h in f if h.strip()]

    print(f"[+] Wappalyzing {len(hosts)} hosts...")
    rows = []
    for h in hosts:
        row = wappalyze_host(h)
        rows.append(row)

    rows.sort(key=lambda r: (-r.get("score", 0), r.get("host", "")))

    Path(os.path.dirname(out_csv)).mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "url", "title", "technologies", "score"])
        for r in rows:
            writer.writerow([
                r.get("host", ""),
                r.get("url", ""),
                r.get("title", ""),
                "|".join(r.get("technologies", [])),
                r.get("score", 0)
            ])
    print(f"[+] Wappalyzer CSV saved: {out_csv}")

    if out_json:
        with open(out_json, "w") as jf:
            json.dump(rows, jf, indent=2)
        print(f"[+] Wappalyzer JSON saved: {out_json}")

# ---------------- main pipeline --------------------

def main():
    parser = argparse.ArgumentParser(description="Recon automation script for HackerOne assets")
    parser.add_argument("input", help="Target domain, CSV, or path to .txt file")
    parser.add_argument("--exclude", help="Path to out-of-scope domains .txt file", default=None)
    parser.add_argument("--mappedports", help="Display mapped ports excluding specific ports", action="store_true")
    parser.add_argument("--omit", help="Ports to omit, e.g. --omit 80,443", default="80,443")
    parser.add_argument("--no-wappalyzer", help="Skip Wappalyzer fingerprinting", action="store_true")

    args = parser.parse_args()
    omit_ports = args.omit.split(",") if args.omit else ["80", "443"]

    # Determine input type
    if args.input.endswith(".csv"):
        targets = load_eligible_assets_from_csv(args.input)
    else:
        targets = load_domains(args.input)

    targets = filter_out_of_scope(targets, args.exclude)

    for domain in targets:
        base_dir = f"./output/{domain}"
        prepare_dirs(base_dir)

        print(f"[+] Running recon for: {domain}")

        final_txt = os.path.join(base_dir, "recon", "final.txt")
        alive_txt = os.path.join(base_dir, "recon", "httprobe", "alive.txt")

        print("[+] Harvesting subdomains...")
        run_command(f"assetfinder --subs-only {domain} | grep '{domain}' | sort -u", final_txt)

        print("[+] Probing for alive hosts...")
        run_command(f"cat {final_txt} | httprobe -s -p https:443 | sed 's|https\\?://||; s|:443||; s|:80||; s|/.*||' | sort -u", alive_txt)

        print("[+] Checking for possible subdomain takeover...")
        subjack_out = os.path.join(base_dir, "recon", "potential_takeovers", "potential_takeovers.txt")
        run_command(f"subjack -w {final_txt} -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o {subjack_out}")

        print("[+] Scanning for open ports...")
        scan_file = os.path.join(base_dir, "recon", "scans", "scanned.txt.nmap")
        run_command(f"nmap -iL {alive_txt} -T4 -oN {scan_file}")

        if args.mappedports:
            print("[+] Mapping open ports excluding: " + ", ".join(omit_ports))
            filtered_ports = parse_nmap_output(scan_file, omit_ports)
            mapped_output_file = os.path.join(base_dir, "recon", "scans", "filtered_ports.txt")

            if filtered_ports:
                for entry in filtered_ports:
                    print(entry)

                with open(mapped_output_file, "w") as f:
                    f.write("\n".join(filtered_ports))
                print(f"[+] Filtered ports saved to: {mapped_output_file}")
            else:
                print("[!] No open ports found outside of omitted ones.")

        if not args.no_wappalyzer:
            if not HAS_WAPPALYZER:
                print("[!] python-Wappalyzer not installed. Install with: pip install python-Wappalyzer requests-html")
            else:
                wap_csv = os.path.join(base_dir, "recon", "httprobe", "wappalyzer.csv")
                wap_json = os.path.join(base_dir, "recon", "httprobe", "wappalyzer.json")
                wappalyze_alive_list(alive_txt, wap_csv, wap_json)

        print(f"[+] Recon for {domain} complete. Output in {base_dir}")

if __name__ == "__main__":
    main()
