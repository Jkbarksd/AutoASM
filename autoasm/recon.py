import os
from typing import Iterable

from . import utils
from .wappalyzer_utils import HAS_WAPPALYZER, wappalyze_alive_list

from .ai_summary import summarize_domain



REQUIRED_CMDS = ["assetfinder", "httprobe", "subjack", "nmap"]


def run_assetfinder(domain: str, output: str) -> None:
    print("[+] Harvesting subdomains...")
    utils.run_command(f"assetfinder --subs-only {domain} | grep '{domain}' | sort -u", output)


def probe_alive(final_txt: str, alive_txt: str) -> None:
    print("[+] Probing for alive hosts...")
    utils.run_command(
        f"cat {final_txt} | httprobe -s -p https:443 | sed 's|https\\?://||; s|:443||; s|:80||; s|/.*||' | sort -u",
        alive_txt,
    )


def check_takeover(final_txt: str, out_file: str) -> None:
    print("[+] Checking for possible subdomain takeover...")
    utils.run_command(
        f"subjack -w {final_txt} -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o {out_file}"
    )


def scan_ports(alive_txt: str, scan_file: str) -> None:
    print("[+] Scanning for open ports...")
    utils.run_command(f"nmap -iL {alive_txt} -T4 -oN {scan_file}")


def map_open_ports(scan_file: str, omit_ports: Iterable[str], output_file: str) -> None:
    print("[+] Mapping open ports excluding: " + ", ".join(omit_ports))
    filtered_ports = utils.parse_nmap_output(scan_file, omit_ports)
    if filtered_ports:
        for entry in filtered_ports:
            print(entry)
        with open(output_file, "w") as f:
            f.write("\n".join(filtered_ports))
        print(f"[+] Filtered ports saved to: {output_file}")
    else:
        print("[!] No open ports found outside of omitted ones.")


def run_wappalyzer(alive_txt: str, base_dir: str) -> None:
    if not HAS_WAPPALYZER:
        print("[!] python-Wappalyzer not installed. Install with: pip install python-Wappalyzer requests-html")
        return
    wap_csv = os.path.join(base_dir, "recon", "httprobe", "wappalyzer.csv")
    wap_json = os.path.join(base_dir, "recon", "httprobe", "wappalyzer.json")
    wappalyze_alive_list(alive_txt, wap_csv, wap_json)


def recon_domain(domain: str, args) -> None:
    base_dir = f"./output/{domain}"
    utils.prepare_dirs(base_dir)

    print(f"[+] Running recon for: {domain}")

    final_txt = os.path.join(base_dir, "recon", "final.txt")
    alive_txt = os.path.join(base_dir, "recon", "httprobe", "alive.txt")

    run_assetfinder(domain, final_txt)
    probe_alive(final_txt, alive_txt)
    check_takeover(final_txt, os.path.join(base_dir, "recon", "potential_takeovers", "potential_takeovers.txt"))
    scan_ports(alive_txt, os.path.join(base_dir, "recon", "scans", "scanned.txt.nmap"))

    if args.mappedports:
        map_open_ports(
            os.path.join(base_dir, "recon", "scans", "scanned.txt.nmap"),
            args.omit_ports,
            os.path.join(base_dir, "recon", "scans", "filtered_ports.txt"),
        )

    if not args.no_wappalyzer:
        run_wappalyzer(alive_txt, base_dir)

    if not args.no_ai:
        summarize_domain(base_dir)


    print(f"[+] Recon for {domain} complete. Output in {base_dir}")
