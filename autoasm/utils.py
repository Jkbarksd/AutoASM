import csv
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List


def run_command(command: str, output_file: str | None = None) -> str:
    """Run shell command and optionally save output to a file."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
        )
        if output_file:
            with open(output_file, "w") as f:
                f.write(result.stdout)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] command failed: {command}\n{e.stderr}")
    except Exception as e:  # pragma: no cover - defensive
        print(f"[ERROR] failed to run command: {command}\n{e}")
    return ""


def load_domains(input_path: str) -> List[str]:
    """Load domains from a file or treat argument as a single domain."""
    if os.path.isfile(input_path):
        with open(input_path, "r") as f:
            return sorted({line.strip() for line in f if line.strip()})
    return [input_path.strip()]


def load_eligible_assets_from_csv(csv_path: str) -> List[str]:
    """Load domains from CSV where eligible_for_submission is TRUE."""
    domains: List[str] = []
    try:
        with open(csv_path, newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row.get("eligible_for_submission", "").strip().lower() == "true":
                    domains.append(row.get("asset", "").strip())
    except FileNotFoundError:
        print(f"[ERROR] CSV not found: {csv_path}")
    return sorted({d for d in domains if d})


def filter_out_of_scope(domains: Iterable[str], exclude_path: str | None) -> List[str]:
    if not exclude_path:
        return list(domains)
    try:
        with open(exclude_path, "r") as f:
            excluded = {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        print(f"[ERROR] Exclusion file not found: {exclude_path}")
        return list(domains)
    return [d for d in domains if d not in excluded]


def prepare_dirs(base_dir: str) -> None:
    Path(base_dir).mkdir(parents=True, exist_ok=True)
    (Path(base_dir) / "recon" / "scans").mkdir(parents=True, exist_ok=True)
    (Path(base_dir) / "recon" / "httprobe").mkdir(parents=True, exist_ok=True)
    (Path(base_dir) / "recon" / "potential_takeovers").mkdir(parents=True, exist_ok=True)


def parse_nmap_output(nmap_file: str, omit_ports: Iterable[str]) -> List[str]:
    """Parse nmap output to show open ports excluding specified ones."""
    results: List[str] = []
    current_ip = None
    omit_ports = set(omit_ports)
    try:
        with open(nmap_file, "r") as f:
            for line in f:
                if line.startswith("Nmap scan report for"):
                    current_ip = line.split()[-1]
                elif "/tcp" in line and "open" in line:
                    port = line.split("/")[0]
                    if port not in omit_ports:
                        results.append(f"{current_ip}: {port} open")
    except FileNotFoundError:
        print(f"[ERROR] Nmap output not found: {nmap_file}")
    return results


def check_dependencies(cmds: Iterable[str]) -> None:
    missing = [c for c in cmds if shutil.which(c) is None]
    if missing:
        raise RuntimeError("Missing required tools: " + ", ".join(missing))
