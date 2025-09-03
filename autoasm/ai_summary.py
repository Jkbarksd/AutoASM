import json
import os
from typing import Dict, List

import requests

HIGH_RISK_PORTS = {"21", "22", "23", "445", "3389", "3306", "5900"}


def fetch_cve_info(keyword: str) -> Dict[str, float]:
    """Query NVD for CVE count and highest CVSS score for a keyword."""
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 1},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            count = data.get("totalResults", 0)
            max_score = 0.0
            for item in data.get("vulnerabilities", []):
                metrics = item.get("cve", {}).get("metrics", {})
                for group in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    for m in metrics.get(group, []):
                        score = m.get("cvssData", {}).get("baseScore")
                        if score and score > max_score:
                            max_score = float(score)
            return {"count": count, "max_score": max_score}
    except Exception:
        pass
    return {"count": 0, "max_score": 0.0}


def parse_nmap_ports(nmap_file: str) -> Dict[str, List[str]]:
    ports: Dict[str, List[str]] = {}
    if not os.path.exists(nmap_file):
        return ports
    current_host = None
    with open(nmap_file) as f:
        for line in f:
            if line.startswith("Nmap scan report for"):
                current_host = line.split()[-1]
            elif "/tcp" in line and "open" in line and current_host:
                port = line.split("/")[0]
                ports.setdefault(current_host, []).append(port)
    return ports


def summarize_domain(base_dir: str) -> None:
    """Generate AI-like summary of recon findings using NVD CVE data."""
    wap_json = os.path.join(base_dir, "recon", "httprobe", "wappalyzer.json")
    nmap_file = os.path.join(base_dir, "recon", "scans", "scanned.txt.nmap")

    hosts: List[Dict] = []
    if os.path.exists(wap_json):
        with open(wap_json) as f:
            hosts = json.load(f)

    port_map = parse_nmap_ports(nmap_file)
    summaries: List[Dict] = []

    for host in hosts:
        name = host.get("host", "")
        open_ports = port_map.get(name, [])
        risk = float(host.get("score", 0))
        cve_notes = []
        for tech in host.get("technologies", []):
            info = fetch_cve_info(tech.split()[0])
            if info["count"]:
                risk += info["max_score"]
                cve_notes.append(
                    {
                        "technology": tech,
                        "cve_count": info["count"],
                        "max_score": info["max_score"],
                    }
                )
        for p in open_ports:
            if p in HIGH_RISK_PORTS:
                risk += 5
        summaries.append(
            {
                "host": name,
                "url": host.get("url"),
                "title": host.get("title"),
                "open_ports": open_ports,
                "cves": cve_notes,
                "risk_score": round(risk, 2),
            }
        )

    summaries.sort(key=lambda s: s.get("risk_score", 0), reverse=True)
    out_dir = os.path.join(base_dir, "analysis")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "summary.json")
    with open(out_file, "w") as f:
        json.dump(summaries, f, indent=2)

    if summaries:
        top = summaries[0]
        print(
            f"[+] Highest risk asset: {top['host']} (score {top['risk_score']})"
        )
    print(f"[+] AI summary saved: {out_file}")
