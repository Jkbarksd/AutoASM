import csv
import json
import os
import re
from pathlib import Path
from typing import Dict, List

try:
    from Wappalyzer import Wappalyzer, WebPage  # type: ignore
    HAS_WAPPALYZER = True
except Exception:  # pragma: no cover - optional dependency
    HAS_WAPPALYZER = False

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


def wappalyze_host(hostname: str, timeout: int = 20) -> Dict:
    results: Dict = {"host": hostname, "url": None, "title": "", "technologies": [], "score": 0}
    if not HAS_WAPPALYZER:
        return results
    wapp = Wappalyzer.latest()
    tried: List[str] = []
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
            results.update({"url": url, "title": title, "technologies": sorted(techs, key=str.lower)})
            results["score"] = _score_row(url, title, len(results["technologies"]))
            return results
        except Exception:
            continue
    results["url"] = tried[-1] if tried else None
    return results


def wappalyze_alive_list(alive_file: str, out_csv: str, out_json: str | None = None) -> None:
    if not os.path.exists(alive_file):
        print(f"[!] Alive file not found: {alive_file}")
        return

    with open(alive_file) as f:
        hosts = [h.strip() for h in f if h.strip()]

    print(f"[+] Wappalyzing {len(hosts)} hosts...")
    rows = [wappalyze_host(h) for h in hosts]
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
                r.get("score", 0),
            ])
    print(f"[+] Wappalyzer CSV saved: {out_csv}")

    if out_json:
        with open(out_json, "w") as jf:
            json.dump(rows, jf, indent=2)
        print(f"[+] Wappalyzer JSON saved: {out_json}")
