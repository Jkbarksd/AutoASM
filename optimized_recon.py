

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



if __name__ == "__main__":
    main()
