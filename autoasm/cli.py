import argparse
from typing import List

from . import utils
from .recon import REQUIRED_CMDS, recon_domain


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recon automation script for HackerOne assets")
    parser.add_argument("input", help="Target domain, CSV, or path to .txt file")
    parser.add_argument("--exclude", help="Path to out-of-scope domains .txt file", default=None)
    parser.add_argument("--mappedports", help="Display mapped ports excluding specific ports", action="store_true")
    parser.add_argument("--omit", help="Ports to omit, e.g. --omit 80,443", default="80,443")
    parser.add_argument("--no-wappalyzer", help="Skip Wappalyzer fingerprinting", action="store_true")
    return parser.parse_args()


def determine_targets(user_input: str) -> List[str]:
    if user_input.endswith(".csv"):
        return utils.load_eligible_assets_from_csv(user_input)
    return utils.load_domains(user_input)


def main() -> None:
    args = parse_args()
    args.omit_ports = args.omit.split(",") if args.omit else ["80", "443"]

    try:
        utils.check_dependencies(REQUIRED_CMDS)
    except RuntimeError as e:
        print(e)
        return

    targets = determine_targets(args.input)
    targets = utils.filter_out_of_scope(targets, args.exclude)

    for domain in targets:
        recon_domain(domain, args)
