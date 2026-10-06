"""Run go-ftw with fresh public client identities for persistent IP tests."""

import argparse
import re
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = ROOT / "tests/regression"
CONFIG = ROOT / "tests/integration/.ftw.yml"
# The resolver uses XFF as client_ip and the limiter persists by that key.
# Preserve each fixture's shared identity across its stages while rotating it
# between full-suite invocations. Private-address exemption fixtures stay fixed.
RATE_LIMIT_IDENTITIES = {
    "9522410.yaml": ("8.8.8.8", "203.0.113.50"),
    "9522412.yaml": ("203.0.113.77", "198.51.100.23"),
    "9522510.yaml": ("203.0.113.7",),
}


def fresh_addresses(count: int) -> list[str]:
    """Allocate distinct IPv4 addresses in the non-private benchmark range."""
    addresses: set[str] = set()
    while len(addresses) < count:
        number = secrets.randbelow(1 << 17)
        addresses.add(f"198.{18 + (number >> 16)}.{(number >> 8) & 255}.{number & 255}")
    return sorted(addresses)


def prepare_suites(source: Path, target: Path, addresses: list[str]) -> None:
    if len(addresses) != sum(map(len, RATE_LIMIT_IDENTITIES.values())):
        raise ValueError("one fresh address is required per rate-limit identity")
    mapping = iter(addresses)
    for original in sorted(source.rglob("*.yaml")):
        relative = original.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        body = original.read_text(encoding="utf-8")
        if original.name in RATE_LIMIT_IDENTITIES:
            for old in RATE_LIMIT_IDENTITIES[original.name]:
                pattern = re.compile(rf"(?m)^(\s*X-Forwarded-For: ['\"]?){re.escape(old)}(['\"]?)$")
                # Keep all occurrences of an identity equal, including the
                # threshold fixture's five POST stages.
                next_address = next(mapping)
                body, hits = pattern.subn(rf"\g<1>{next_address}\g<2>", body)
                if not hits:
                    raise ValueError(f"missing X-Forwarded-For {old} in {original}")
        destination.write_text(body, encoding="utf-8")


def run_ftw(ftw: Path, config: Path, suites: Path) -> None:
    for action in ("check", "run"):
        command = [str(ftw.resolve()), action, "-d", str(suites),
                   "--config", str(config.resolve())]
        if action == "run":
            command.append("--show-failures-only")
        try:
            result = subprocess.run(command, check=True, cwd=ROOT, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            sys.stdout.write(exc.stdout or "")
            sys.stdout.flush()
            raise
        sys.stdout.write(result.stdout)
        # go-ftw 2.1.0 can print failed stages, then exit zero and report the
        # multi-stage test successful because its final stage passed.
        if action == "run" and re.search(r"(?m)^💥 .+ failed in ", result.stdout):
            raise RuntimeError("go-ftw reported failed stages")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ftw", type=Path, default=ROOT / "ftw")
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()
    addresses = fresh_addresses(sum(map(len, RATE_LIMIT_IDENTITIES.values())))
    print(f"rate-limit fixture identities: {', '.join(addresses)}", flush=True)
    with tempfile.TemporaryDirectory(prefix="wphard-ftw-") as directory:
        suites = Path(directory)
        prepare_suites(SUITES, suites, addresses)
        run_ftw(args.ftw, args.config, suites)


if __name__ == "__main__":
    main()
