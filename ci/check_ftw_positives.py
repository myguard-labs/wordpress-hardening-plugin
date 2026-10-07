"""Ensure enabled rule suites retain a live go-ftw positive assertion."""

import argparse
import hashlib
import re
from pathlib import Path

import yaml

# Keys are YAML suite filename stems (for example, 9522410.yaml -> 9522410).
# These suites cannot assert their own logged hit: disabled defaults, silent
# actions, allowed traffic, or a private-address-only harness client.
NO_POSITIVE_RULES = {
    "9522410",  # Counter and gate are silent; 9522412 tests the threshold.
    "9522604",  # loopback source cannot exercise the reputation hit.
    "9522801",  # silent ctl:ruleRemoveById action.
}

# SHA-256 of the sorted, newline-separated Apache ignore IDs in .ftw.yml.
# The YAML is the sole list of IDs and reasons; this approval fingerprint makes
# any added or substituted ignore fail CI until it is explicitly reviewed.
APACHE_IGNORE_IDS_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
ISSUE_REASON = re.compile(r"^R6-[A-Z0-9-]+: \S.{15,}$")


def check_ignores(settings: dict) -> None:
    ignored = (settings.get("testoverride") or {}).get("ignore")
    if not isinstance(ignored, dict):
        raise TypeError("Apache go-ftw ignore must be a mapping")
    if not all(isinstance(title, str) for title in ignored):
        raise TypeError("Apache go-ftw ignore IDs must be strings")
    actual = hashlib.sha256("\n".join(sorted(ignored)).encode()).hexdigest()
    if actual != APACHE_IGNORE_IDS_SHA256:
        raise ValueError("Apache go-ftw ignore IDs changed; review every new ignore")
    for title, reason in ignored.items():
        if not isinstance(reason, str) or not ISSUE_REASON.fullmatch(reason.strip()):
            raise ValueError(f"Apache go-ftw ignore {title}: tracked reason required")


def check_positives(directory: Path, config: Path) -> int:
    settings = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    ignored = (settings.get("testoverride") or {}).get("ignore") or {}
    paths = sorted(directory.glob("*.yaml"))
    if not paths:
        raise ValueError(f"no rule YAML files in {directory}")
    for path in paths:
        suite = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not (suite.get("meta") or {}).get("enabled", True):
            continue
        tests = suite.get("tests") or []
        if path.stem in NO_POSITIVE_RULES:
            continue
        positives = [
            test.get("test_title")
            for test in tests
            if any(
                "log_contains" in (stage.get("output") or {})
                for stage in (test.get("stages") or [])
            )
        ]
        if not any(title not in ignored for title in positives):
            raise ValueError(f"{path}: no non-ignored log_contains positive")
    return len(paths)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        settings = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
        check_ignores(settings)
        count = check_positives(args.directory, args.config)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        parser.exit(1, f"{exc}\n")
    print(f"Checked live positives in {count} rule YAML files")


if __name__ == "__main__":
    main()
