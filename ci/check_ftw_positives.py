"""Ensure enabled rule suites retain a live go-ftw positive assertion."""

import argparse
from pathlib import Path

import yaml

# Keys are YAML suite filename stems (for example, 9522410.yaml -> 9522410).
# These suites cannot assert their own logged hit: disabled defaults, silent
# actions, allowed traffic, or a private-address-only harness client.
NO_POSITIVE_RULES = {
    "9522107",  # REST access remains allowed.
    "9522410",  # Counter and gate are silent; 9522412 tests the threshold.
    "9522111",  # wp-cron remains allowed by default.
    "9522115",  # plugin readme blocking is off by default.
    "9522122",  # author archive blocking is off by default.
    "9522604",  # loopback source cannot exercise the reputation hit.
    "9522801",  # silent ctl:ruleRemoveById action.
}


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
        count = check_positives(args.directory, args.config)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.exit(1, f"{exc}\n")
    print(f"Checked live positives in {count} rule YAML files")


if __name__ == "__main__":
    main()
