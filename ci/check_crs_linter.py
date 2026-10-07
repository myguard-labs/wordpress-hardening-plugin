"""Fail on CRS linter findings that apply to plugin rules.

The CRS core version, tag, action order, indentation, TX initialization, and
line-based PL checks do not model this plugin's conventions or CRS setup.
Keep this list explicit so adding a CRS-core check cannot silently block CI.
"""

import subprocess
import sys
import tempfile
from glob import glob
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINTER_TIMEOUT_SECONDS = 300
SUPPORTED = (
    "rule uses TX.N without capture;",
    "ctl:auditLogParts action is deprecated;",
    "Invalid action ",
    "Action case mismatch:",
    "Invalid ctl ",
    "Ctl case mismatch:",
    "Invalid transform:",
    "Transform case mismatch:",
    "Invalid operator:",
    "Operator case mismatch:",
    "Empty operator isn't allowed",
    "rule uses (?i) in combination with t:lowercase:",
    "rule uses 'pass' without 'nolog';",
    "standalone rule uses TX.N as target;",
)


def check(rule_files, executable="crs-linter", timeout=LINTER_TIMEOUT_SECONDS):
    matched_files = []
    unmatched = []
    non_files = []
    for pattern in rule_files:
        candidate = Path(pattern)
        search_pattern = str(candidate if candidate.is_absolute() else ROOT / candidate)
        matches = sorted(glob(search_pattern))
        if matches:
            for match in matches:
                if Path(match).is_file():
                    matched_files.append(match)
                else:
                    non_files.append(match)
        else:
            unmatched.append(pattern)
    if unmatched:
        for pattern in unmatched:
            print(f"crs-linter subset: no rule files matched: {pattern}", file=sys.stderr)
        return 1
    if non_files:
        for path in non_files:
            print(f"crs-linter subset: matched path is not a rule file: {path}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as directory:
        tags = Path(directory) / "tags"
        tags.write_text("")
        command = [executable, "-d", str(ROOT), "-t", str(tags)]
        for path in matched_files:
            command.extend(("-r", str(path)))
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(
                f"crs-linter subset: linter timed out after {timeout} seconds",
                file=sys.stderr,
            )
            return 1

    output = result.stdout + result.stderr
    findings = [
        line for line in output.splitlines()
        if any(marker in line for marker in SUPPORTED)
    ]
    parse_errors = [
        line for line in output.splitlines()
        if "Can't parse config file:" in line or "Error running rule " in line
    ]
    if (not output or result.returncode not in (0, 1)
            or "Traceback (most recent call last):" in output):
        print(f"crs-linter subset: linter failed (exit {result.returncode})", file=sys.stderr)
        return 1
    for line in findings + parse_errors:
        print(line, file=sys.stderr)
    if findings or parse_errors:
        print("crs-linter subset: FAILED", file=sys.stderr)
        return 1
    print("crs-linter subset: passed")
    return 0


if __name__ == "__main__":
    plugin_files = sys.argv[1:] or [str(path) for path in sorted((ROOT / "plugins").glob("*.conf"))]
    if not plugin_files:
        print("crs-linter subset: no plugin rules found", file=sys.stderr)
        raise SystemExit(1)
    try:
        raise SystemExit(check(plugin_files))
    except OSError as exc:
        print(f"crs-linter subset: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
