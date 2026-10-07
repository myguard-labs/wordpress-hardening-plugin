"""Probe phase-one encoded-path blockers on the shipped nginx/libmodsecurity3."""

import argparse
import json
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ci import check_xff_trust

# Mirrors the single-decode boundaries in the Apache go-ftw fixtures. The
# separate load-budget v3 probe already covers 9522112; 9522120 has its own gate.
# (rule, method, encoded positive, benign encoded, double encoded)
CASES = (
    (9522100, "GET", "/r%65adme.html", "/r%65adme.html-guide", "/r%2565adme.html"),
    (9522113, "GET", "/%2eenv", "/%2eenv-guide", "/%252eenv"),
    (
        9522114,
        "GET",
        "/wp-config.php.s%61ve",
        "/wp-config.php.s%61ve-guide",
        "/wp-config.php.s%2561ve",
    ),
    (
        9522115,
        "GET",
        "/wp-content/plugins/akismet/readm%65.txt",
        "/wp-content/plugins/akismet/readm%65.txt-guide",
        "/wp-content/plugins/akismet/readm%2565.txt",
    ),
    (
        9522117,
        "POST",
        "/wp-json/sure-tr%69ggers/v1/connection/create-wp-connection",
        "/wp-json/sure-tr%69ggers/v2/health",
        "/wp-json/sure-tr%2569ggers/v1/connection/create-wp-connection",
    ),
    (
        9522118,
        "POST",
        "/wp-json/br%69cks/v1/render_element",
        "/wp-json/br%69cks/v2/render_element",
        "/wp-json/br%2569cks/v1/render_element",
    ),
    (9522119, "PUT", "/wp-log%69n.php", "/about%2ehtml", "/wp-log%2569n.php"),
    (9522121, "GET", "/wp-adm%69n/", "/about%2ehtml", "/wp-adm%2569n/"),
)


def stage(plugins, _mode, _peer, disabled_rule=None):
    shutil.copytree(check_xff_trust.ROOT / "plugins", plugins)
    (plugins / "aaa-ci-encoded-config.conf").write_text(
        'SecAction "id:9902115,phase:1,pass,nolog,t:none,'
        'setvar:tx.wphard.block_plugin_readme=1"\n'
    )
    if disabled_rule is not None:
        # Append after the rule definition, exactly as a rule-disabled mutation.
        rules_path = plugins / "wordpress-hardening-after.conf"
        with rules_path.open("a") as rules:
            rules.write(f"\nSecRuleRemoveById {disabled_rule}\n")
        staged = rules_path.stat()
        print(
            f"mutated rules: {rules_path} size={staged.st_size} "
            f"mtime_ns={staged.st_mtime_ns}",
            flush=True,
        )


def assert_result(rule_id, kind, status, record):
    ids = {
        int(message["details"]["ruleId"])
        for message in record["transaction"].get("messages", [])
    }
    matched = rule_id in ids
    if kind == "positive":
        assert matched, f"{kind} {rule_id}: rule did not fire; IDs {sorted(ids)}"
        expected = 200 if rule_id == 9522121 else 403
        assert status == expected, (
            f"{kind} {rule_id}: expected HTTP {expected}, got {status}"
        )
    else:
        assert not matched, (
            f"{kind} {rule_id}: rule fired unexpectedly; IDs {sorted(ids)}"
        )
    return matched


def parse_audit_log(data):
    lines = data.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines.pop()
    return [json.loads(line) for line in lines if line.strip()]


def check(_engine, mode, url, server, _private_peer):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def audit():
        result = subprocess.run(
            ["docker", "exec", server, "cat", "/tmp/encoded-audit.log"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise AssertionError(f"{server}: audit unavailable: {result.stderr}")
        return parse_audit_log(result.stdout)

    def request(method, path):
        req = urllib.request.Request(
            url + path,
            headers={"User-Agent": "Mozilla/5.0 (encoded-path-v3)"},
            method=method,
        )
        try:
            with opener.open(req, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    for _ in range(60):
        try:
            if request("GET", "/") == 200:
                break
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    else:
        raise AssertionError(f"{server}: nginx did not become ready")

    for rule_id, method, positive, benign, double in CASES:
        for kind, path in (
            ("positive", positive),
            ("benign", benign),
            ("double", double),
        ):
            before = len(audit())
            status = request(method, path)
            for _ in range(20):
                matches = [
                    record
                    for record in audit()[before:]
                    if record["transaction"]["request"]["uri"] == path
                ]
                if matches:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError(
                    f"{mode} {method} {path}: no native audit transaction"
                )
            assert len(matches) == 1, (
                f"{mode} {method} {path}: duplicate audit transactions"
            )
            matched = assert_result(rule_id, kind, status, matches[0])
            print(
                f"{mode} {method} {path}: HTTP {status}, rule {rule_id} "
                f"{'present' if matched else 'absent'}",
                flush=True,
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disable-rule", type=int, choices=[case[0] for case in CASES])
    args = parser.parse_args()
    tags = check_xff_trust.workflow_tags()
    with tempfile.TemporaryDirectory(
        prefix="wph-encoded-v3-", dir=check_xff_trust.ROOT
    ) as temporary:
        check_xff_trust.docker(
            Path(temporary),
            "nginx",
            check_xff_trust.selected_image("nginx", tags),
            modes=("base",),
            prepare=lambda plugins, mode, peer: stage(
                plugins, mode, peer, args.disable_rule
            ),
            check=check,
            environment=(
                "MODSEC_RULE_ENGINE=On",
                "ANOMALY_INBOUND=5",
                "PARANOIA=2",
                "MODSEC_AUDIT_ENGINE=On",
                "MODSEC_AUDIT_LOG_TYPE=Serial",
                "MODSEC_AUDIT_LOG=/tmp/encoded-audit.log",
            ),
        )


if __name__ == "__main__":
    main()
