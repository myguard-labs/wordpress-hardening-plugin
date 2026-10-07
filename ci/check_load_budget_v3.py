"""Check encoded load[] handling on the shipped nginx/libmodsecurity3 engine."""

import json
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ci import check_xff_trust

RULE_ID = 9522112
LONG_PATH = "/wp-admin/load-scripts.php?load%5B%5D=" + "x" * 80
SHORT_PATH = "/wp-admin/load-scripts.php?load%5B%5D=jquery,common"


def stage(plugins, mode, _peer):
    shutil.copytree(check_xff_trust.ROOT / "plugins", plugins)
    if mode == "disabled":
        (plugins / "aaa-ci-load-config.conf").write_text(
            'SecAction "id:9902112,phase:1,pass,nolog,t:none,'
            'setvar:tx.wphard.block_load_scripts_dos=0"\n'
        )


def assert_result(mode, path, status, record):
    ids = {str(message["details"]["ruleId"])
           for message in record["transaction"].get("messages", [])}
    matched = str(RULE_ID) in ids
    if mode == "base" and path == LONG_PATH:
        assert matched, f"{mode} {path}: rule {RULE_ID} did not fire; IDs {sorted(ids)}"
        assert status == 403, f"{mode} {path}: expected HTTP 403, got {status}"
    else:
        assert not matched, f"{mode} {path}: rule {RULE_ID} fired unexpectedly"
        assert status == 200, f"{mode} {path}: expected HTTP 200, got {status}"
    return matched


def check(_engine, mode, url, server, _private_peer):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def audit():
        result = subprocess.run(
            ["docker", "exec", server, "cat", "/tmp/load-audit.log"],
            check=False, capture_output=True, text=True,
        )
        if result.returncode:
            raise AssertionError(f"{server}: audit unavailable: {result.stderr}")
        return [json.loads(line) for line in result.stdout.splitlines() if line]

    def request(path):
        req = urllib.request.Request(
            url + path, headers={"User-Agent": "Mozilla/5.0 (load-budget-v3)"}
        )
        try:
            with opener.open(req, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    for _ in range(60):
        try:
            if request("/") == 200:
                break
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    else:
        raise AssertionError(f"{server}: nginx did not become ready")

    for path in (LONG_PATH, SHORT_PATH):
        before = len(audit())
        status = request(path)
        for _ in range(20):
            records = audit()[before:]
            matches = [record for record in records
                       if record["transaction"]["request"]["uri"] == path]
            if matches:
                break
            time.sleep(0.1)
        else:
            raise AssertionError(f"{mode} {path}: no native audit transaction")
        assert len(matches) == 1, f"{mode} {path}: duplicate audit transactions"
        matched = assert_result(mode, path, status, matches[0])
        print(f"{mode} {path}: HTTP {status}, rule {RULE_ID} "
              f"{'present' if matched else 'absent'}", flush=True)


def main():
    tags = check_xff_trust.workflow_tags()
    with tempfile.TemporaryDirectory(prefix="wph-load-v3-") as temporary:
        check_xff_trust.docker(
            Path(temporary), "nginx", check_xff_trust.selected_image("nginx", tags),
            modes=("base", "disabled"), prepare=stage, check=check,
            environment=("MODSEC_RULE_ENGINE=On", "ANOMALY_INBOUND=5", "PARANOIA=2",
                         "MODSEC_AUDIT_ENGINE=On", "MODSEC_AUDIT_LOG_TYPE=Serial",
                         "MODSEC_AUDIT_LOG=/tmp/load-audit.log"),
        )


if __name__ == "__main__":
    main()
