"""Prove a shipped scoring rule reaches the production inbound block threshold."""

import argparse
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ci import check_xff_trust

RULE_ID = 9522115
ATTACK_PATH = "/wp-content/plugins/example/readme.txt"
THRESHOLD = 5


def stage(plugins, _mode, _peer):
    """Enable only the shipped opt-in readme rule in this isolated lane."""
    shutil.copytree(check_xff_trust.ROOT / "plugins", plugins)
    (plugins / "aaa-ci-block-config.conf").write_text(
        'SecAction "id:9902115,phase:1,pass,nolog,t:none,'
        'setvar:tx.wphard.block_plugin_readme=1"\n'
    )
    (plugins / "zzz-ci-block-after.conf").write_text(
        'SecRule TX:inbound_anomaly_score_pl2 "@ge 5" '
        '"id:9902116,phase:1,pass,log,t:none,msg:\'CI plugin PL2 score marker\'"\n'
    )


def check(_engine, _mode, url, server, _private_peer):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def status(path):
        request = urllib.request.Request(
            url + path, headers={"User-Agent": "Mozilla/5.0 (block-mode-control)"}
        )
        try:
            with opener.open(request, timeout=3) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    for _ in range(60):
        if check_xff_trust.run("docker", "inspect", "-f", "{{.State.Running}}", server) != "true":
            raise AssertionError(check_xff_trust.run("docker", "logs", server))
        try:
            if status("/") == 200:
                break
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    else:
        raise AssertionError(check_xff_trust.run("docker", "logs", server))

    actual = status(ATTACK_PATH)
    logs = subprocess.run(
        ["docker", "logs", server], check=True, capture_output=True, text=True
    ).stderr
    attack_logs = [line for line in logs.splitlines() if f'[uri "{ATTACK_PATH}"]' in line]
    assert any('[id "9522115"]' in line for line in attack_logs), (
        f"plugin rule {RULE_ID} did not match the attack request"
    )
    assert any('[id "9902116"]' in line for line in attack_logs), (
        f"rule {RULE_ID} did not add {THRESHOLD} points to the PL2 inbound score"
    )
    assert any('[id "949110"]' in line for line in attack_logs), (
        "CRS inbound threshold rule 949110 did not fire for the attack request"
    )
    assert actual == 403, (
        f"rule {RULE_ID} score at inbound threshold {THRESHOLD}: "
        f"expected HTTP 403, got {actual}"
    )
    actual = status("/")
    assert actual == 200, f"harmless homepage: expected HTTP 200, got {actual}"
    print(f"rule {RULE_ID} score at inbound threshold {THRESHOLD}: HTTP 403")
    print("harmless homepage: HTTP 200")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule-engine", choices=("On", "DetectionOnly"), default="On")
    args = parser.parse_args()
    tags = check_xff_trust.workflow_tags()
    with tempfile.TemporaryDirectory(prefix="wph-block-mode-") as temporary:
        check_xff_trust.docker(
            Path(temporary),
            "apache",
            check_xff_trust.selected_image("apache", tags),
            modes=("score",),
            prepare=stage,
            check=check,
            environment=(
                f"MODSEC_RULE_ENGINE={args.rule_engine}",
                f"ANOMALY_INBOUND={THRESHOLD}",
                "PARANOIA=2",
            ),
        )


if __name__ == "__main__":
    main()
