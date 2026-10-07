"""Exercise populated proxy and reputation CIDR files on real WAF engines."""

import argparse
import ipaddress
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ci import check_xff_trust as xff

MODES = ("inside", "outside", "malformed-proxy", "malformed-reputation")
REPUTATION = "198.51.100.64/27"


def stage(directory, mode, peer, mutation=None):
    xff.stage(directory, "trusted", peer)
    network = ipaddress.ip_network(peer + "/28", strict=False)
    proxy = (
        network
        if mode != "outside"
        else ipaddress.ip_network(
            str(network.network_address + 16) + "/28", strict=False
        )
    )
    (directory / "wordpress-hardening-trusted-proxies.data").write_text(
        "bad-cidr/99\n" if mode == "malformed-proxy" else str(proxy) + "\n"
    )
    (directory / "wordpress-hardening-ip-reputation.data").write_text(
        "bad-cidr/99\n" if mode == "malformed-reputation" else REPUTATION + "\n"
    )
    with (directory / "ci-xff-probe-config.conf").open("a") as config:
        config.write(
            '\nSecRule REQUEST_URI "@streq /ip-reputation-probe" '
            '"id:9902091,phase:1,pass,nolog,t:none,'
            'setvar:tx.wphard.ip_reputation_enabled=1"\n'
        )
    if mutation:
        rule = {"remove-proxy": 9522065, "remove-reputation": 9522603}[mutation]
        with (directory / "wordpress-hardening-ip.conf").open("a") as config:
            config.write(f"\nSecRuleRemoveById {rule}\n")


def check(engine, mode, url, server, private_peer):
    del private_peer
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def status(path, header):
        request = urllib.request.Request(
            url + path, headers={"X-Forwarded-For": header}
        )
        try:
            with opener.open(request, timeout=3) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    for _ in range(60):
        if xff.run("docker", "inspect", "-f", "{{.State.Running}}", server) != "true":
            if mode.startswith("malformed-"):
                logs = xff.run("docker", "logs", server, stderr=subprocess.STDOUT)
                filename = (
                    "wordpress-hardening-trusted-proxies.data"
                    if mode == "malformed-proxy"
                    else "wordpress-hardening-ip-reputation.data"
                )
                failure = (
                    "Could not add entry" in logs and filename in logs
                    if engine == "apache"
                    else '"modsecurity_rules_file" directive Rules error' in logs
                    and "wordpress-hardening-ip.conf" in logs
                )
                assert failure, f"{engine}:{mode}: missing CIDR load error: {logs}"
                print(f"{engine}:{mode}: invalid CIDR rejected at startup", flush=True)
                return
            raise AssertionError(
                f"{engine}:{mode}: server stopped: {xff.run('docker', 'logs', server)}"
            )
        try:
            if status("/", "198.51.100.96") == 200:
                break
        except (urllib.error.URLError, TimeoutError):
            # The disposable server may still be opening its listening socket.
            pass
        time.sleep(1)
    else:
        raise AssertionError(f"{engine}:{mode}: server never became ready")
    assert not mode.startswith("malformed-"), f"{engine}:{mode}: invalid CIDR loaded"

    for name, path, header, expected in (
        ("proxy-inside", "/xmlrpc.php", "10.0.0.5", 200 if mode == "inside" else 403),
        (
            "reputation-lower-bound",
            "/ip-reputation-probe",
            "198.51.100.64",
            403 if mode == "inside" else 200,
        ),
        (
            "reputation-inside",
            "/ip-reputation-probe",
            "198.51.100.77",
            403 if mode == "inside" else 200,
        ),
        (
            "reputation-upper-bound",
            "/ip-reputation-probe",
            "198.51.100.95",
            403 if mode == "inside" else 200,
        ),
        ("reputation-outside", "/ip-reputation-probe", "198.51.100.96", 200),
    ):
        actual = status(path, header)
        assert actual == expected, (
            f"{engine}:{mode}:{name}: expected {expected}, got {actual}"
        )
        print(f"{engine}:{mode}:{name}: HTTP {actual}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=xff.TAG_KEYS)
    parser.add_argument("--mutation", choices=("remove-proxy", "remove-reputation"))
    args = parser.parse_args()
    tags = xff.workflow_tags()
    with tempfile.TemporaryDirectory(prefix="wph-cidr-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        lane = directory / "public-peer"
        lane.mkdir()

        def prepare(target, mode, peer):
            stage(target, mode, peer, args.mutation)

        xff.docker(
            lane,
            args.engine,
            xff.selected_image(args.engine, tags),
            modes=MODES,
            prepare=prepare,
            check=check,
        )


if __name__ == "__main__":
    main()
