"""Prove that IP rules are optional and preserve identity when selected.

Run against disposable Apache/nginx containers or the local Coraza probe.
The base lane leaves the optional file on disk to detect accidental autoloading.
"""

import argparse
import json
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ci import check_xff_trust as xff

MODES = ("base", "unset", "enabled", "disabled")
MOVED_IDS = (
    9522047,
    9522050,
    9522060,
    9522064,
    9522065,
    9522061,
    9522062,
    9522068,
    9522067,
    9522063,
    9522066,
    9522600,
    9522601,
    9522602,
    9522603,
    9522604,
)
STATE = ("client_ip", "xff_trusted", "xff_parsed", "client_is_private")


def stage(directory, mode, peer, mutation=None):
    """Keep production files intact; add only explicit CI includes and probes."""
    shutil.copytree(xff.ROOT / "plugins", directory)
    config = []
    if mode in ("enabled", "disabled"):
        value = 0 if mode == "disabled" else 1
        config.append(
            'SecAction "id:9902070,phase:1,pass,nolog,'
            f'setvar:tx.wordpress-hardening-plugin_enabled={value}"'
        )
    # Turn reputation on only for these requests; other requests check the
    # shipped reputation default. A listed public identity also hits XML-RPC.
    config.append(
        'SecRule REQUEST_URI "@rx ^/(?:ip-reputation-probe|xmlrpc\\.php)$" '
        '"id:9902071,phase:1,pass,nolog,t:none,'
        'setvar:tx.wphard.ip_reputation_enabled=1"'
    )
    (directory / "wordpress-hardening-trusted-proxies.data").write_text(peer + "\n")
    (directory / "wordpress-hardening-ip-reputation.data").write_text("198.51.100.77\n")
    if mode == "ratelimit":
        config.append(
            'SecAction "id:9902072,phase:1,pass,nolog,'
            'setvar:tx.wphard.ratelimit_login_attempts=3"'
        )
        (directory / "zzz-ci-ratelimit-before.conf").write_text(
            "Include /etc/modsecurity.d/owasp-crs/plugins/"
            "wordpress-hardening-ratelimit.conf\n"
        )
    (directory / "zzz-ci-selection-config.conf").write_text("\n".join(config) + "\n")

    # These independent markers observe generated state on both phases. They
    # remain outside the plugin's ID range, so its kill-switch cannot hide them.
    with (directory / "wordpress-hardening-before.conf").open("a") as rules:
        for phase in (1, 2):
            for index, key in enumerate(STATE):
                rules.write(
                    f'\nSecRule REQUEST_URI "@streq /ip-state-probe-{phase}" '
                    f'"id:{9902080 + phase * 10 + index},phase:{phase},'
                    'deny,status:409,log,t:none,chain"\n'
                    f' SecRule &TX:wphard.{key} "@gt 0" "t:none"\n'
                )
        rules.write(
            '\nSecRule REQUEST_URI "@streq /ip-default-probe" '
            '"id:9902073,phase:2,deny,status:409,log,t:none,chain"\n'
            " SecRule &TX:wphard.trusted_proxies_enabled|"
            '&TX:wphard.ip_reputation_enabled "@gt 0" "t:none"\n'
        )
    if mutation == "remove-private":
        with (directory / "wordpress-hardening-ip.conf").open("a") as rules:
            rules.write("\nSecRuleRemoveById 9522063\n")
    elif mutation == "autoload-ip" and mode == "base":
        # Deliberately violate the filename contract; the untouched base lane
        # must reject the resulting generated state and private exemption.
        shutil.copyfile(
            directory / "wordpress-hardening-ip.conf",
            directory / "aaa-ci-accidental-before.conf",
        )


def cases(mode, peer):
    """Expected outcomes are explicit and independent of production rule text."""
    active = mode in ("unset", "enabled")
    disabled = mode == "disabled"
    private_status = 200 if active or disabled else 403
    return [
        ("homepage", "/", None, 200),
        (
            "generated-state-phase1",
            "/ip-state-probe-1",
            "10.0.0.5",
            409 if active else 200,
        ),
        (
            "generated-state-phase2",
            "/ip-state-probe-2",
            "10.0.0.5",
            409 if active else 200,
        ),
        ("feature-defaults", "/ip-default-probe", None, 409 if active else 200),
        ("private-client-exemption", "/xmlrpc.php", "10.0.0.5", private_status),
        (
            "public-client-protection",
            "/xmlrpc.php",
            "198.51.100.78",
            200 if disabled else 403,
        ),
        ("reputation", "/ip-reputation-probe", "198.51.100.77", 403 if active else 200),
        ("reputation-disabled-default", "/", "198.51.100.77", 200),
        (
            "reputation-and-endpoint",
            "/xmlrpc.php",
            "198.51.100.77",
            200 if disabled else 403,
        ),
        (
            "private-peer-no-header",
            "/xmlrpc.php",
            None,
            200 if disabled or (active and peer.startswith("10.")) else 403,
        ),
    ]


def check_http(engine, mode, url, server, private_peer):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def status(path, header=None, data=None):
        headers = {"User-Agent": "Optional IP test", "Accept": "*/*"}
        if header is not None:
            headers["X-Forwarded-For"] = header
        request = urllib.request.Request(url + path, headers=headers, data=data)
        try:
            with opener.open(request, timeout=3) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    for _ in range(60):
        if xff.run("docker", "inspect", "-f", "{{.State.Running}}", server) != "true":
            raise AssertionError(xff.run("docker", "logs", server))
        try:
            if status("/") == 200:
                break
        except (urllib.error.URLError, TimeoutError):
            # The disposable server may not be listening yet; fail after readiness retries.
            pass
        time.sleep(1)
    else:
        raise AssertionError(xff.run("docker", "logs", server))

    if mode == "ratelimit":
        # Same address with different ports shares a collection; another
        # address has a separate counter, and a private client remains exempt.
        for name, header, expected in (
            ("client-a-first", "198.51.100.100:8080", 200),
            ("client-a-second", "198.51.100.100:443", 200),
            ("client-b-first", "198.51.100.101", 200),
            ("client-a-throttled", "198.51.100.100", 429),
            ("client-b-second", "198.51.100.101:80", 200),
            ("private-client-exempt", "10.0.0.5", 200),
        ):
            actual = status("/wp-login.php", header, b"log=reader&pwd=fixture")
            assert actual == expected, (
                f"{engine}:{mode}:{name}: expected {expected}, got {actual}"
            )
            print(f"{engine}:{mode}:{name}: HTTP {actual}", flush=True)
        return
    peer = "10.254.0.1" if private_peer else "198.18.0.1"
    for name, uri, header, expected in cases(mode, peer):
        actual = status(uri, header)
        assert actual == expected, (
            f"{engine}:{mode}:{name}: expected {expected}, got {actual}"
        )
        print(f"{engine}:{mode}:{name}: HTTP {actual}", flush=True)


def transaction(mode, peer, case):
    """Tie each HTTP expectation to the rule IDs observable in Coraza."""
    name, uri, header, expected = case
    forbidden = list(MOVED_IDS) if mode in ("base", "disabled") else []
    if expected == 200:
        forbidden.extend([9522102, 9522603])
    required = []
    if name in ("reputation", "reputation-and-endpoint") and mode in (
        "unset",
        "enabled",
    ):
        required.append(9522603)
    if name == "private-client-exemption" and mode in ("unset", "enabled"):
        required.append(9522063)
    if expected == 403 and mode == "base":
        required.append(9522102)
    return {
        "name": mode + ":" + name,
        "uri": uri,
        "client_ip": peer,
        "headers": {"X-Forwarded-For": header} if header is not None else {},
        "expect_ids": required,
        "no_expect_ids": forbidden,
        "expect_interruption": expected != 200,
    }


def coraza(directory, probe, private_peer=False, mutation=None):
    peer = "10.254.0.1" if private_peer else "198.18.0.1"
    setup = directory / "setup.conf"
    setup.write_text('SecDefaultAction "phase:2,log,deny,status:403"\n')
    for mode in MODES:
        plugins = directory / mode
        stage(plugins, mode, peer, mutation)
        transactions = [transaction(mode, peer, case) for case in cases(mode, peer)]
        fixture = directory / "transactions.json"
        fixture.write_text(json.dumps(transactions))
        optional = ["wordpress-hardening-ip.conf"] if mode != "base" else []
        if mutation == "autoload-ip" and mode == "base":
            optional = ["aaa-ci-accidental-before.conf"]
        print(
            xff.run(
                str(probe),
                "-tx",
                str(fixture),
                str(setup),
                "wordpress-hardening-config.conf",
                "zzz-ci-selection-config.conf",
                *optional,
                "wordpress-hardening-before.conf",
                "wordpress-hardening-after.conf",
                cwd=plugins,
            )
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=["coraza", *xff.TAG_KEYS])
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--mutation", choices=["remove-private", "autoload-ip"])
    args = parser.parse_args()
    if args.engine == "coraza" and args.probe is None:
        parser.error("coraza requires --probe")
    tags = xff.workflow_tags()
    with tempfile.TemporaryDirectory(prefix="wph-optional-ip-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        for private_peer in (False, True):
            lane = directory / ("private-peer" if private_peer else "public-peer")
            lane.mkdir()
            if args.engine == "coraza":
                coraza(lane, args.probe.resolve(), private_peer, args.mutation)
            else:
                modes = MODES + (("ratelimit",) if args.engine == "apache" else ())

                def prepare(target, mode, peer):
                    stage(target, mode, peer, args.mutation)

                xff.docker(
                    lane,
                    args.engine,
                    xff.selected_image(args.engine, tags),
                    private_peer,
                    modes=modes,
                    prepare=prepare,
                    check=check_http,
                )


if __name__ == "__main__":
    main()
