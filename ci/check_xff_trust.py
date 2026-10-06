"""Exercise XFF defaults and proxy pinning on real WAF engines.

Docker lanes use both public benchmark and private peers, so tests cover
fallback, private exemptions, and malformed XFF on each engine. No CI
legacy-XFF override is loaded. All resources are disposable.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAG_KEYS = {"apache": "CRS_TAG", "nginx": "CRS_TAG_NGINX"}
TAG_WORKFLOWS = (
    "apache-modsecurity2.yml",
    "nginx-libmodsecurity3.yml",
    "security-corpus.yml",
)
MALFORMED_IPV6 = {
    "[::1",
    "::1]",
    "::ffff:10.999.999.999",
    "::ffff:127.0.0.256",
    "::ffff:127.000.0.1",
    "::ffff:127.0.0.01",
}


def workflow_tags():
    """Read the same CRS tags used by the engine workflows and compose."""
    selected = {}
    for workflow in TAG_WORKFLOWS:
        source = (ROOT / ".github/workflows" / workflow).read_text()
        for key in TAG_KEYS.values():
            matches = re.findall(r"^  " + key + r': "([^"]+)"$', source, re.MULTILINE)
            if len(matches) != 1:
                raise ValueError(f"{workflow}: expected exactly one {key}")
            if key in selected and selected[key] != matches[0]:
                raise ValueError(f"{workflow}: {key} differs from other workflows")
            selected[key] = matches[0]
    for key, tag in selected.items():
        if key in os.environ and os.environ[key] != tag:
            raise ValueError(f"{key} environment differs from workflow tag {tag}")
    return selected


def selected_image(engine, tags, explicit=None):
    return explicit or "owasp/modsecurity-crs:" + tags[TAG_KEYS[engine]]


# name, header, whether a trusted first hop is private
CASES = [
    ("no-header", None, False),
    ("spoof-loopback", "127.0.0.1", True),
    ("spoof-rfc1918", "10.20.30.40", True),
    ("spoof-ula", "fc00::1", True),
    ("spoof-ipv6-loopback", "::1", True),
    ("spoof-mapped", "::ffff:10.0.0.1", True),
    ("spoof-bracketed-v6", "[::1]", True),
    ("spoof-v4-port", "127.0.0.1:8080", True),
    ("spoof-bracketed-v6-port", "[::1]:443", True),
    ("v4-port-minimum", "127.0.0.1:1", True),
    ("v4-port-maximum", "127.0.0.1:65535", True),
    ("v6-port-minimum", "[::1]:1", True),
    ("v6-port-maximum", "[::1]:65535", True),
    ("spoof-v6-full", "0:0:0:0:0:0:0:1", True),
    ("spoof-v6-full-padded", "0000:0000:0000:0000:0000:0000:0000:0001", True),
    ("spoof-v6-full-bracketed", "[0:0:0:0:0:0:0:1]", True),
    ("public-v6-full", "0:0:0:0:0:0:0:2", False),
    ("spoof-v6-compressed", "fd00::1", True),
    ("public", "8.8.8.8", False),
    ("private-first", "10.0.0.1, 8.8.8.8", True),
    ("public-first", "8.8.8.8, 10.0.0.1", False),
    ("private-boundary", "172.31.255.255", True),
    ("public-boundary", "172.32.0.1", False),
    ("malformed-v4", "127.0.0.1junk", False),
    ("malformed-v4-port-overflow", "127.0.0.1:65536", False),
    ("malformed-v4-port-junk", "127.0.0.1:80junk", False),
    ("malformed-v4-port-zero", "127.0.0.1:0", False),
    ("malformed-v4-port-leading-zero", "127.0.0.1:080", False),
    ("malformed-v6-port-overflow", "[::1]:65536", False),
    ("malformed-v6-port-junk", "[::1]:80junk", False),
    ("malformed-v6-port-zero", "[::1]:0", False),
    ("malformed-v6-port-leading-zero", "[::1]:080", False),
    ("malformed-v6-unbracketed-port", "::1:12345", False),
    ("malformed-v6", "::1junk", False),
    ("invalid-octet", "999.0.0.1", False),
    ("empty-first", ", 127.0.0.1", False),
    ("missing-v6-bracket", "[::1", False),
    ("extra-v6-bracket", "::1]", False),
    ("mapped-invalid-999", "::ffff:10.999.999.999", False),
    ("mapped-invalid-256", "::ffff:127.0.0.256", False),
    ("mapped-leading-zero-3", "::ffff:127.000.0.1", False),
    ("mapped-leading-zero-2", "::ffff:127.0.0.01", False),
    ("mapped-comma", "::ffff:10.0.0.1, 8.8.8.8", True),
    ("v6-whitespace", "::1   ", True),
]


# Each name carries an independently chosen expected private-network outcome.
IPV6_BOUNDARIES = [
    ("mapped-expanded-private", "0:0:0:0:0:ffff:10.0.0.1", True),
    ("mapped-expanded-public", "0:0:0:0:0:ffff:192.0.2.1", False),
    ("mapped-compressed-private", "0:0::0:ffff:192.168.1.1", True),
    ("mapped-padded-private", "0000:0000:0000:0000:0000:FFFF:127.0.0.1", True),
    ("mapped-bracketed-private", "[0:0:0:0:0:ffff:10.0.0.1]", True),
    ("mixed-uncompressed", "2001:db8:1:2:3:4:192.0.2.1", False),
    ("mixed-compressed", "2001:db8::1:192.0.2.1", False),
    ("mixed-ula", "fc00:1:2:3:4:5:192.0.2.1", True),
    ("ula-compression-boundary", "fc00:0:0:0:0:0::1", True),
    ("ula-overlong-compression", "fc00:0:0:0:0:0:0::1", False),
    ("ula-short-uncompressed", "fc00:1", False),
    ("ula-overlong-mixed", "fc00:0:0:0:0:0:0:192.0.2.1", False),
    ("mixed-overlong-compression", "fc00:0:0:0:0:0::192.0.2.1", False),
    ("encoded-ipv4", "%31%30.0.0.1", False),
    ("encoded-ipv6", "fc00%3a%3a1", False),
]
CASES.extend(IPV6_BOUNDARIES)


def address_corpus():
    """Generate group-count boundaries independently of the rule's regex."""
    addresses = {header for _, header, _ in IPV6_BOUNDARIES}
    addresses.update(MALFORMED_IPV6)
    addresses.update({"::", "::1", "[::]", "::ffff:0.0.0.0", "::ffff:255.255.255.255"})
    for count in range(11):
        groups = ["fc00"] + ["0"] * max(0, count - 1) if count else []
        addresses.add(":".join(groups))
        for split in range(count + 1):
            addresses.add(":".join(groups[:split]) + "::" + ":".join(groups[split:]))
        for tail in ("192.0.2.1", "256.0.0.1", "01.2.3.4"):
            addresses.add(":".join(groups + [tail]))
            for split in range(count + 1):
                addresses.add(
                    ":".join(groups[:split]) + "::" + ":".join(groups[split:] + [tail])
                )
    addresses.update(
        {
            "ffff:FFFF:0123:4567:89ab:cdef:abcd:ef01",
            "abcd::ffff:255.255.255.255",
            "abcde::1",
            "gggg::1",
            "1::2::3",
            ":::1",
            "1:::2",
            "::1%eth0",
            "[::1]:80",
            "::ffff:192.0.2.1:80",
            "::ffff:192.0.2.",
            "[127.0.0.1]",
            "fc00::1 junk",
            "fc00::1, 8.8.8.8",
            " fc00::1   ",
        }
    )
    # Every possible zero-compression position in an IPv4-mapped prefix.
    for left in range(6):
        for right in range(6):
            addresses.add(
                ":".join(["0"] * left)
                + "::"
                + ":".join(["0"] * right + ["ffff", "10.0.0.1"])
            )
    return sorted(addresses)


def expected_address(header):
    """Standards oracle for first-hop IPs and explicit, bounded ports."""
    token = header.split(",", 1)[0].strip()
    if token.startswith("["):
        closing = token.find("]")
        if closing < 0:
            return None
        address, suffix = token[1:closing], token[closing + 1 :]
    elif token.count(":") == 1:
        address, separator, port = token.partition(":")
        suffix = separator + port
    else:
        address, suffix = token, ""
    if suffix and (
        not suffix.startswith(":")
        or not re.fullmatch(r"[1-9][0-9]{0,4}", suffix[1:])
        or int(suffix[1:]) > 65535
    ):
        return None
    if "%" in address:
        return None
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if token.startswith("[") and not isinstance(parsed, ipaddress.IPv6Address):
        return None
    return address


def parser_cases():
    # Run the same differential corpus on PCRE/PCRE2 and RE2, not just Python re.
    headers = set(address_corpus())
    for header in address_corpus():
        headers.add("[" + header + "]:443")
        if expected_address(header) is not None and ":" in header and "[" not in header:
            headers.update({"[" + header + "]", header + " , 8.8.8.8"})
    headers.update({"8.8.8.8", "127.0.0.1", "%31%30.0.0.1", "fc00%3a%3a1"})
    headers.update(header for _, header, _ in CASES if header is not None)
    for index, header in enumerate(sorted(headers)):
        yield "parser-" + str(index), header, expected_address(header)


def run(*args, **kwargs):
    """Keep subprocess failures visible without using a shell."""
    try:
        return subprocess.check_output(args, text=True, **kwargs).strip()
    except subprocess.CalledProcessError as error:
        print(error.output, flush=True)
        raise


def stage(directory, mode, peer):
    shutil.copytree(ROOT / "plugins", directory)
    with (directory / "wordpress-hardening-before.conf").open("a") as rules:
        rules.write(
            '\nSecRule REQUEST_URI "@streq /xff-parser-probe" '
            '"id:9902064,phase:1,deny,status:409,log,t:none,chain"\n'
            ' SecRule TX:wphard.xff_parsed "@eq 1" "t:none,chain"\n'
            " SecRule TX:wphard.client_ip "
            '"!@streq %{REQUEST_HEADERS.X-Expected-Client-IP}" "t:none"\n'
            'SecRule REQUEST_URI "@streq /xff-parser-probe" '
            '"id:9902063,phase:1,deny,status:403,log,t:none,chain"\n'
            ' SecRule TX:wphard.xff_parsed "@eq 1" "t:none"\n'
        )
    config = []
    if mode in ("trusted", "untrusted"):
        config.append(
            'SecAction "id:9902062,phase:1,pass,nolog,setvar:tx.wphard.trusted_proxies_enabled=1"'
        )
    elif mode in ("legacy", "unsupported", "textual"):
        value = {"legacy": 0, "unsupported": 2, "textual": "false"}[mode]
        config.append(
            'SecAction "id:9902062,phase:1,pass,nolog,'
            f'setvar:tx.wphard.trusted_proxies_enabled={value}"'
        )
    if peer.startswith("10."):
        with (directory / "wordpress-hardening-ip-reputation.data").open("a") as data:
            data.write("\n" + peer + "\n2001:db8::bad\n")
        config.append(
            'SecRule REQUEST_URI "@streq /ip-reputation-probe" '
            '"id:9902061,phase:1,pass,nolog,t:none,setvar:tx.wphard.ip_reputation_enabled=1"'
        )
    if config:
        (directory / "ci-xff-probe-config.conf").write_text("\n".join(config) + "\n")
    if mode != "default":
        # An exact IP tests the peer boundary: untrusted is adjacent.
        trusted = peer if mode == "trusted" else str(ipaddress.ip_address(peer) + 1)
        (directory / "wordpress-hardening-trusted-proxies.data").write_text(
            "# Trusted test peer\n" + trusted + "\n"
        )


def peer_cases(private_peer):
    # Private forwarding peers must never lend their exemption to public XFF.
    if private_peer:
        cases = [
            ("private-peer-no-header", None, False),
            ("private-peer-public-XFF", "8.8.8.8", False),
            ("private-peer-private-XFF", "10.0.0.5", True),
            ("private-peer-v4-port-XFF", "10.0.0.5:8080", True),
            ("private-peer-v6-port-XFF", "[::1]:443", True),
            ("private-peer-malformed-v4-port-XFF", "10.0.0.5:65536", False),
            ("private-peer-malformed-v6-port-XFF", "[::1]:65536", False),
        ]
        cases.extend(
            [
                ("private-peer-empty-XFF", "", False),
                ("private-peer-malformed-XFF", "127.0.0.1junk", False),
                ("private-peer-malformed-whitespace-v4-XFF", "127.0.0.1 junk", False),
                ("private-peer-malformed-whitespace-v6-XFF", "::1 junk", False),
                ("private-peer-private-comma-XFF", "10.0.0.5 , 8.8.8.8", True),
                ("private-peer-private-whitespace-XFF", "10.0.0.5   ", True),
                ("private-peer-missing-v6-bracket", "[::1", False),
                ("private-peer-extra-v6-bracket", "::1]", False),
                ("private-peer-mapped-invalid-999", "::ffff:10.999.999.999", False),
                ("private-peer-mapped-invalid-256", "::ffff:127.0.0.256", False),
                ("private-peer-mapped-leading-zero-3", "::ffff:127.000.0.1", False),
                ("private-peer-mapped-leading-zero-2", "::ffff:127.0.0.01", False),
                ("private-peer-bracketed-v6", "[::1]", True),
                ("private-peer-mapped-comma", "::ffff:10.0.0.1, 8.8.8.8", True),
                ("private-peer-v6-whitespace", "::1   ", True),
            ]
        )
        cases.extend(IPV6_BOUNDARIES)
        return cases
    return CASES


def reputation_cases(mode, peer):
    cases = []
    for name, header in [
        ("private-peer-reputation-public-XFF", "8.8.8.8"),
        ("private-peer-reputation-no-header", None),
        ("private-peer-reputation-v6-XFF", "2001:db8::bad"),
        ("private-peer-reputation-bracketed-v6-XFF", "[2001:db8::bad]"),
    ]:
        blocked = header is not None and (
            mode not in ("trusted", "legacy") or name.endswith("v6-XFF")
        )
        cases.append(
            {
                "name": mode + ":" + name,
                "uri": "/ip-reputation-probe",
                "client_ip": peer,
                "headers": {"X-Forwarded-For": header} if header else {},
                "expect_ids": [9522603] if blocked else [],
                "no_expect_ids": [9522601] if blocked else [9522603],
                "expect_interruption": blocked,
            }
        )
    return cases


def parser_ids(mode, name, header):
    """Require a parsed full address and reject malformed first hops in trusted modes."""
    if mode not in ("trusted", "legacy"):
        return [], [9522068] if name == "spoof-bracketed-v6-port" else []
    expected = []
    if name == "spoof-v6-full":
        expected.append(9522062)
    if name == "spoof-bracketed-v6-port":
        expected.append(9522068)
    forbidden = [9522062] if header in MALFORMED_IPV6 else []
    if name.startswith("malformed-v6-port"):
        forbidden.append(9522068)
    return expected, forbidden


def parser_transactions(mode, peer):
    """Assert both parser acceptance and the exact downstream client identity."""
    for name, header, address in parser_cases():
        accepted = mode in ("trusted", "legacy") and address is not None
        yield {
            "name": mode + ":" + name,
            "uri": "/xff-parser-probe",
            "client_ip": peer,
            "headers": {
                "Host": "localhost",
                "User-Agent": "XFF trust test",
                "Accept": "*/*",
                "X-Forwarded-For": header,
                "X-Expected-Client-IP": address or "invalid",
            },
            "expect_ids": [9902063] if accepted else [],
            "no_expect_ids": [9902064] if accepted else [9902063, 9902064],
            "expect_interruption": accepted,
        }


def coraza(directory, probe, private_peer=False):
    peer = "10.254.0.1" if private_peer else "198.18.0.1"
    setup = directory / "setup.conf"
    setup.write_text('SecDefaultAction "phase:2,log,deny,status:403"\n')
    for mode in ("default", "trusted", "untrusted", "legacy", "unsupported", "textual"):
        plugins = directory / mode
        stage(plugins, mode, peer)
        cases = []
        for name, header, private in peer_cases(private_peer):
            ids = parser_ids(mode, name, header)
            allowed = (mode in ("trusted", "legacy") and private) or (
                private_peer and header is None
            )
            headers = {
                "Host": "localhost",
                "User-Agent": "XFF trust test",
                "Accept": "*/*",
            }
            if header is not None:
                headers["X-Forwarded-For"] = header
            cases.append(
                {
                    "name": mode + ":" + name,
                    "uri": "/xmlrpc.php",
                    "client_ip": peer,
                    "headers": headers,
                    "expect_ids": ([] if allowed else [9522102]) + ids[0],
                    "no_expect_ids": ([9522102] if allowed else []) + ids[1],
                    "expect_interruption": not allowed,
                }
            )
        cases.append(
            {
                "name": mode + ":homepage",
                "uri": "/",
                "client_ip": peer,
                "expect_interruption": False,
                "no_expect_ids": [9522102],
            }
        )
        cases.append(
            {
                "name": mode + ":direct-private-peer",
                "uri": "/xmlrpc.php",
                "client_ip": "10.0.0.1",
                "expect_interruption": False,
                "no_expect_ids": [9522102],
            }
        )
        if private_peer:
            cases.extend(reputation_cases(mode, peer))
        cases.extend(parser_transactions(mode, peer))
        fixture = directory / "transactions.json"
        fixture.write_text(json.dumps(cases))
        print(
            run(
                str(probe),
                "-tx",
                str(fixture),
                str(setup),
                "wordpress-hardening-config.conf",
                *(
                    ["ci-xff-probe-config.conf"]
                    if (plugins / "ci-xff-probe-config.conf").exists()
                    else []
                ),
                "wordpress-hardening-ip.conf",
                "wordpress-hardening-before.conf",
                "wordpress-hardening-after.conf",
                cwd=plugins,
            )
        )


def check_http(engine, mode, url, server, private_peer):
    """Assert real HTTP outcomes after the complete ruleset starts."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def status(path, header=None, address=None):
        headers = {"User-Agent": "XFF trust test", "Accept": "*/*"}
        if header is not None:
            headers["X-Forwarded-For"] = header
        if address is not None:
            headers["X-Expected-Client-IP"] = address
        request = urllib.request.Request(url + path, headers=headers)
        try:
            with opener.open(request, timeout=3) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    for _ in range(60):
        if run("docker", "inspect", "-f", "{{.State.Running}}", server) != "true":
            raise AssertionError(run("docker", "logs", server))
        try:
            if status("/") == 200:
                break
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    else:
        raise AssertionError(run("docker", "logs", server))
    for case, header, private in peer_cases(private_peer):
        allowed = (mode in ("trusted", "legacy") and private) or (
            private_peer and header is None
        )
        expected = 200 if allowed else 403
        actual = status("/xmlrpc.php", header)
        assert actual == expected, (
            f"{engine}:{mode}:{case}: expected {expected}, got {actual}"
        )
        print(f"{engine}:{mode}:{case}: HTTP {actual}", flush=True)
    if private_peer:
        for case in reputation_cases(mode, "unused"):
            actual = status(case["uri"], case["headers"].get("X-Forwarded-For"))
            expected = 403 if case["expect_interruption"] else 200
            assert actual == expected, (
                f"{engine}:{case['name']}: expected {expected}, got {actual}"
            )
            print(f"{engine}:{case['name']}: HTTP {actual}", flush=True)
    check_parser_http(status, engine, mode)
    assert status("/") == 200, f"{engine}:{mode}:homepage blocked"
    print(f"{engine}:{mode}:homepage: HTTP 200", flush=True)


def check_parser_http(status, engine, mode):
    """Check parser markers separately from XML-RPC and reputation behavior."""
    for case, header, address in parser_cases():
        accepted = mode in ("trusted", "legacy") and address is not None
        expected = 403 if accepted else 200
        actual = status("/xff-parser-probe", header, address or "invalid")
        assert actual == expected, (
            f"{engine}:{mode}:{case}:{header!r}: expected {expected}, got {actual}"
        )
    print(f"{engine}:{mode}: differential parser corpus passed", flush=True)


def docker(
    directory,
    engine,
    image,
    private_peer=False,
    *,
    modes=("default", "trusted", "untrusted", "legacy", "unsupported", "textual"),
    prepare=stage,
    check=check_http,
):
    name = directory.parent.name.replace(".", "-") + "-" + directory.name
    network = name + "-net"
    containers = []
    try:
        # Use a small benchmark subnet; concurrent runs get distinct PID slots.
        base = (
            ipaddress.ip_address("10.254.0.0" if private_peer else "198.18.0.0")
            + (os.getpid() % 8192) * 16
        )
        run("docker", "network", "create", "--subnet", str(base) + "/28", network)
        peer = str(base + 1)  # host gateway, the directly-connected test peer
        containers.append(name + "-backend")
        run(
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name + "-backend",
            "--network",
            network,
            "-v",
            str(ROOT / "tests/integration/backend/nginx.conf")
            + ":/etc/nginx/nginx.conf:ro",
            "nginx:alpine",
        )
        for mode in modes:
            plugins = directory / mode
            prepare(plugins, mode, peer)
            if mode != "base":
                (plugins / "aaa-ci-ip-before.conf").write_text(
                    "Include /etc/modsecurity.d/owasp-crs/plugins/"
                    "wordpress-hardening-ip.conf\n"
                )
            server = name + "-" + mode
            containers.append(server)
            run(
                "docker",
                "run",
                "-d",
                "--name",
                server,
                "--network",
                network,
                "-e",
                "BACKEND=http://" + name + "-backend:80",
                "-e",
                "PORT=8080",
                "-e",
                "MODSEC_RULE_ENGINE=On",
                "-e",
                "MODSEC_RESP_BODY_ACCESS=Off",
                "-v",
                str(plugins) + ":/etc/modsecurity.d/owasp-crs/plugins:ro",
                image,
            )
            address = run(
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                server,
            )
            url = "http://" + address + ":8080"

            check(engine, mode, url, server, private_peer)
            run("docker", "rm", "-f", server)
            containers.remove(server)
    finally:
        for container in reversed(containers):
            subprocess.run(
                ["docker", "rm", "-f", container], check=False, capture_output=True
            )
        subprocess.run(
            ["docker", "network", "rm", network], check=False, capture_output=True
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", nargs="?", choices=["coraza", *TAG_KEYS])
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--image", help="explicit Docker image for the selected engine")
    parser.add_argument(
        "--check-tags",
        action="store_true",
        help="check workflow tag consistency and exit",
    )
    args = parser.parse_args()
    tags = workflow_tags()
    if args.check_tags:
        print("CRS workflow tags consistent", flush=True)
        return
    if args.engine is None:
        parser.error("engine is required unless --check-tags is set")
    if args.engine == "coraza" and args.probe is None:
        parser.error("coraza requires --probe")
    if args.engine == "coraza" and args.image is not None:
        parser.error("--image is only valid for Docker engines")
    with tempfile.TemporaryDirectory(prefix="wph-xff-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        for private_peer in (False, True):
            lane = directory / ("private-peer" if private_peer else "public-peer")
            lane.mkdir()
            if args.engine == "coraza":
                coraza(lane, args.probe.resolve(), private_peer)
            else:
                docker(
                    lane,
                    args.engine,
                    selected_image(args.engine, tags, args.image),
                    private_peer,
                )


if __name__ == "__main__":
    main()
