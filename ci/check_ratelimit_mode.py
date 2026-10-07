"""Assert the optional login limiter returns HTTP 429 in ModSecurity On mode."""

import argparse
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ci import check_xff_trust as xff

LIMIT = 3
LOGIN = "/wp-login.php"


def stage(directory, _mode, peer, mutation=None):
    shutil.copytree(xff.ROOT / "plugins", directory)
    (directory / "wordpress-hardening-trusted-proxies.data").write_text(peer + "\n")
    settings = f"setvar:tx.wphard.ratelimit_login_attempts={LIMIT}"
    if mutation == "disable-limiter":
        settings += ",setvar:tx.wphard.ratelimit_login_enabled=0"
    (directory / "zzz-ci-ratelimit-config.conf").write_text(
        f'SecAction "id:9902072,phase:1,pass,nolog,{settings}"\n'
    )
    (directory / "zzz-ci-ratelimit-before.conf").write_text(
        "Include /etc/modsecurity.d/owasp-crs/plugins/"
        "wordpress-hardening-ratelimit.conf\n"
    )
    if mutation == "remove-deny":
        rules = directory / "wordpress-hardening-ratelimit.conf"
        original = rules.read_text()
        assert original.count("deny,status:429") == 1
        rules.write_text(original.replace("deny,status:429", "pass"))
    if mutation == "remove-retry-after":
        rules = directory / "wordpress-hardening-ratelimit.conf"
        original = rules.read_text()
        assert original.count("setenv:'wphard_retry_after=60'") == 1
        rules.write_text(original.replace("setenv:'wphard_retry_after=60',\\\n", ""))


def configure_apache_retry_after(server):
    """Enable the documented optional Apache Header directive in the fixture."""
    with tempfile.TemporaryDirectory(prefix="wph-apache-header-") as temporary:
        header_conf = Path(temporary) / "apache-retry-after.conf"
        header_conf.write_text(
            'Header always set Retry-After "%{wphard_retry_after}e" '
            "env=wphard_retry_after\n"
        )
        xff.run(
            "docker", "cp", str(header_conf), f"{server}:/tmp/apache-retry-after.conf"
        )
        xff.run(
            "docker", "exec", server, "sh", "-c",
            "cat /tmp/apache-retry-after.conf >> /usr/local/apache2/conf/httpd.conf",
        )
        xff.run("docker", "exec", server, "apachectl", "-k", "graceful")


def check(_engine, _mode, url, server, _private_peer):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def response(path, client=None, data=None, method=None):
        headers = {"User-Agent": "Rate-limit On-mode test"}
        if client is not None:
            headers["X-Forwarded-For"] = client
        request = urllib.request.Request(
            url + path, headers=headers, data=data, method=method
        )
        try:
            with opener.open(request, timeout=3) as response:
                return response.status, response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.headers

    for _ in range(60):
        if xff.run("docker", "inspect", "-f", "{{.State.Running}}", server) != "true":
            raise AssertionError(xff.run("docker", "logs", server))
        try:
            if response("/")[0] == 200:
                break
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    else:
        raise AssertionError(xff.run("docker", "logs", server))

    # Exercise exactly the Apache Header directive documented in README.
    configure_apache_retry_after(server)

    # Each disposable container has empty persistent collections. Query strings
    # and XFF port/chain spellings must not reset A's counter.
    # A's GET must not consume an attempt; B must retain its own allowance.
    # Invalid XFF values resolve to the same direct peer, so cannot rotate C.
    for name, path, client, method, data, expected in (
        (
            "client-a-first",
            LOGIN,
            "198.51.100.100",
            "POST",
            b"log=reader&pwd=fixture",
            200,
        ),
        (
            "client-a-get",
            LOGIN + "?action=lostpassword",
            "198.51.100.100",
            "GET",
            None,
            200,
        ),
        (
            "client-b-first",
            LOGIN,
            "198.51.100.101",
            "POST",
            b"log=reader&pwd=fixture",
            200,
        ),
        (
            "client-a-port-below-limit",
            LOGIN + "?redirect_to=%2Fwp-admin%2F",
            "198.51.100.100:8080",
            "POST",
            b"log=reader&pwd=fixture",
            200,
        ),
        (
            "client-b-chain-below-limit",
            LOGIN + "?action=login",
            "198.51.100.101, 203.0.113.9",
            "POST",
            b"log=reader&pwd=fixture",
            200,
        ),
        (
            "client-a-chain-at-limit",
            LOGIN + "?action=login",
            "198.51.100.100, 203.0.113.9",
            "POST",
            b"log=reader&pwd=fixture",
            429,
        ),
        (
            "client-b-port-at-limit",
            LOGIN,
            "198.51.100.101:8080",
            "POST",
            b"log=reader&pwd=fixture",
            429,
        ),
        (
            "client-c-invalid-first",
            LOGIN,
            "not-an-ip",
            "POST",
            b"log=reader&pwd=fixture",
            200,
        ),
        (
            "client-c-invalid-below-limit",
            LOGIN + "?action=login",
            "999.0.0.1",
            "POST",
            b"log=reader&pwd=fixture",
            200,
        ),
        (
            "client-c-invalid-at-limit",
            LOGIN,
            "198.51.100.102:0",
            "POST",
            b"log=reader&pwd=fixture",
            429,
        ),
    ):
        actual, headers = response(path, client, data, method)
        assert actual == expected, f"{name}: expected HTTP {expected}, got {actual}"
        retry_after = headers.get("Retry-After")
        expected_retry_after = "60" if expected == 429 else None
        assert retry_after == expected_retry_after, (
            f"{name}: expected Retry-After {expected_retry_after!r}, got {retry_after!r}"
        )
        print(f"{name}: HTTP {actual}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mutation",
        choices=("remove-deny", "disable-limiter", "remove-retry-after"),
    )
    args = parser.parse_args()
    tags = xff.workflow_tags()
    with tempfile.TemporaryDirectory(prefix="wph-ratelimit-mode-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)

        def prepare(target, mode, peer):
            stage(target, mode, peer, args.mutation)

        xff.docker(
            directory,
            "apache",
            xff.selected_image("apache", tags),
            modes=("ratelimit",),
            prepare=prepare,
            check=check,
            environment=("MODSEC_RULE_ENGINE=On",),
        )


if __name__ == "__main__":
    main()
