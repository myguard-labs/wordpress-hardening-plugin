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
    (directory / "zzz-ci-ratelimit-config.conf").write_text(
        f'SecAction "id:9902072,phase:1,pass,nolog,'
        f'setvar:tx.wphard.ratelimit_login_attempts={LIMIT}"\n'
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


def check(_engine, _mode, url, server, _private_peer):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def status(path, client=None, data=None):
        headers = {"User-Agent": "Rate-limit On-mode test"}
        if client is not None:
            headers["X-Forwarded-For"] = client
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
            pass
        time.sleep(1)
    else:
        raise AssertionError(xff.run("docker", "logs", server))

    # The disposable container starts with empty persistent collections. A and
    # B use different resolved XFF clients; B cannot consume A's attempts.
    for name, client, expected in (
        ("client-a-first", "198.51.100.100", 200),
        ("client-a-below-limit", "198.51.100.100", 200),
        ("client-b-first", "198.51.100.101", 200),
        ("client-a-at-limit", "198.51.100.100", 429),
        ("client-b-below-limit", "198.51.100.101", 200),
    ):
        actual = status(LOGIN, client, b"log=reader&pwd=fixture")
        assert actual == expected, f"{name}: expected HTTP {expected}, got {actual}"
        print(f"{name}: HTTP {actual}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutation", choices=("remove-deny",))
    args = parser.parse_args()
    tags = xff.workflow_tags()
    with tempfile.TemporaryDirectory(prefix="wph-ratelimit-mode-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)

        def prepare(target, mode, peer):
            stage(target, mode, peer, args.mutation)

        xff.docker(
            directory, "apache", xff.selected_image("apache", tags),
            modes=("ratelimit",), prepare=prepare, check=check,
            environment=("MODSEC_RULE_ENGINE=On",),
        )


if __name__ == "__main__":
    main()
