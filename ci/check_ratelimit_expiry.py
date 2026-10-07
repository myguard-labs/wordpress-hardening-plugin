"""Exercise the optional limiter's 60-second expiry in fresh Apache state."""

import argparse
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ci import check_ratelimit_mode as limiter

CLIENT = "198.51.100.151"
EXPIRY_SECONDS = 60
WAIT_SECONDS = EXPIRY_SECONDS + 2


def stage(directory, mode, peer, mutation=None):
    limiter.stage(directory, mode, peer)
    if mutation == "remove-expiry":
        rules = directory / "wordpress-hardening-ratelimit.conf"
        original = rules.read_text()
        expiry = ",\\\n    expirevar:ip.login_attempts=60"
        assert original.count(expiry) == 1
        rules.write_text(original.replace(expiry, ""))


def check(_engine, _mode, url, server, _private_peer):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def status(path, *, method="POST"):
        request = urllib.request.Request(
            url + path,
            headers={
                "User-Agent": "Rate-limit expiry test",
                "X-Forwarded-For": CLIENT,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=b"log=reader&pwd=fixture" if method == "POST" else None,
            method=method,
        )
        try:
            with opener.open(request, timeout=3) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    for _ in range(60):
        if (
            limiter.xff.run("docker", "inspect", "-f", "{{.State.Running}}", server)
            != "true"
        ):
            raise AssertionError(limiter.xff.run("docker", "logs", server))
        try:
            if status("/", method="GET") == 200:
                break
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    else:
        raise AssertionError(limiter.xff.run("docker", "logs", server))

    for name, expected in (
        ("first-attempt", 200),
        ("below-threshold", 200),
        ("at-threshold", 429),
        ("before-expiry", 429),
    ):
        actual = status(limiter.LOGIN)
        assert actual == expected, f"{name}: expected HTTP {expected}, got {actual}"
        print(f"{name}: HTTP {actual}", flush=True)

    time.sleep(WAIT_SECONDS)
    actual = status(limiter.LOGIN)
    assert actual == 200, f"after-expiry: expected HTTP 200, got {actual}"
    print(f"after-expiry: HTTP {actual}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutation", choices=("remove-expiry",))
    args = parser.parse_args()
    tags = limiter.xff.workflow_tags()
    with tempfile.TemporaryDirectory(prefix="wph-ratelimit-expiry-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)

        def prepare(target, mode, peer):
            stage(target, mode, peer, args.mutation)

        limiter.xff.docker(
            directory,
            "apache",
            limiter.xff.selected_image("apache", tags),
            modes=("ratelimit",),
            prepare=prepare,
            check=check,
            environment=("MODSEC_RULE_ENGINE=On",),
        )


if __name__ == "__main__":
    main()
