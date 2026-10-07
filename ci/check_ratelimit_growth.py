"""Probe SDBM growth from distinct login clients in disposable Apache/v2."""

import argparse
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from ci import check_ratelimit_mode as limiter

CLIENTS = 20
COLLECTION_TIMEOUT = 3
WAIT_SECONDS = COLLECTION_TIMEOUT + 2


def stage(directory, mode, peer, mutation=None):
    limiter.stage(directory, mode, peer, mutation)
    (directory / "zzz-ci-timeout.conf").write_text(
        f"SecCollectionTimeout {COLLECTION_TIMEOUT}\n"
    )


def key_count(server, directory, label, data_file):
    """Copy an idle SDBM pair and count its records without exposing keys."""
    base = directory / label
    for suffix in ("pag", "dir"):
        subprocess.run(
            ["docker", "cp", f"{server}:{data_file}.{suffix}", f"{base}.{suffix}"],
            check=True,
            capture_output=True,
        )
    result = subprocess.run(
        [
            "perl",
            "-MSDBM_File",
            "-e",
            'tie %records, "SDBM_File", $ARGV[0], 0, 0 or die $!; print scalar(keys %records);',
            str(base),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return int(result.stdout)


def check(_engine, _mode, url, server, _private_peer, directory):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def status(path, client, method="POST"):
        request = urllib.request.Request(
            url + path,
            headers={"User-Agent": "Rate-limit growth test", "X-Forwarded-For": client},
            data=b"log=reader&pwd=fixture" if method == "POST" else None,
            method=method,
        )
        try:
            with opener.open(request, timeout=3) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    last_error = None
    for _ in range(60):
        if (
            limiter.xff.run("docker", "inspect", "-f", "{{.State.Running}}", server)
            != "true"
        ):
            raise AssertionError(limiter.xff.run("docker", "logs", server))
        try:
            if status("/", "198.51.100.250", "GET") == 200:
                break
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
        time.sleep(1)
    else:
        raise AssertionError(f"readiness timeout: {last_error!r}")

    data_file = (
        limiter.xff.run("docker", "exec", server, "printenv", "MODSEC_DATA_DIR")
        + "/httpd-ip"
    )

    # GET and a POST on another path must not initialize IP collections.
    assert status("/wp-login.php", "198.51.100.250", "GET") == 200
    assert status("/", "198.51.100.250") == 200
    no_store = subprocess.run(
        ["docker", "exec", server, "test", "-e", data_file + ".pag"],
        check=False,
        capture_output=True,
    )
    assert no_store.returncode == 1, "non-login request created IP collection"

    for number in range(1, CLIENTS + 1):
        actual = status("/wp-login.php", f"198.51.100.{number}")
        assert actual == 200, f"client {number}: expected HTTP 200, got {actual}"
    store = subprocess.run(
        ["docker", "exec", server, "test", "-e", data_file + ".pag"],
        check=False,
        capture_output=True,
    )
    assert store.returncode == 0, "login requests did not create IP collection"
    initial = key_count(server, directory, "initial", data_file)
    assert initial == CLIENTS, (
        f"distinct clients: expected {CLIENTS} keys, got {initial}"
    )

    # A second request for the same identity updates its record, not key count.
    assert status("/wp-login.php", "198.51.100.1") == 200
    assert key_count(server, directory, "repeated", data_file) == initial

    time.sleep(WAIT_SECONDS)
    assert status("/wp-login.php", "198.51.100.200") == 200
    later = key_count(server, directory, "later", data_file)
    assert later == initial + 1, (
        f"expired distinct keys were reclaimed: expected {initial + 1}, got {later}"
    )
    print(
        f"collection timeout {COLLECTION_TIMEOUT}s; "
        f"{initial} distinct keys before wait, {later} after {WAIT_SECONDS}s "
        "and one new client",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutation", choices=("disable-limiter",))
    args = parser.parse_args()
    try:
        subprocess.run(
            ["perl", "-MSDBM_File", "-e", "1"],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        raise SystemExit("host Perl SDBM_File is required for growth probe") from error
    tags = limiter.xff.workflow_tags()
    with tempfile.TemporaryDirectory(prefix="wph-ratelimit-growth-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)

        def prepare(target, mode, peer):
            stage(target, mode, peer, args.mutation)

        def inspect(engine, mode, url, server, private_peer):
            check(engine, mode, url, server, private_peer, directory)

        limiter.xff.docker(
            directory,
            "apache",
            limiter.xff.selected_image("apache", tags),
            modes=("ratelimit",),
            prepare=prepare,
            check=inspect,
            environment=("MODSEC_RULE_ENGINE=On",),
        )


if __name__ == "__main__":
    main()
