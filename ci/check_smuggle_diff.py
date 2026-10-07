"""Bounded CL+TE framing probe through the two real CRS reverse proxies."""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from ci.check_xff_trust import selected_image, workflow_tags

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 8192
CASES = {
    "valid": (b"POST /framing-probe HTTP/1.1\r\nHost: probe.test\r\n"
              b"Content-Type: application/x-www-form-urlencoded\r\n"
              b"Content-Length: 4\r\nAccept: */*\r\n"
              b"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\ntest"),
    "ambiguous": (b"POST /framing-probe HTTP/1.1\r\nHost: probe.test\r\n"
                  b"Content-Type: application/x-www-form-urlencoded\r\n"
                  b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n"
                  b"Accept: */*\r\nUser-Agent: Mozilla/5.0\r\n"
                  b"Connection: close\r\n\r\n0\r\n\r\n"),
}


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def receive_once(listener, result):
    try:
        listener.settimeout(8)
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(0.5)
            chunks = []
            while sum(map(len, chunks)) < LIMIT:
                try:
                    chunk = conn.recv(LIMIT - sum(map(len, chunks)))
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            result.append(b"".join(chunks))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    except TimeoutError:
        pass
    finally:
        listener.close()


def probe(engine, case, request, image, network, gateway, staged, audit):
    origin = socket.socket()
    origin.bind((gateway, 0))
    origin.listen(1)
    seen = []
    thread = threading.Thread(target=receive_once, args=(origin, seen), daemon=True)
    thread.start()
    name = network + "-" + engine + "-" + case
    try:
        audit.write_text("")
        run("docker", "run", "-d", "--name", name, "--network", network,
            "-e", f"BACKEND=http://{gateway}:{origin.getsockname()[1]}",
            "-e", "PORT=8080", "-e", "PARANOIA=2",
            "-e", "MODSEC_RULE_ENGINE=On", "-e", "MODSEC_AUDIT_ENGINE=On",
            "-e", "MODSEC_AUDIT_LOG_TYPE=Serial",
            "-e", "MODSEC_AUDIT_LOG=/var/log/modsec/audit.log",
            "-v", f"{staged}:/etc/modsecurity.d/owasp-crs/plugins:ro",
            "-v", f"{audit.parent}:/var/log/modsec", image)
        address = run("docker", "inspect", "-f",
                      "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
        response = b""
        for _ in range(30):
            try:
                with socket.create_connection((address, 8080), timeout=1) as conn:
                    conn.settimeout(8)
                    conn.sendall(request)
                    while len(response) < LIMIT:
                        chunk = conn.recv(LIMIT - len(response))
                        if not chunk:
                            break
                        response += chunk
                break
            except (ConnectionRefusedError, TimeoutError):
                time.sleep(1)
        else:
            raise AssertionError(f"{engine}: WAF did not become ready")
        thread.join(timeout=9)
        status = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
        raw = seen[0] if seen else b""
        header, _, body = raw.partition(b"\r\n\r\n")
        audit_text = audit.read_text(errors="replace")
        record = {"engine": engine, "case": case, "status": status,
                  "decision": "allowed" if status.endswith(" 200 OK") else "rejected",
                  "origin_seen": bool(seen), "origin_headers": header.decode("latin1"),
                  "origin_body_hex": body.hex(),
                  "audit_has_transaction": bool(audit_text)}
        return record
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)
        origin.close()
        thread.join(timeout=1)


def assert_observations(records):
    assert {(r["engine"], r["case"]) for r in records} == {
        (engine, case) for engine in ("apache", "nginx") for case in CASES}
    for row in records:
        if row["case"] == "valid":
            assert row["status"].endswith(" 200 OK"), row
            assert row["origin_seen"], row
            assert row["origin_body_hex"] == b"test".hex(), row
            assert "content-length: 4" in row["origin_headers"].lower(), row
        else:
            if row["engine"] == "apache":
                assert row["status"].endswith(" 200 OK"), row
                assert row["audit_has_transaction"], row
                assert row["origin_seen"], row
                lengths = []
                for line in row["origin_headers"].split("\r\n")[1:]:
                    name, separator, value = line.partition(":")
                    if separator and name.lower() == "content-length":
                        lengths.append(value.strip())
                assert lengths == ["0"], row
                assert "transfer-encoding:" not in row["origin_headers"].lower(), row
                assert row["origin_body_hex"] == "", row
            else:
                assert row["status"].endswith(" 400 Bad Request"), row
                assert not row["origin_seen"], row


def main():
    tags = workflow_tags()
    with tempfile.TemporaryDirectory(prefix=".smuggle-", dir=ROOT / "tests/integration") as temp:
        work = Path(temp)
        staged = work / "plugins"
        staged.mkdir()
        for source in (*ROOT.glob("plugins/*"), *ROOT.glob("tests/integration/ci-plugin/*")):
            if source.is_file():
                shutil.copy2(source, staged / source.name)
        (staged / "aaa-ci-ip-before.conf").write_text(
            "Include /etc/modsecurity.d/owasp-crs/plugins/wordpress-hardening-ip.conf\n")
        (staged / "wordpress-hardening-ratelimit.conf").rename(
            staged / "wordpress-hardening-ratelimit-before.conf")
        audit_dir = work / "audit"
        audit_dir.mkdir(mode=0o777)
        audit_dir.chmod(0o777)
        audit = audit_dir / "audit.log"
        audit.write_text("")
        audit.chmod(0o666)
        network = "wph-smuggle-" + str(os.getpid())
        try:
            run("docker", "network", "create", network)
            gateway = run("docker", "network", "inspect", "-f",
                          "{{(index .IPAM.Config 0).Gateway}}", network)
            records = [probe(engine, case, request, selected_image(engine, tags),
                             network, gateway, staged, audit)
                       for engine in ("apache", "nginx")
                       for case, request in CASES.items()]
            print(json.dumps(records, indent=2))
            assert_observations(records)
        finally:
            subprocess.run(["docker", "network", "rm", network],
                           check=False, capture_output=True)


if __name__ == "__main__":
    main()
