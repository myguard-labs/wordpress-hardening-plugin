# Integration tests — official OWASP CRS images, two engines

The plugin is tested against the **official OWASP CRS Docker images**, one per
engine, so CRS version drift never breaks CI the way a pinned distro package
did. Each image is a reverse proxy in front of a tiny stub origin; this repo's
plugin tree is mounted into the CRS plugins dir.

| Service  | Image                                   | Engine                         | Port |
|----------|-----------------------------------------|--------------------------------|------|
| `apache` | `owasp/modsecurity-crs:<tag>-apache`    | Apache httpd + **ModSecurity v2** | 8001 |
| `nginx`  | `owasp/modsecurity-crs:<tag>-nginx`     | nginx + **libmodsecurity3** (v3)  | 8002 |
| `backend`| `nginx:alpine`                          | stub origin, returns 200 on every path | — |

The image tag is set in one place — the `CRS_TAG` / `CRS_TAG_NGINX` env in the
workflows (and `${CRS_TAG:-apache}` / `${CRS_TAG_NGINX:-nginx}` defaults in the
compose file). Bump there to move CRS versions; `-dev` tags are not used.

## How the plugin loads

The official image's include chain is:

```
*-config.conf -> *-before.conf -> CRS rules -> *-after.conf
```

Compose mounts `tests/integration/.plugins-staged/` into both WAF services at
`/etc/modsecurity.d/owasp-crs/plugins/`. Stage copies from `plugins/` and the
CI-only `ci-plugin/zzz-ci-config.conf` before startup. That extra config enables
the opt-in features (GeoIP login control, IP reputation, scanner/REST/wp-cron
blocking, plugin readme blocking, strict integer params) that ship disabled,
and bumps detection paranoia to 2. A CI-only before-file explicitly includes
`wordpress-hardening-ip.conf` before the main rules; the rate-limit include runs
after them. Base-only selection tests leave the IP file present but unincluded.
Restage after editing either source tree,
then restart the WAF services to load the new rules.

The shipped `block_plugin_readme` default remains `0`; the shared CI fixture
explicitly enables it for rule 9522115 tests. `ci/test_info_leak_paths.py` and
the Coraza default fixture load the shipped rules without that override and
assert the disabled behavior. The unit suite also checks that explicit opt-in
still enables the rule.

Rule 9522100 tests cover exact filenames and slash-delimited PATH_INFO for
installers and named static files, filename near-misses, and the existing
raw-path single-decode behavior. Static-file suffixes cover optional origin
configurations that accept PATH_INFO; no default static-file exposure is assumed.
The tests assert the specific rule ID: other plugin rules may independently
match a filename near-miss. All engine cases use inert requests and a stub
origin; they do not run a WordPress installer.

go-ftw's `X-CRS-Test` markers are recorded by audit part B directly. A
separate marker rule duplicates them in part H and can make go-ftw capture a
partially written marker line, breaking exact start/end matching.

Engine settings (`SecRuleEngine DetectionOnly`, serial native audit log, body
access) come from the image's `MODSEC_*` environment variables, set in the
compose file. DetectionOnly so go-ftw can drive every endpoint and assert on
the audit log without traffic being 403'd.

The Apache workflow also runs `python3 -m ci.check_block_mode` in a separate
disposable container with `SecRuleEngine On`, PL2, and the production inbound
threshold of 5. It enables the shipped plugin readme rule for one request,
requires that rule's PL2 score marker and CRS threshold rule 949110 in the
attack transaction, checks HTTP 403, and checks that the homepage stays 200.
The shared DetectionOnly regression stack and XFF On-mode probes are unchanged.

## Run locally

From the repo root:

```bash
mkdir -p tests/logs/apache tests/logs/nginx && chmod -R 777 tests/logs
rm -rf tests/integration/.plugins-staged
mkdir -p tests/integration/.plugins-staged
cp plugins/* tests/integration/ci-plugin/* tests/integration/.plugins-staged/
printf '%s\n' \
  'Include /etc/modsecurity.d/owasp-crs/plugins/wordpress-hardening-ip.conf' \
  > tests/integration/.plugins-staged/aaa-ci-ip-before.conf
mv tests/integration/.plugins-staged/wordpress-hardening-ratelimit.conf \
  tests/integration/.plugins-staged/wordpress-hardening-ratelimit-before.conf

CRS_TAG=4.26.0-apache-202605200705 \
CRS_TAG_NGINX=4.26.0-nginx-202605200705 \
  docker compose -f tests/integration/docker-compose.yml up -d

# go-ftw v2 (https://github.com/coreruleset/go-ftw)
ftw run -d tests/regression --config tests/integration/.ftw.yml          # apache:8001
# for nginx, retarget port->8002 + logfile->nginx (the workflow generates
# .ftw.nginx.yml with the libmodsecurity3-specific ignores appended).

docker compose -f tests/integration/docker-compose.yml down -t 0
```

CI runs two **mandatory** jobs with different roles, because the two engines
differ in determinism:

- `.github/workflows/apache-modsecurity2.yml` — **Apache + ModSecurity v2** —
  the blocking **functional** gate. mod_security2 is deterministic, so it runs
  the full go-ftw regression suite (`tests/regression/`) on every rule.
- `.github/workflows/nginx-libmodsecurity3.yml` — **nginx + libmodsecurity3** —
  the **parse/load** gate on the *production* engine. It starts the official v3
  image with our rules (a rule that is malformed on v3 fails to load and the
  container never serves → job fails) and runs a tiny deterministic smoke check
  (`GET /wp-json/` must trip 9522207; homepage stays clean).

> **Why nginx is parse/load, not full regression.** libmodsecurity3 v3 has an
> upstream transaction-handling non-determinism that intermittently drops a
> random rule for one request per run (~10–15 % of full-suite runs, raised by
> host load). It is **not** a plugin bug — the byte-identical rules run green
> and deterministic on Apache + mod_security2. It is not the persistent
> collection either (disabling the rate-limiter did not help) nor request
> spacing (a go-ftw `--rate-limit` made it worse). Gating a *mandatory* check
> on a flaky engine would force retry hacks or spurious red, so functional
> behaviour is gated on Apache and v3 loadability is gated here — both
> deterministic, both first-run.

## Optional IP selection

`python3 -m ci.check_optional_ip apache` and the equivalent `nginx` command
start disposable stacks with base-only, unset/default-on, explicitly enabled,
and disabled configurations. They assert state absence, private exemptions,
reputation, and ordinary endpoint protection. Apache also verifies that the
login limiter shares identity across client ports and separates different clients.
The separate `check_xff_trust.py` lane explicitly includes the IP file and retains
the full parser, malformed-header, trust, and reputation corpus on both engines.

## Security corpus

`.github/workflows/security-corpus.yml` runs an adversarial corpus
(`tests/security/`) on **Apache + ModSecurity v2** (deterministic, mandatory):

- **`bypass-evasion.yaml`** — attacks obfuscated with case / path-normalisation
  / encoding / header casing that **must still be blocked** (guards against
  bypassable rules; includes the regression for the `t:lowercase` GeoIP fix).
- **`false-positives.yaml`** — legitimate WordPress traffic (homepage,
  admin-ajax, wp-cron, REST sub-paths, assets, whitelisted login) that must
  not trip any blocking `9522xxx` rule. Six sensitive-path cases require the
  passive BREACH audit marker `9522121` and reject every other `9522xxx` ID.

Apache only, for the same reason the nginx job is parse/load only: the corpus
needs a deterministic pass/fail and libmodsecurity3 v3 cannot provide one. The
corpus rules are byte-identical across engines, so a real bypass/over-block is
caught here regardless of engine.

> **GeoIP tests + private client IPs.** The GeoIP block intentionally exempts
> private RFC-1918 clients. The CI containers talk from a docker-bridge IP, so
> GeoIP block tests send a public `X-Forwarded-For` (the realistic
> "client behind a proxy" case) — otherwise the exemption would mask the block.

## Files

- `docker-compose.yml` — the stack: official CRS images + stub backend, plugin
  mounts, `MODSEC_*` env.
- `ci-plugin/` — CI-only plugin files mounted into the CRS plugins dir
  (feature gates + PL bump). **Never shipped to production.**
- `backend/nginx.conf` — stub origin returning 200 on every path.
- `.ftw.yml` — committed go-ftw config (Apache @ :8001 + pre-existing ignores).
  The nginx/corpus workflows generate `.ftw.nginx.yml` / `.ftw.corpus.yml` from
  it (gitignored).
