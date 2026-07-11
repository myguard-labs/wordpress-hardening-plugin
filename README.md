# Wordpress-hardening-plugin / modsecurity (CRS4.0+)
![Integration tests](https://github.com/myguard-labs/wordpress-hardening-plugin/actions/workflows/integration.yml/badge.svg) ![Lint](https://github.com/myguard-labs/wordpress-hardening-plugin/actions/workflows/lint.yml/badge.svg) ![Apache + ModSecurity v2](https://github.com/myguard-labs/wordpress-hardening-plugin/actions/workflows/apache-modsecurity2.yml/badge.svg) ![nginx + libmodsecurity3](https://github.com/myguard-labs/wordpress-hardening-plugin/actions/workflows/nginx-libmodsecurity3.yml/badge.svg) ![WAF security corpus](https://github.com/myguard-labs/wordpress-hardening-plugin/actions/workflows/security-corpus.yml/badge.svg)

![Defense-in-depth: the wordpress-hardening-plugin WAF blocks most XSS and SQL injection attacks at the edge before PHP loads, backed by php-snuffleupagus, a hardened Docker container and disciplined patching](https://deb.myguard.nl/wp-content/uploads/2026/06/wordpress-hardening-plugin-defense-in-depth.webp)

This plugin contains extra rules to enhance the security of wordpress installations with the OWASP Core Rule Set.
It's encouraged to install the wordpress-exclusions-rules-plugin as well, as we only add extra blocks in this plugin.

📖 **Full guide & deep-dive (every rule explained):** [WordPress Hardening Plugin for ModSecurity CRS — Block XSS & SQLi at the WAF](https://deb.myguard.nl/2026/06/wordpress-hardening-plugin-modsecurity-crs-block-attacks/) on deb.myguard.nl. Covers the AI-discovered vulnerability wave, the typed-parameter SQLi/XSS rules, and the defense-in-depth stack (updates · [php-snuffleupagus](https://deb.myguard.nl/2026/05/php-snuffleupagus-tutorial-harden-php-fpm/) · [web-server hardening](https://deb.myguard.nl/2026/05/how-to-install-modsecurity-owasp-crs-nginx/) · [Docker hardening](https://deb.myguard.nl/2026/05/docker-hardening-rootless-readonly-distroless/)).

The idea is to enhance the security of WordPress while minimizing the impact on PHP/SQL performance and eliminating the need for additional wordpress security plugins without interfering with wordpress or owasp.

What this plugin does so far:
- Block xmlrpc.php access (configurable, default: block) (PL1)
- Block user enumeration (configurable, default: block) (PL1)
- Block user "admin" logins (configurable, default: block) (PL1)
- Block the wp-json restapi (configurable, default: non-block) (PL1)
- Block wp-cron.php (configurable, default: non-block) (PL1)
- Block directory listing in /wp-content/* and /wp-includes/* (PL1)
- Block direct php access in /wp-content/* and /wp-includes/* (PL1)
- Block direct file access to some files in / and other files/directories (PL1)
- Block other interpreters like .pl/.lua/.py/.sh (PL2)
- Block nasty files in uploads/* (PL1)
- Block access to sensitive files like .db/.orig/.sql/.log/.git (PL1)
- Block access to "/wp-json" (exact match, the api still works) (PL1)
- Block wp-admin theme/plugin editor access (configurable, default: block) (PL1)
- Block backup directory and archive file access (configurable, default: block) (PL1)
- Block compressed database dump access (.sql.gz/.sql.bz2/.sql.zip) (configurable, default: block) (PL1)
- Block directory traversal attempts in /wp-content/uploads/ (configurable, default: block) (PL1)
- Block null byte injection in URIs and parameters (configurable, default: block) (PL2)
- Block known security scanner user agents like nikto, sqlmap, wpscan (configurable, default: non-block) (PL2). **SEO note:** the bundled UA list also includes third-party SEO crawlers (Ahrefs, Semrush, Majestic/MJ12, Moz/dotbot/rogerbot, Petal, etc.). Enabling this toggle hides your site from those services. Search-engine bots (Googlebot, Bingbot) and social previews (Twitterbot, LinkedInBot, facebookexternalhit/1.1) are NOT in the list and continue to work.
- Block XDebug and phpinfo debug probe parameters (configurable, default: block) (PL1)
- Block code injection patterns in wp-login.php POST parameters (configurable, default: block) (PL1)
- Block dangerous wp-admin endpoints — upgrade.php, wp-activate.php (configurable, default: block) (PL2)
- IP-based rate limiting for wp-login.php (configurable, default: 5 attempts per 60 seconds, replies with HTTP 429 per RFC 6585) (PL1)
- GeoIP-based access control for wp-login.php (configurable, default: disabled) (PL1)
- Automatic IP reputation blocklist blocking all requests from listed IPs/CIDRs (configurable, default: disabled) (PL1)
- Trusted-proxy pinning for X-Forwarded-For (configurable, default: disabled — backward compatible) (PL1)
- IPv6-aware client-IP resolution and private-network whitelisting (loopback + RFC 1918 + IPv6 `::1` + ULA `fc00::/7`)
- Detect version-disclosure response headers — X-Pingback, X-Powered-By, REST Link rel=api.w.org. Real stripping must be at the proxy: `proxy_hide_header X-Pingback; proxy_hide_header X-Powered-By; more_clear_headers "Link";` (configurable, default: tag) (PL1)
- Hard-block info-leak paths in phase:1 — readme.html, license.txt, .user.ini, wp-admin/install.php, wp-admin/setup-config.php, wp-includes/wlwmanifest.xml, wp-content/debug.log (configurable, default: block) (PL1)
- Block CVE-2018-6389 DoS — long `?load=` on wp-admin/load-scripts.php and load-styles.php (configurable, default: block) (PL1)
- Block VCS / dotfile probes — .env, .git/, .svn/, .hg/, .bzr/, .htpasswd, .DS_Store (configurable, default: block) (PL1)
- Block wp-config backup variants — .save, .old, .new, .dist, .sample, .copy, ~, numeric .1/.2 (configurable, default: block) (PL1)
- Block plugin/theme readme.txt version-disclosure probes (configurable, default: non-block — wp-cli reads these) (PL2)
- Block PHP stream wrappers in args — php://, data://, expect://, file://, phar://, glob://, zip://, compress.zlib://, compress.bzip2:// (configurable, default: block) (PL1)
- Block known-CVE plugin signatures — SureTriggers/OttoKit (CVE-2025-3102, CVE-2025-27007), Bricks Builder (CVE-2024-25600) (configurable, default: block) (PL1)
- Block uncommon HTTP methods on /wp-admin/, /wp-login.php, /xmlrpc.php, /wp-cron.php — TRACE/TRACK/DEBUG/PROPFIND/MKCOL/COPY/MOVE/LOCK/UNLOCK/PUT/DELETE/PATCH (configurable, default: block) (PL1)
- Block legacy CVE scanner probes — revslider, timthumb, WP Symposium, MailPoet wysija_captcha, wp-file-manager, Duplicator installer (configurable, default: block) (PL1)
- BREACH/CRIME compression side-channel detection — tag requests to /wp-admin/, /wp-login.php, /wp-json/* (configurable, default: tag). Real stripping must be configured at the proxy: `proxy_set_header Accept-Encoding "";` + `gzip off;` + `brotli off;` on those locations. (PL1)
- Block public /author/<slug>/ archive pages (configurable, default: non-block — most blogs expose these) (PL2)
- Block ORDER BY injection — `order=` must be `asc`/`desc`, `orderby=` must be a bare column name with no SQL metacharacters/keywords (configurable, default: block) (PL1; PL2 adds a strict column-name allowlist). The #1 WordPress plugin SQLi class; a typed allowlist is strictly stronger than libinjection, which has documented ORDER BY bypasses.
- Block SQLi / reflected-XSS in WP-core numeric query-vars — `p`, `page_id`, `attachment_id`, `m`, `w`, `year`, `monthnum`, `day`, `hour`, `minute`, `paged`, `cpage` must be integer (configurable, default: block — zero false-positive; `cat`/`author` excluded as they accept comma/negative lists) (PL1)
- Block non-integer values in generic plugin id params — `id`, `post_id`, `user_id`, `term_id`, `parent_id`, `comment_id` (configurable, default: **non-block** — these names are generic; only enforced at PL2 when enabled) (PL2)

> **Why these were added:** CRS already runs libinjection (`@detectSQLi`/`@detectXSS`) on all arguments at PL1. The rules above do **not** duplicate that — they add the *semantic/typed* parameter validation CRS lacks, which is exactly where the 2025–2026 wave of (often AI-discovered) WordPress plugin SQLi/XSS CVEs slips through.

## IP Whitelisting

The blocked endpoints (`xmlrpc.php`, `wp-json`, `wp-cron.php`), the rate-limit counter, the GeoIP login gate, and the IP-reputation blocklist all share a **single** client-IP resolver and a **single** "is-this-a-private-IP?" decision, so the same identity is used everywhere.

Whitelisted by default:

- `127.0.0.0/8` (IPv4 loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (IPv4 RFC 1918)
- `::1` (IPv6 loopback)
- `fc00::/7` (IPv6 Unique Local addresses, RFC 4193)

This allows internal systems (cron jobs, monitoring, load balancers) to access these endpoints while blocking external attacks.

### Client-IP resolution

`tx.wphard.client_ip` is built in phase 1 as follows:

1. Default to `REMOTE_ADDR` (the directly-connected peer).
2. If `X-Forwarded-For` is present **and trusted** (see [Trusted-Proxy Pinning](#trusted-proxy-pinning) below), take the leftmost hop. IPv4 and IPv6 first hops are both recognised; malformed values like `1.2.3.4junk` are rejected.

### Trusted-Proxy Pinning

By default the plugin honours `X-Forwarded-For` unconditionally — this is backward compatible and correct for any deployment behind a single trusted proxy (Cloudflare, nginx with `set_real_ip_from`, HAProxy). On a server with direct internet exposure, an attacker can otherwise spoof `X-Forwarded-For` and bypass the private-IP whitelist or rotate the rate-limit key.

To eliminate that footgun:

1. Populate `plugins/wordpress-hardening-trusted-proxies.data` with the public CIDRs of your real upstream proxies (one per line).
2. Enable pinning in `plugins/wordpress-hardening-config.conf`:
   ```bash
   SecAction "id:9522055,phase:1,nolog,pass,t:none,setvar:'tx.wphard.trusted_proxies_enabled=1'"
   ```

When enabled, `X-Forwarded-For` is honoured **only** if `REMOTE_ADDR` is in that list; otherwise the resolver falls back to `REMOTE_ADDR`.

> **Scope:** the private-IP whitelist only applies to the xmlrpc / wp-json / wp-cron rules (`9522102`, `9522107`, `9522111`, `9522207`). The user-enumeration rule (`9522104`), the direct-PHP-access rule (`9522200`), sensitive-files (`9522202`/`9522206`), info-leak (`9522100`), VCS-dotfile (`9522113`), and the audit-round-4 protections (`9522112`-`9522122`, `9522701`-`9522703`) apply to **all** clients regardless of source IP — they are flagging request shapes that no legitimate caller (internal or external) produces.

## Configuration

All features are **enabled by default** with sensible defaults. To override defaults or disable specific protections, uncomment the corresponding `SecAction` line in `plugins/wordpress-hardening-config.conf`.

**Important note on `block_admin_login`**: This rule blocks login attempts that use the **literal username "admin"** — it does NOT block all administrator accounts. Only WordPress installations with a user named exactly "admin" will be affected.

## IP-Based Rate Limiting (opt-in, Apache/mod_security2 only)

The plugin ships IP-based rate limiting for `wp-login.php` to prevent brute
force attacks — in the **separate, opt-in file
`plugins/wordpress-hardening-ratelimit.conf`**. It is *not* loaded by the
standard CRS plugin loader (which only picks up `*-config.conf`,
`*-before.conf` and `*-after.conf`); to enable it, add an explicit
`Include` for the file *after* the plugin before-file:

```apache
Include /path/to/plugins/wordpress-hardening-ratelimit.conf
```

**How it works:**
- Tracks all POST requests to `/wp-login.php` per resolved client IP
- Locks out an IP after exceeding the attempt threshold
- Whitelist prevents rate limiting for trusted IPs (loopback + private ranges, IPv4 and IPv6)
- Blocks return **HTTP 429 Too Many Requests** (RFC 6585 §4) and export `wphard_retry_after` as an env var so the webserver can add a `Retry-After` header to the response

> **⚠️ Engine support:** rate limiting relies on persistent collections
> (`initcol:ip=...` + `IP:` variables). This works reliably on **Apache +
> mod_security2 (v2.x)** only. **libmodsecurity3 (the engine used by nginx /
> Angie)** has long-standing gaps in its persistent-collection
> implementation — the counter often never persists across requests and
> the rate-limit never triggers, even when the rule itself parses and
> loads correctly. **Coraza v3 has no persistent collections at all** and
> rejects these constructs at config load — which is why the rules live in
> a separate file: loading `wordpress-hardening-ratelimit.conf` on Coraza
> is a fatal error. On libmodsec3 or Coraza, prefer your webserver's
> native rate-limiter (e.g. nginx/Angie's `limit_req zone=...`) or
> fail2ban for `/wp-login.php`.

> **⚠️ Collection growth (DoS):** `initcol:ip=%{client_ip}` creates one
> SDBM entry per resolved IP under `SecDataDir`. The plugin does NOT set
> `SecCollectionTimeout` (the CRS plugin convention says only operators
> may set it). On a server with direct internet exposure — i.e. where
> trusted-proxy pinning is OFF — an attacker rotating source IPs (easy
> over IPv6) can grow the collection file unboundedly. Operators MUST:
>
> 1. Set `SecCollectionTimeout 300` (or higher) in the engine config.
> 2. Place `SecDataDir` on a partition that can absorb growth or has a
>    housekeeping cron.
> 3. Enable [Trusted-Proxy Pinning](#trusted-proxy-pinning) on direct-
>    exposure servers so the counter keys on a vetted upstream.

**Default settings:**
- **Enabled by default** (`ratelimit_login_enabled`)
- **5 login attempts** per IP (`ratelimit_login_attempts`)
- **60 second window** (`ratelimit_login_window`)
- **Whitelisted IPs**: see [IP Whitelisting](#ip-whitelisting) above

**Customization:**

Uncomment these in `plugins/wordpress-hardening-config.conf` to override defaults:

```bash
# Reduce to 3 attempts (window remains 60s)
#SecAction "id:9522049,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_attempts=3"

# Change the window (allowed values: 30, 60, 120, 300, 600 — any other value
# silently falls back to 60s)
#SecAction "id:9522050,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_window=300"

# Disable rate limiting entirely
#SecAction "id:9522048,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_enabled=0"
```

> **Note on the window:** `expirevar` in ModSecurity does not accept macro
> expansion in its TTL, so the plugin dispatches the configured window through
> five literal `expirevar` rules (rule IDs `9522416`-`9522420`) covering 30, 60,
> 120, 300, and 600 seconds. Any other value falls back to 60s.

### `Retry-After` response header (optional)

Rule `9522412` calls `setenv:wphard_retry_after=<seconds>` whenever it blocks
with 429. To expose that as an HTTP response header, add the following to your
webserver config:

**nginx / Angie:**
```nginx
add_header Retry-After $wphard_retry_after always;
```

**Apache (with mod_security2):**
```apache
Header always set Retry-After "%{wphard_retry_after}e" env=wphard_retry_after
```

## GeoIP-Based Access Control for wp-login.php

Blocks access to `wp-login.php` for clients from countries not in the allowed list. No GeoIP database is required on the WAF — the upstream proxy sets a standard header and ModSecurity reads it.

**How it works:**
- Upstream proxy (Cloudflare, nginx + ngx_http_geoip2_module, HAProxy, etc.) sets `CF-IPCountry` or `X-GeoIP-Country` with the client's 2-letter ISO 3166-1 country code
- Requests without a recognized country header are **allowed through** (fail-open)
- Loopback and private ranges (IPv4 RFC 1918 + IPv6 `::1` and ULA `fc00::/7`) are always whitelisted
- Allowed countries are listed one per line in `plugins/wordpress-hardening-login-countries.data`

**Default settings:**
- **Disabled by default** (`geoip_login_enabled=0`)

> **Security note:** The country header is trusted unconditionally. Only enable this feature behind a proxy that sets and strips client-supplied values for these headers.

**To enable:**
1. Uncomment the SecAction in `plugins/wordpress-hardening-config.conf`:
   ```bash
   SecAction "id:9522902,phase:1,nolog,pass,t:none,setvar:'tx.wphard.geoip_login_enabled=1'"
   ```
2. Populate `plugins/wordpress-hardening-login-countries.data` with the ISO codes of countries you want to allow (**lowercase, one per line**):
   ```
   nl
   de
   gb
   ```

   > **⚠️ Case matters.** The country header is normalised to lowercase before lookup, and `@pmFromFile` is case-sensitive. Adding `NL` (uppercase) means the allow-list never matches and every login is blocked.

## IP Reputation Blocklist

Blocks **all requests** (not just login attempts) from IP addresses listed in `plugins/wordpress-hardening-ip-reputation.data`. Supports individual IPs and CIDR ranges. No external API or database required — the blocklist is a plain text file you populate from threat intelligence feeds or your own data.

**How it works:**
- Uses the shared resolved client IP (`tx.wphard.client_ip`) — see [Client-IP resolution](#client-ip-resolution) above
- Uses ModSecurity's `@ipMatchFromFile` operator — supports IPv4, IPv6, and CIDR notation
- Loopback and private ranges (IPv4 RFC 1918 + IPv6 `::1` and ULA `fc00::/7`) are always whitelisted
- Applies globally (all URIs, not just `wp-login.php`)

**Default settings:**
- **Disabled by default** (`ip_reputation_enabled=0`)
- Data file ships with `192.0.2.0/24` (RFC 5737 documentation range used for CI tests) — replace with real entries in production

> **Security note:** `X-Forwarded-For` is trusted by default. For deployments without a proxy in front, enable [trusted-proxy pinning](#trusted-proxy-pinning) before turning this feature on, or attackers can rotate XFF to evade the blocklist.

**To enable:**
1. Uncomment the SecAction in `plugins/wordpress-hardening-config.conf`:
   ```bash
   SecAction "id:9522903,phase:1,nolog,pass,t:none,setvar:'tx.wphard.ip_reputation_enabled=1'"
   ```
2. Populate `plugins/wordpress-hardening-ip-reputation.data` with known bad IPs and CIDRs (one per line):
   ```
   198.51.100.0/24
   203.0.113.5
   2001:db8::/32
   ```

**Recommended threat intelligence sources:**
- [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) — Don't Route Or Peer list
- [Emerging Threats](https://rules.emergingthreats.net/fwrules/) — compromised host blocklists
- [Firehol Level 1](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset) — aggregated reputation feed

## Rule ID Map

The plugin uses the allocated range **9522000-9522999**. Major buckets:

| Range | Purpose |
|---|---|
| `9522010`-`9522055` | Config-knob `SecAction`s (commented examples in `config.conf`) |
| `9522012`-`9522050` | Default-value setters (in `before.conf`, IPv6/proxy series) |
| `9522071`-`9522081` | Default-value setters (in `before.conf`, audit-round-4 protections) |
| `9522060`-`9522065` | Client-IP resolver (`REMOTE_ADDR`, XFF v4/v6, trusted-proxy gate, `client_is_private`) |
| `9522099` | Plugin kill-switch (removes 9522000-9522998) |
| `9522101`-`9522111` | xmlrpc / user-enumeration / REST API / admin-login / wp-cron blocks |
| `9522150`-`9522155` | Per-group whitelist (uses `client_is_private`) |
| `9522199`-`9522207` | Static-asset fast path, direct-PHP guard, files.data, uploads, sensitive files |
| `9522300`-`9522320` | Editor / backup / DB / upload-traversal / null-byte / scanner / debug / login-injection / dangerous-admin |
| `9522400`-`9522420` | Rate-limit gate, counter, window dispatcher, 429 block |
| `9522500`-`9522510` | GeoIP header extraction + login gate |
| `9522600`-`9522604` | IP reputation gate, whitelist, block |

## Future Features (Raincheck list)

These features are planned but not yet implemented:
- IP-based rate limiting for other endpoints (wp-admin, xmlrpc, etc.)
- Native `Retry-After` header injection (today requires a one-line webserver snippet — see [Rate Limiting](#ip-based-rate-limiting))

## Requirements
- CRS Version 4.0 or newer
- ModSecurity compatible Web Application Firewall

## How to install the plugin

Please see https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin

## Disabling the plugin
The plugin can be disabled by uncommenting rule 9522010 inside ``plugins/wordpress-config.conf`` or by removing the includes for this plugin.

## Known false-positive patterns

Production traffic on `deb.myguard.nl` was audited on 2026-05-22; only the cases below have ever fired the hardening rules on legitimate requests. Everything else (138× `9522202`, 66× `9522206`, 24× `9522200`, 3× `9522104` over the recent window) was confirmed scanner / probe traffic. The same audit flagged 93× `959100` outbound blocks on tutorial post permalinks (driven by `953100`); this is now fixed in-plugin by rule `9522801` (see the FP table below).

| Rule | Trigger | Why it's a FP | Mitigation |
| ---- | ------- | ------------- | ---------- |
| `9522104` | `GET /wp-json/wp/v2/users/me` (with or without `?context=edit&_locale=user`) | The block editor and `/wp-admin/` UI call `/users/me` on every page load to get the current user. It returns ONLY the authenticated user — it's not enumeration. | Tighten the regex to `(?:[/?&]author=[0-9]+)\|(?:/wp/v2/users/?(?:\?\|$))\|(?:/wp/v2/users/[0-9]+)` so `/users/me` and other non-numeric subroutes pass through. Numeric-ID lookups (`/users/42`) and the bare collection still block. |
| `9522104` | Internal / loopback admin tooling | The xmlrpc / rest-api / wpcron rules already skip private-IP clients (`tx.wphard.client_is_private`); `9522104` does not. | Mirror the existing skip pattern (`SecRule TX:wphard.client_is_private "@eq 1" ... skipAfter:END_WPHARD_USER_ENUMERATION`) before `BEGIN_WPHARD_USER_ENUMERATION`. |
| CRS `950140` (not this plugin, but commonly co-deployed) | Outbound block of blog posts containing `#!/...` shell snippets | CRS treats shebangs in the response body as "CGI source code leakage". Tutorial blogs that publish shell commands hit this on every post view. | Disable `950140` for the affected vhost via a host-scoped exclusion plugin (`SecRule REQUEST_HEADERS:Host "@streq <host>" "id:...,phase:1,pass,nolog,ctl:ruleRemoveById=950140"`). Do not disable globally. |
| CRS `953100` / `953110` / `953120` (RESPONSE-953-DATA-LEAKAGES-PHP) — covered in-plugin | Tutorial / dev blog posts containing PHP function names (`$_POST`, `fopen`, `move_uploaded_file`, ...), PHP error strings, or `<?php` opening tags inside `<pre>/<code>` blocks accumulate outbound anomaly score in phase:4, eventually tripping `959100` (BLOCKING_OUTBOUND_ANOMALY_SCORE ≥ 4) and a 302/403 hides the article from readers. | Rule **9522801** (ON by default, tunable `tx.wphard.exclude_response_php_leakage_on_permalinks`) drops 953100/953110/953120 only on front-end permalinks (any path that is NOT `/wp-admin/`, `/wp-login.php`, `/wp-json/`, `/?rest_route=`, `/xmlrpc.php`, `/wp-cron.php`, `/wp-content/`, `/wp-includes/`). Set the tunable to `0` to keep the CRS rules everywhere. |

## Reporting false positives
If you find a false positive that this plugin does not cover then please open a new issue or pull request, if creating an issue then please include the following details:

1. CRS Version
2. ModSecurity/Coraza Version
3. modsec audit logs
4. what caused the false positive
