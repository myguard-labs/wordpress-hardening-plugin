# Coraza v3 compatibility gate

`main.go` loads ruleset files into `coraza.NewWAF()` and exits 1 on any
load failure; `-tx tests.json` replays JSON-defined transactions and asserts
which rule IDs fire. Run from `plugins/` so relative `@pmFromFile` /
`@ipMatchFromFile` paths resolve:

    cd plugins
    go run ../tests/coraza wordpress-hardening-config.conf \
      wordpress-hardening-ip.conf wordpress-hardening-before.conf \
      wordpress-hardening-after.conf

Omit `wordpress-hardening-ip.conf` for the base ruleset. Keep operator overrides
after config and before the optional IP include. Never use `*.conf`: it also
loads the separate persistent rate-limit rules, which Coraza cannot support.

The workflow builds the probe and runs `python3 -m ci.check_optional_ip coraza --probe
/path/to/coraza-probe` for base-only, unset/default-on, enabled, and disabled
behavior. It also runs the full opt-in XFF corpus through `ci/check_xff_trust.py`.

Driven by `.github/workflows/coraza.yml`. Vendored copy of the
waf-rulesets coraza-compat-probe — keep the pinned coraza version in
`go.mod` in sync across the CRS plugin repos when bumping.
