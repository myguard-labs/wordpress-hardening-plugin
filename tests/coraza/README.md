# Coraza v3 compatibility gate

`main.go` loads ruleset files into `coraza.NewWAF()` and exits 1 on any
load failure; `-tx tests.json` replays JSON-defined transactions and asserts
which rule IDs fire. Run from `plugins/` so relative `@pmFromFile` /
`@ipMatchFromFile` paths resolve:

    cd plugins && go run ../tests/coraza *.conf

Driven by `.github/workflows/coraza.yml`. Vendored copy of the
waf-rulesets coraza-compat-probe — keep the pinned coraza version in
`go.mod` in sync across the CRS plugin repos when bumping.
