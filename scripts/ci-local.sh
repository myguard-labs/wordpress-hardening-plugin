#!/usr/bin/env bash
# Run the same checks CI runs, locally. Mirrors:
#   .github/workflows/lint.yml          (validate-files + plugin-lint/check-syntax)
#   .github/workflows/integration.yml   (validate-gates)
# Used by the pre-push git hook (.githooks/pre-push) and runnable by hand.
#
# Exit non-zero if any check fails. Docker images and the optional
# secrules-parsing install may require network access on a cold host.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

FAIL=0
note() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  \xe2\x9c\x93 %s\n' "$1"; }
err()  { printf '  ERROR: %s\n' "$1"; FAIL=1; }

note "PHP PATH_INFO origin behavior"
if bash ci/test_static_pathinfo_origins.sh; then
  ok "Apache and nginx PHP PATH_INFO behavior"
else
  err "PHP PATH_INFO origin behavior failed"
fi

# Publication tests use local Git fixtures and a stubbed GitHub CLI.
note "release publication contract"
if python3 tests/ci/test_release_publication.py; then
  ok "release publication contract"
else
  err "release publication contract failed"
fi

note "sensitive file boundary unit tests"
if python3 ci/check_ftw_positives.py \
    tests/regression/wordpress-hardening-plugin tests/integration/.ftw.yml; then
  ok "go-ftw positive coverage"
else
  if ! python3 -c 'import yaml' 2>/dev/null; then
    err "PyYAML is required for go-ftw positive coverage; install PyYAML==6.0.2 for python3"
  fi
  err "go-ftw positive coverage failed"
fi
if python3 -B -m unittest discover -s ci -p 'test_*.py'; then
  ok "sensitive file boundary unit tests"
else
  err "sensitive file boundary unit tests failed"
fi

# ── lint.yml: @pmFromFile references resolve ────────────────────────────────
note "pmFromFile references"
while read -r line; do
  f=$(printf '%s' "$line" | sed -n 's/.*@pmFromFile \([^ "]*\).*/\1/p')
  [ -n "$f" ] && [ ! -f "plugins/$f" ] && err "referenced file not found: $f"
done < <(grep -rh "@pmFromFile" plugins/*.conf)
[ "$FAIL" -eq 0 ] && ok "all @pmFromFile targets exist"

# ── lint.yml: rule IDs within allocated range ───────────────────────────────
note "rule ID range 9522000-9522999"
RANGE_BAD=0
for id in $(grep -oh 'id:[0-9]*' plugins/*.conf | cut -d: -f2); do
  if [ "$id" -lt 9522000 ] || [ "$id" -gt 9522999 ]; then
    err "rule ID $id outside allocated range"; RANGE_BAD=1
  fi
done
[ "$RANGE_BAD" -eq 0 ] && ok "all rule IDs in range"

# ── lint.yml: no duplicate rule IDs ─────────────────────────────────────────
note "duplicate rule IDs"
DUPES=$(grep -oh 'id:[0-9]*' plugins/*.conf | cut -d: -f2 | sort | uniq -d)
if [ -n "$DUPES" ]; then err "duplicate rule IDs: $DUPES"; else ok "no duplicate rule IDs"; fi

# ── lint.yml: every test file maps to an existing rule ──────────────────────
note "test file -> rule ID mapping"
MAP_BAD=0
for t in tests/regression/wordpress-hardening-plugin/*.yaml; do
  rid=$(basename "$t" .yaml)
  grep -q "id:$rid" plugins/*.conf || { err "$t references missing rule $rid"; MAP_BAD=1; }
done
[ "$MAP_BAD" -eq 0 ] && ok "all test files map to a rule"

# ── plugin-lint / check-syntax: CRS secrules-parsing correctness ────────────
note "ModSecurity syntax (secrules-parsing -c)"
if ! python3 -c "import secrules_parsing" 2>/dev/null; then
  pip install --quiet --user secrules-parsing 2>/dev/null || \
    err "secrules-parsing not installed and pip install failed"
fi
if python3 -c "import secrules_parsing" 2>/dev/null; then
  CLI=$(python3 -c "import os,secrules_parsing; print(os.path.join(os.path.dirname(secrules_parsing.__file__),'cli.py'))")
  OUT=$(python3 "$CLI" -c -f plugins/*.conf 2>&1)
  printf '%s\n' "$OUT" | sed 's/^/  /'
  # The tool exits 0 even on errors; it reports "Syntax invalid" on failure.
  printf '%s' "$OUT" | grep -qi 'invalid' && err "secrules-parsing reported invalid syntax"
  [ "$FAIL" -eq 0 ] && ok "secrules-parsing: all files OK"
fi

# ── integration.yml: skipAfter only on chain-starter rules ──────────────────
note "no skipAfter on chained (inner) rules  [AH00526 guard]"
if ! awk '
  /^[ \t]+SecRule/ { inrule = 1 }
  inrule && /skipAfter/ { print "  -> " FILENAME ":" FNR; bad = 1 }
  inrule && !/\\[ \t]*$/ { inrule = 0 }
  END { exit bad ? 1 : 0 }' plugins/*.conf; then
  err "skipAfter on a chained rule (move it to the chain starter)"
else
  ok "no chained rule carries skipAfter"
fi

# ── skipAfter targets resolve to a SecMarker ────────────────────────────────
note "skipAfter targets resolve to a SecMarker"
SA_MISS=0
for label in $(grep -ohE 'skipAfter:[A-Za-z0-9_]+' plugins/*.conf | cut -d: -f2 | sort -u); do
  grep -qE "SecMarker \"?${label}\"?" plugins/*.conf || { err "skipAfter:${label} has no matching SecMarker"; SA_MISS=1; }
done
[ "$SA_MISS" -eq 0 ] && ok "all skipAfter targets resolve"

# ── file-extension regexes use an escaped dot  [9522203 class] ──────────────
note "extension regexes use an escaped dot"
if grep -nE '@rx [^"]*[^\\]\((pl|cgi|py|sh|lua|aspx?|php|html?|sql)[^)]*\)[^"]*\$' plugins/*.conf \
     | grep -vE '\\\.\((pl|cgi|py|sh|lua|aspx?|php|html?|sql)'; then
  err "extension alternation not preceded by an escaped dot (\\.)"
else
  ok "extension regexes properly anchored"
fi

# ── Markers well-formed and reachable ───────────────────────────────────────
# Two valid marker shapes:
#   1. Feature gate: a BEGIN_X / END_X pair (END must have a BEGIN).
#   2. Skip target:  an END_X (or bare label) with NO BEGIN, used purely as a
#      skipAfter jump destination (e.g. PL gates, the static fast-path).
# Either way EVERY marker must be targeted by at least one skipAfter, else it
# is dead code; and a BEGIN_X must always have its END_X.
note "markers well-formed and reachable"
GP_BAD=0
for end in $(grep -ohE 'SecMarker "END_[A-Z0-9_]+"' plugins/*.conf | sed 's/SecMarker "//;s/"//'); do
  begin="BEGIN_${end#END_}"
  if grep -qE "SecMarker \"${begin}\"" plugins/*.conf; then
    : # paired feature gate — fine
  else
    # skip-only target: allowed, but it MUST be jumped to by a skipAfter
    grep -qE "skipAfter:${end}\b" plugins/*.conf || { err "${end} has no BEGIN_ and no skipAfter targets it (dead marker)"; GP_BAD=1; }
  fi
  grep -qE "skipAfter:${end}\b" plugins/*.conf || { err "${end} never targeted by a skipAfter (dead gate)"; GP_BAD=1; }
done
for begin in $(grep -ohE 'SecMarker "BEGIN_[A-Z0-9_]+"' plugins/*.conf | sed 's/SecMarker "//;s/"//'); do
  end="END_${begin#BEGIN_}"
  grep -qE "SecMarker \"${end}\"" plugins/*.conf || { err "${begin} has no matching ${end}"; GP_BAD=1; }
done
[ "$GP_BAD" -eq 0 ] && ok "all markers well-formed and reachable"

# ── integration.yml: gate markers enclose their blocking rules ──────────────
note "gate marker coverage"
gate_check() { # marker  ruleid
  if grep -q "$1" plugins/*.conf && grep -A 50 "$1" plugins/*.conf | grep -q "id:$2"; then
    ok "$2 within $1"
  else
    err "$2 not enclosed by $1"
  fi
}
gate_check BEGIN_WPHARD_BLOCK_REST_API_ROOT 9522207
gate_check BEGIN_WPHARD_BLOCK_EDITOR_ACCESS  9522301
gate_check BEGIN_WPHARD_BLOCK_BACKUP_FILES   9522303
gate_check BEGIN_WPHARD_BLOCK_DB_FILES       9522305
gate_check BEGIN_WPHARD_BLOCK_UPLOAD_TRAVERSAL 9522307
gate_check BEGIN_WPHARD_BLOCK_NULL_BYTES     9522309
gate_check BEGIN_WPHARD_BLOCK_SCANNERS       9522311
gate_check BEGIN_WPHARD_BLOCK_DEBUG_PROBES   9522313
gate_check BEGIN_WPHARD_BLOCK_LOGIN_INJECTION 9522315
gate_check BEGIN_WPHARD_BLOCK_DANGEROUS_ADMIN 9522317
gate_check BEGIN_WPHARD_RATELIMIT_LOGIN      9522411
gate_check BEGIN_WPHARD_GEOIP_LOGIN          9522510
gate_check BEGIN_WPHARD_IP_REPUTATION        9522603

# ── regression YAML well-formed ─────────────────────────────────────────────
note "regression YAML parses"
if python3 -c "import yaml,glob,sys
[yaml.safe_load(open(f)) for f in glob.glob('tests/regression/wordpress-hardening-plugin/*.yaml')]" 2>/tmp/yamlerr; then
  ok "all regression YAML valid"
else
  err "invalid regression YAML: $(cat /tmp/yamlerr)"
fi

printf '\n'
if [ "$FAIL" -ne 0 ]; then
  printf 'CI-local: FAILED\n'
  exit 1
fi
printf 'CI-local: all checks passed\n'
