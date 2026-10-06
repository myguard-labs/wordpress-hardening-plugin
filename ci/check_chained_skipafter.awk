# A chain action makes the next SecRule an inner rule, regardless of indentation.
# Join continued lines before checking actions, so flush-left multiline rules
# receive the same check as indented and single-line rules.
function rule_actions(text,    i, quoted) {
  sub(/^[[:space:]]*SecRule[[:space:]]+[^[:space:]]+[[:space:]]*/, "", text)
  gsub(/\\[[:space:]]+/, " ", text)
  sub(/^[[:space:]]*/, "", text)
  if (substr(text, 1, 1) == "\"") {
    quoted = 0
    for (i = 2; i <= length(text); i++) {
      if (substr(text, i, 1) == "\\") {
        i++
      } else if (substr(text, i, 1) == "\"") {
        quoted = 1
        break
      }
    }
    if (!quoted) return ""
    text = substr(text, i + 1)
  } else {
    sub(/^[^[:space:]]+/, "", text)
  }
  sub(/^[[:space:]]*/, "", text)
  sub(/^"/, "", text)
  return text
}

function finish_rule(    actions) {
  actions = rule_actions(rule)
  if (inner && actions ~ /skipAfter:[A-Za-z0-9_]+/) {
    print FILENAME ":" start_line ": chained skipAfter (move it to the chain starter)"
    bad = 1
  }
  inchain = (actions ~ /(^|[,[:space:]])chain([,[:space:]"\\]|$)/)
  inrule = 0
}

FNR == 1 { inchain = 0; inrule = 0 }

/^[[:space:]]*SecRule[[:space:]]/ {
  inner = inchain
  inchain = 0
  inrule = 1
  start_line = FNR
  rule = $0
  if ($0 !~ /\\[[:space:]]*$/) finish_rule()
  next
}

inrule {
  rule = rule " " $0
  if ($0 !~ /\\[[:space:]]*$/) finish_rule()
  next
}

/^[[:space:]]*($|#)/ { next }
{ inchain = 0 }

END { exit bad ? 1 : 0 }
