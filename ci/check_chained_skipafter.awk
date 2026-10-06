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
  sub(/"[[:space:]]*$/, "", text)
  return text
}

function action_matches(token, name) {
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", token)
  if (name == "chain") return token == "chain"
  return token ~ /^skipAfter:[A-Za-z0-9_]+$/
}

# Commas inside single-quoted action values are data, not action separators.
function has_action(actions, name,    i, c, quote, token) {
  token = ""
  quote = 0
  for (i = 1; i <= length(actions); i++) {
    c = substr(actions, i, 1)
    if (c == "\\") {
      token = token c substr(actions, ++i, 1)
    } else if (c == "'") {
      quote = !quote
      token = token c
    } else if (c == "," && !quote) {
      if (action_matches(token, name)) return 1
      token = ""
    } else {
      token = token c
    }
  }
  return !quote && action_matches(token, name)
}

function finish_rule(    actions) {
  actions = rule_actions(rule)
  if (inner && has_action(actions, "skipAfter")) {
    print FILENAME ":" start_line ": chained skipAfter (move it to the chain starter)"
    bad = 1
  }
  inchain = has_action(actions, "chain")
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
