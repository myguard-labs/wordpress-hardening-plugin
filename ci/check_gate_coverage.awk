# Check the required rule IDs between their matching feature-gate markers.
# Run over all plugin .conf files at once so duplicate IDs/markers are caught.
BEGIN {
    required[9522207] = "WPHARD_BLOCK_REST_API_ROOT"
    required[9522301] = "WPHARD_BLOCK_EDITOR_ACCESS"
    required[9522303] = "WPHARD_BLOCK_BACKUP_FILES"
    required[9522305] = "WPHARD_BLOCK_DB_FILES"
    required[9522307] = "WPHARD_BLOCK_UPLOAD_TRAVERSAL"
    required[9522309] = "WPHARD_BLOCK_NULL_BYTES"
    required[9522311] = "WPHARD_BLOCK_SCANNERS"
    required[9522313] = "WPHARD_BLOCK_DEBUG_PROBES"
    required[9522315] = "WPHARD_BLOCK_LOGIN_INJECTION"
    required[9522317] = "WPHARD_BLOCK_DANGEROUS_ADMIN"
    required[9522411] = "WPHARD_RATELIMIT_LOGIN"
    required[9522510] = "WPHARD_GEOIP_LOGIN"
    required[9522603] = "WPHARD_IP_REPUTATION"
}

function count_rule_actions(    quoted, actions, fields, count, i, action, id) {
    # The ID must be an action of a SecRule, not a comment or operator pattern.
    if (rule_text !~ /^[[:space:]]*SecRule[[:space:]]+[^[:space:]]+[[:space:]]+"[^"]*"[[:space:]]+"[^"]*"/)
        return
    split(rule_text, quoted, "\"")
    actions = quoted[4]
    count = split(actions, fields, ",")
    for (i = 1; i <= count; i++) {
        action = fields[i]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", action)
        if (action ~ /^id:[0-9]+$/) {
            id = substr(action, 4)
            if (id in required) {
                rule_count[id]++
                rule_file[id] = FILENAME
                rule_line[id] = rule_start
            }
        }
    }
}

/^[[:space:]]*SecMarker "(BEGIN|END)_WPHARD_[A-Z0-9_]+"/ {
    if (match($0, /"(BEGIN|END)_WPHARD_[A-Z0-9_]+"/)) {
        marker = substr($0, RSTART + 1, RLENGTH - 2)
        gate = marker
        sub(/^(BEGIN|END)_/, "", gate)
        for (id in required) {
            if (required[id] == gate) {
                marker_count[marker]++
                marker_file[marker] = FILENAME
                marker_line[marker] = FNR
                break
            }
        }
    }
}

{
    if ($0 ~ /^[[:space:]]*SecRule[[:space:]]+/) {
        rule_text = ""
        rule_start = FNR
        in_rule = 1
    }
    if (in_rule) {
        line = $0
        continued = line ~ /\\[[:space:]]*$/
        if (continued)
            sub(/\\[[:space:]]*$/, " ", line)
        rule_text = rule_text " " line
        if (!continued) {
            count_rule_actions()
            in_rule = 0
        }
    }
}

END {
    failed = 0
    for (id in required) {
        begin = "BEGIN_" required[id]
        end = "END_" required[id]
        if (marker_count[begin] != 1 || marker_count[end] != 1 || rule_count[id] != 1 ||
            marker_file[begin] != marker_file[end] || marker_file[begin] != rule_file[id] ||
            marker_line[begin] >= rule_line[id] || rule_line[id] >= marker_line[end]) {
            printf "ERROR: rule %s must occur exactly once between %s and %s in one file\n", id, begin, end > "/dev/stderr"
            failed = 1
        }
    }
    if (failed) exit 1
    print "All required rules are enclosed by their gate markers"
}
