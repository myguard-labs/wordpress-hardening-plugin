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

/id:[0-9]+/ {
    if (match($0, /id:[0-9]+/)) {
        id = substr($0, RSTART + 3, RLENGTH - 3)
        if (id in required) {
            rule_count[id]++
            rule_file[id] = FILENAME
            rule_line[id] = FNR
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
