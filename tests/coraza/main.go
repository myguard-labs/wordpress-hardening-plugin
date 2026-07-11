// coraza-compat-probe: verify SecLang construct support in the pinned Coraza
// version, gate arbitrary ruleset files against Coraza, or run a mini-ftw
// runtime check (load OK ≠ fires — this proves rules actually fire).
//
//	go run .                              # run the built-in construct matrix
//	go run . file1.conf [...]             # load gate: exit 1 on any load failure
//	go run . -tx tests.json file1.conf [...]  # runtime mode: load ruleset(s)
//	                                      # into ONE WAF, replay each test
//	                                      # transaction, check fired rule IDs
//
// -tx test file = JSON array of transactions (go-ftw-lite):
//
//	[
//	  {
//	    "name": "xff-ipv4-first-hop",
//	    "method": "POST",                       // default GET
//	    "uri": "/wp-login.php?a=b",             // default /
//	    "client_ip": "203.0.113.77",            // default 203.0.113.99 (REMOTE_ADDR)
//	    "headers": {"Host": "localhost", "User-Agent": "ftw", "Content-Type": "application/x-www-form-urlencoded"},
//	    "data": "log=admin&pwd=x",              // request body (sets body phase in motion)
//	    "expect_ids": [9522061],                // every id must have fired
//	    "no_expect_ids": [9522062],             // none of these may fire
//	    "expect_interruption": false            // optional: assert deny/drop/redirect happened (or not)
//	  }
//	]
//
// Runtime mode prepends `SecRuleEngine On` + `SecRequestBodyAccess On` before
// the ruleset files (a file can still override — last directive wins).
// Interruption semantics are real: a phase-1/2 deny stops later phases, same
// as a live engine.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/corazawaf/coraza/v3"
)

func try(name, directive string) {
	cfg := coraza.NewWAFConfig().WithDirectives(directive)
	_, err := coraza.NewWAF(cfg)
	if err != nil {
		fmt.Printf("%-34s ERROR: %v\n", name, err)
	} else {
		fmt.Printf("%-34s OK\n", name)
	}
}

func gateFiles(files []string) {
	failed := false
	for _, f := range files {
		_, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectivesFromFile(f))
		if err != nil {
			fmt.Printf("%s: LOAD-FATAL: %v\n", f, err)
			failed = true
		} else {
			fmt.Printf("%s: OK\n", f)
		}
	}
	if failed {
		os.Exit(1)
	}
}

type txTest struct {
	Name               string            `json:"name"`
	Method             string            `json:"method"`
	URI                string            `json:"uri"`
	ClientIP           string            `json:"client_ip"`
	Headers            map[string]string `json:"headers"`
	Data               string            `json:"data"`
	ExpectIDs          []int             `json:"expect_ids"`
	NoExpectIDs        []int             `json:"no_expect_ids"`
	ExpectInterruption *bool             `json:"expect_interruption"`
}

func runTests(testFile string, confFiles []string) {
	raw, err := os.ReadFile(testFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", testFile, err)
		os.Exit(2)
	}
	var tests []txTest
	if err := json.Unmarshal(raw, &tests); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", testFile, err)
		os.Exit(2)
	}

	cfg := coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine On\nSecRequestBodyAccess On")
	for _, f := range confFiles {
		cfg = cfg.WithDirectivesFromFile(f)
	}
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LOAD-FATAL: %v\n", err)
		os.Exit(1)
	}

	failed := 0
	for i, t := range tests {
		name := t.Name
		if name == "" {
			name = fmt.Sprintf("test-%d", i+1)
		}
		if t.Method == "" {
			t.Method = "GET"
		}
		if t.URI == "" {
			t.URI = "/"
		}
		if t.ClientIP == "" {
			t.ClientIP = "203.0.113.99"
		}

		tx := waf.NewTransaction()
		tx.ProcessConnection(t.ClientIP, 42424, "127.0.0.1", 80)
		tx.ProcessURI(t.URI, t.Method, "HTTP/1.1")
		for k, v := range t.Headers {
			tx.AddRequestHeader(k, v)
		}
		it := tx.ProcessRequestHeaders()
		if it == nil && t.Data != "" {
			if it2, _, err := tx.WriteRequestBody([]byte(t.Data)); err == nil && it2 == nil {
				it, _ = tx.ProcessRequestBody()
			} else {
				it = it2
			}
		} else if it == nil {
			it, _ = tx.ProcessRequestBody()
		}
		tx.ProcessLogging()

		fired := map[int]bool{}
		var firedList []int
		for _, mr := range tx.MatchedRules() {
			id := mr.Rule().ID()
			if id != 0 && !fired[id] {
				fired[id] = true
				firedList = append(firedList, id)
			}
		}
		sort.Ints(firedList)
		tx.Close()

		var problems []string
		for _, id := range t.ExpectIDs {
			if !fired[id] {
				problems = append(problems, fmt.Sprintf("expected id %d did not fire", id))
			}
		}
		for _, id := range t.NoExpectIDs {
			if fired[id] {
				problems = append(problems, fmt.Sprintf("forbidden id %d fired", id))
			}
		}
		if t.ExpectInterruption != nil {
			if *t.ExpectInterruption && it == nil {
				problems = append(problems, "expected interruption, none happened")
			}
			if !*t.ExpectInterruption && it != nil {
				problems = append(problems, fmt.Sprintf("unexpected interruption by rule %d (%s %d)", it.RuleID, it.Action, it.Status))
			}
		}

		if len(problems) == 0 {
			fmt.Printf("PASS %-40s fired=%v\n", name, firedList)
		} else {
			failed++
			fmt.Printf("FAIL %-40s fired=%v\n", name, firedList)
			for _, p := range problems {
				fmt.Printf("     - %s\n", p)
			}
			if it != nil {
				fmt.Printf("     - interruption: rule %d action=%s status=%d\n", it.RuleID, it.Action, it.Status)
			}
		}
	}
	fmt.Printf("%d/%d passed\n", len(tests)-failed, len(tests))
	if failed > 0 {
		os.Exit(1)
	}
}

func main() {
	txFile := flag.String("tx", "", "JSON transaction test file (mini-ftw runtime mode)")
	flag.Parse()
	args := flag.Args()

	if *txFile != "" {
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "-tx requires at least one ruleset .conf file")
			os.Exit(2)
		}
		runTests(*txFile, args)
		return
	}
	if len(args) > 0 {
		gateFiles(args)
		return
	}
	try("exec-with-arg", `SecRule ARGS "@rx x" "id:1,phase:2,pass,exec:/usr/local/bin/test.sh"`)
	try("initcol", `SecAction "id:2,phase:1,initcol:ip=%{REMOTE_ADDR},pass,nolog"`)
	try("setvar-ip-collection", `SecAction "id:3,phase:1,setvar:ip.count=+1,pass,nolog"`)
	try("expirevar", `SecAction "id:31,phase:1,setvar:tx.a=1,expirevar:tx.a=3600,pass,nolog"`)
	try("sanitiseArg", `SecAction "id:4,phase:1,sanitiseArg:password,pass"`)
	try("append", `SecAction "id:41,phase:4,append:'<!-- x -->',pass"`)
	try("prepend", `SecAction "id:42,phase:4,prepend:'x',pass"`)
	try("deprecatevar", `SecAction "id:43,phase:1,deprecatevar:ip.x=1/60,pass,nolog"`)
	try("setsid", `SecAction "id:44,phase:1,setsid:%{REQUEST_COOKIES.sid},pass,nolog"`)
	try("setuid", `SecAction "id:45,phase:1,setuid:%{ARGS.user},pass,nolog"`)
	try("setrsc", `SecAction "id:46,phase:1,setrsc:x,pass,nolog"`)
	try("pause", `SecAction "id:47,phase:1,pause:3000,pass,nolog"`)
	try("proxy", `SecRule ARGS "@rx x" "id:48,phase:1,proxy:http://x.example"`)
	try("xmlns", `SecRule XML:/x/y "@rx x" "id:49,phase:2,pass,xmlns:x=http://x"`)
	try("sanitiseMatched", `SecAction "id:50,phase:5,sanitiseMatched,pass"`)
	try("regex-lookbehind", `SecRule ARGS "@rx (?<=foo)bar" "id:5,phase:2,pass"`)
	try("regex-lookahead", `SecRule ARGS "@rx foo(?!bar)" "id:51,phase:2,pass"`)
	try("regex-backreference", `SecRule ARGS "@rx (\w+) \1" "id:52,phase:2,pass"`)
	try("regex-possessive", `SecRule ARGS "@rx a++b" "id:53,phase:2,pass"`)
	try("regex-atomic-group", `SecRule ARGS "@rx (?>fo+)bar" "id:54,phase:2,pass"`)
	try("regex-K", `SecRule ARGS "@rx foo\Kbar" "id:55,phase:2,pass"`)
	try("var-SESSION", `SecRule SESSION:foo "@rx x" "id:6,phase:2,pass"`)
	try("var-GLOBAL", `SecRule GLOBAL:foo "@rx x" "id:61,phase:2,pass"`)
	try("var-RESOURCE", `SecRule RESOURCE:foo "@rx x" "id:62,phase:2,pass"`)
	try("var-USER", `SecRule USER:foo "@rx x" "id:63,phase:2,pass"`)
	try("var-IP", `SecRule IP:count "@gt 5" "id:64,phase:2,pass"`)
	try("var-PERF_RULES", `SecRule PERF_RULES "@gt 100" "id:65,phase:5,pass"`)
	try("var-STREAM_INPUT", `SecRule STREAM_INPUT_BODY "@rx x" "id:66,phase:2,pass"`)
	try("var-WEBSERVER_ERROR_LOG", `SecRule WEBSERVER_ERROR_LOG "@rx x" "id:67,phase:5,pass"`)
	try("var-MODSEC_BUILD", `SecRule MODSEC_BUILD "@ge 020905" "id:68,phase:1,pass"`)
	try("op-rbl", `SecRule REMOTE_ADDR "@rbl xbl.spamhaus.org" "id:7,phase:1,pass"`)
	try("op-inspectFile", `SecRule FILES_TMPNAMES "@inspectFile /bin/true" "id:8,phase:2,pass"`)
	try("op-geoLookup", `SecRule REMOTE_ADDR "@geoLookup" "id:81,phase:1,pass,nolog"`)
	try("op-verifyCC", `SecRule ARGS "@verifyCC \d{13,16}" "id:82,phase:2,pass"`)
	try("op-verifySSN", `SecRule ARGS "@verifySSN \d{3}-\d{2}-\d{4}" "id:83,phase:2,pass"`)
	try("op-verifyCPF", `SecRule ARGS "@verifyCPF x" "id:84,phase:2,pass"`)
	try("op-rsub", `SecRule STREAM_OUTPUT_BODY "@rsub s/foo/bar/" "id:85,phase:4,pass"`)
	try("op-fuzzyHash", `SecRule REQUEST_BODY "@fuzzyHash /x.txt 6" "id:86,phase:2,pass"`)
	try("op-validateHash", `SecRule REQUEST_URI "@validateHash x" "id:87,phase:1,pass"`)
	try("op-gsbLookup", `SecRule ARGS "@gsbLookup x" "id:88,phase:2,pass"`)
	try("op-validateDTD", `SecRule XML "@validateDTD /x.dtd" "id:89,phase:2,pass"`)
	try("op-validateSchema-xsd", `SecRule XML "@validateSchema /x.xsd" "id:90,phase:2,pass"`)
	try("op-datePattern", `SecRule ARGS "@strmatch x" "id:91,phase:2,pass"`)
	try("t-parityEven7bit", `SecRule ARGS "@rx x" "id:92,phase:2,t:parityEven7bit,pass"`)
	try("t-sqlHexDecode", `SecRule ARGS "@rx x" "id:93,phase:2,t:sqlHexDecode,pass"`)
	try("t-escapeSeqDecode", `SecRule ARGS "@rx x" "id:94,phase:2,t:escapeSeqDecode,pass"`)
	try("ctl-hashEngine", `SecAction "id:95,phase:1,ctl:hashEngine=Off,pass,nolog"`)
	try("ctl-ruleRemoveById-range", `SecAction "id:96,phase:1,ctl:ruleRemoveById=1-3,pass,nolog"`)
	try("dir-SecRuleScript", "SecRuleScript /x.lua \"phase:2,id:97,pass\"")
	try("dir-SecRemoteRules", `SecRemoteRules key https://example.com/rules.conf`)
	try("dir-SecUnicodeMap", `SecUnicodeMap 20127`)
	try("dir-SecContentInjection", `SecContentInjection On`)
	try("dir-SecStreamOutBodyInspection", `SecStreamOutBodyInspection On`)
	try("dir-SecDisableBackendCompression", `SecDisableBackendCompression On`)
	try("dir-SecGeoLookupDb", `SecGeoLookupDb /usr/share/GeoIP/GeoLite2-Country.mmdb`)
	try("dir-SecCollectionTimeout", `SecCollectionTimeout 600`)
	try("dir-SecInterceptOnError", `SecInterceptOnError On`)
	try("dir-SecPcreMatchLimit", `SecPcreMatchLimit 1500`)
	try("dir-SecStatusEngine", `SecStatusEngine On`)
	try("dir-SecGuardianLog", `SecGuardianLog /x`)
	try("dir-SecCacheTransformations", `SecCacheTransformations On`)
	try("dir-SecChrootDir", `SecChrootDir /x`)
	try("dir-SecHashEngine", `SecHashEngine On`)
	try("dir-SecXmlExternalEntity", `SecXmlExternalEntity Off`)
}
