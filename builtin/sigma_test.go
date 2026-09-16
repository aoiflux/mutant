package builtin

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"mutant/object"
)

func sigmaB64(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

// A rule in the shape the SigmaHQ repository actually ships: logsource,
// a selection, a filter, and a condition that subtracts one from the other.
const sigmaEncodedPowerShell = `
title: Encoded PowerShell Command Line
id: 5b1c0a0f-2a8e-4a7f-9a1f-0c7d2c9a0b01
status: experimental
description: A PowerShell process started with an encoded command.
author: test
references:
  - https://example.invalid/encoded-powershell
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  filter:
    User: 'NT AUTHORITY\SYSTEM'
  condition: selection and not filter
falsepositives:
  - Administrative scripting
level: high
tags:
  - attack.execution
  - attack.t1059.001
`

func sigmaEvent(t *testing.T, fields map[string]object.Object) *object.Hash {
	t.Helper()
	return makeHashObject(fields)
}

func sigmaParseRule(t *testing.T, text string) *object.Hash {
	t.Helper()
	result, errObj := unwrapPair(t, SigmaParse(stringObj(text)))
	if errObj != nil {
		t.Fatalf("sigma_parse: %s", errObj.Message)
	}
	rule, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("sigma_parse returned %T, want *object.Hash", result)
	}
	return rule
}

func sigmaMatched(t *testing.T, rule object.Object, event *object.Hash) *object.Hash {
	t.Helper()
	result, errObj := unwrapPair(t, SigmaMatch(rule, event))
	if errObj != nil {
		t.Fatalf("sigma_match: %s", errObj.Message)
	}
	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("sigma_match returned %T, want *object.Hash", result)
	}
	return hash
}

func sigmaBool(t *testing.T, hash *object.Hash, key string) bool {
	t.Helper()
	value := hashValueByKey(hash, key)
	boolean, ok := value.(*object.Boolean)
	if !ok {
		t.Fatalf("field %q is %T, want *object.Boolean", key, value)
	}
	return boolean.Value
}

func sigmaStrings(t *testing.T, hash *object.Hash, key string) []string {
	t.Helper()
	value := hashValueByKey(hash, key)
	array, ok := value.(*object.Array)
	if !ok {
		t.Fatalf("field %q is %T, want *object.Array", key, value)
	}
	out := make([]string, 0, len(array.Elements))
	for _, element := range array.Elements {
		out = append(out, sigmaObjectString(element))
	}
	return out
}

func sigmaInt(t *testing.T, hash *object.Hash, key string) int64 {
	t.Helper()
	value := hashValueByKey(hash, key)
	number, ok := value.(*object.Integer)
	if !ok {
		t.Fatalf("field %q is %T, want *object.Integer", key, value)
	}
	return number.Value
}

// sigmaRuleFor builds a one-search rule around a detection body, so a modifier
// test reads as the modifier and nothing else.
func sigmaRuleFor(body string) string {
	return "title: t\ndetection:\n  selection:\n" + body + "  condition: selection\n"
}

func TestSigmaParseReadsTheWholeRule(t *testing.T) {
	rule := sigmaParseRule(t, sigmaEncodedPowerShell)

	for key, want := range map[string]string{
		"title":  "Encoded PowerShell Command Line",
		"id":     "5b1c0a0f-2a8e-4a7f-9a1f-0c7d2c9a0b01",
		"status": "experimental",
		"level":  "high",
		"author": "test",
	} {
		if got := sigmaObjectString(hashValueByKey(rule, key)); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := sigmaObjectString(hashValueByKey(rule, "condition")); got != "selection and not filter" {
		t.Errorf("condition = %q", got)
	}
	if got := sigmaStrings(t, rule, "searches"); strings.Join(got, ",") != "filter,selection" {
		t.Errorf("searches = %v, want [filter selection]", got)
	}
	// The field list is what a coverage question is asked against, so it has to
	// name every field the rule reads, sorted and deduplicated.
	if got := sigmaStrings(t, rule, "fields"); strings.Join(got, ",") != "CommandLine,Image,User" {
		t.Errorf("fields = %v, want [CommandLine Image User]", got)
	}
	if got := sigmaStrings(t, rule, "tags"); strings.Join(got, ",") != "attack.execution,attack.t1059.001" {
		t.Errorf("tags = %v", got)
	}
	logsource, ok := hashValueByKey(rule, "logsource").(*object.Hash)
	if !ok {
		t.Fatalf("logsource is not a hash")
	}
	if got := sigmaObjectString(hashValueByKey(logsource, "category")); got != "process_creation" {
		t.Errorf("logsource.category = %q", got)
	}
	// The detection block comes back verbatim; without it the hash would
	// describe a rule rather than be one, and sigma_match could not take it.
	if _, ok := hashValueByKey(rule, "detection").(*object.Hash); !ok {
		t.Errorf("detection did not round-trip as a hash")
	}
}

func TestSigmaMatchSubtractsTheFilter(t *testing.T) {
	rule := sigmaParseRule(t, sigmaEncodedPowerShell)

	hit := sigmaEvent(t, map[string]object.Object{
		"Image":       stringObj(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
		"CommandLine": stringObj(`powershell.exe -nop -w hidden -enc SQBFAFgA`),
		"User":        stringObj(`CORP\jdoe`),
	})
	result := sigmaMatched(t, rule, hit)
	if !sigmaBool(t, result, "matched") {
		t.Fatalf("the rule did not match an encoded PowerShell command line")
	}
	if got := strings.Join(sigmaStrings(t, result, "searches"), ","); got != "selection" {
		t.Errorf("searches = %q, want selection", got)
	}

	// Same command line, run by SYSTEM: the filter takes it back.
	filtered := sigmaEvent(t, map[string]object.Object{
		"Image":       stringObj(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
		"CommandLine": stringObj(`powershell.exe -nop -w hidden -enc SQBFAFgA`),
		"User":        stringObj(`NT AUTHORITY\SYSTEM`),
	})
	if sigmaBool(t, sigmaMatched(t, rule, filtered), "matched") {
		t.Errorf("the filter did not subtract the SYSTEM process")
	}

	// A plain PowerShell start is not the detection.
	quiet := sigmaEvent(t, map[string]object.Object{
		"Image":       stringObj(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
		"CommandLine": stringObj(`powershell.exe -File C:\scripts\inventory.ps1`),
		"User":        stringObj(`CORP\jdoe`),
	})
	if sigmaBool(t, sigmaMatched(t, rule, quiet), "matched") {
		t.Errorf("a command line with no encoded command matched")
	}
}

// The rule hash has to be a rule: handing it straight back to sigma_match is
// how a ruleset compiled once gets reused, and how a rule stored in a case
// comes back out.
func TestSigmaRuleHashRoundTrips(t *testing.T) {
	rule := sigmaParseRule(t, sigmaEncodedPowerShell)
	again, errObj := unwrapPair(t, SigmaParse(stringObj(sigmaEncodedPowerShell)))
	if errObj != nil {
		t.Fatalf("second parse: %s", errObj.Message)
	}
	_ = again

	event := sigmaEvent(t, map[string]object.Object{
		"Image":       stringObj(`C:\powershell.exe`),
		"CommandLine": stringObj(`x -EncodedCommand y`),
	})
	if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Errorf("the parsed rule hash did not match when handed back to sigma_match")
	}
}

// events_from() keeps the source entry verbatim in `extra`. A rule written
// against the source's own field names has to reach it, or every Sigma rule in
// existence would need a mapping file before it could run here.
func TestSigmaReadsFieldsOutOfExtra(t *testing.T) {
	rule := sigmaParseRule(t, sigmaRuleFor("    EventID: 4688\n"))
	event := sigmaEvent(t, map[string]object.Object{
		"kind":     stringObj("evtx"),
		"category": stringObj("execution"),
		"extra": makeHashObject(map[string]object.Object{
			"EventID": intObj(4688),
			"Image":   stringObj(`C:\Windows\System32\cmd.exe`),
		}),
	})
	if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Errorf("a rule reading EventID did not find it in extra")
	}
}

func TestSigmaNumberMatchesItsStringForm(t *testing.T) {
	rule := sigmaParseRule(t, sigmaRuleFor("    EventID: 1\n"))
	for _, value := range []object.Object{intObj(1), stringObj("1"), &object.Float{Value: 1}} {
		event := sigmaEvent(t, map[string]object.Object{"EventID": value})
		if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
			t.Errorf("EventID: 1 did not match %s", value.Inspect())
		}
	}
	event := sigmaEvent(t, map[string]object.Object{"EventID": intObj(11)})
	if sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Errorf("EventID: 1 matched 11 -- the comparison is not anchored")
	}
}

func TestSigmaModifiers(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		field string
		value object.Object
		want  bool
	}{
		// An unmodified value is the whole field, not a substring of it. This is
		// the difference between a rule that names a user and a rule that
		// matches every user whose name contains those letters.
		{"plain value is the whole field", "    User: 'jdoe'\n", "User", stringObj(`CORP\jdoe`), false},
		{"plain value exact", "    User: 'jdoe'\n", "User", stringObj("jdoe"), true},
		{"contains hit", "    CommandLine|contains: 'mimikatz'\n", "CommandLine", stringObj("c:\\t\\MIMIKATZ.exe run"), true},
		{"contains miss", "    CommandLine|contains: 'mimikatz'\n", "CommandLine", stringObj("notepad.exe"), false},
		{"startswith", "    Image|startswith: 'C:\\Windows'\n", "Image", stringObj(`C:\Windows\cmd.exe`), true},
		{"startswith anchored", "    Image|startswith: 'Windows'\n", "Image", stringObj(`C:\Windows\cmd.exe`), false},
		{"endswith", "    Image|endswith: '\\cmd.exe'\n", "Image", stringObj(`C:\Windows\cmd.exe`), true},
		{"cased respects case", "    Image|contains|cased: 'CMD'\n", "Image", stringObj(`C:\Windows\cmd.exe`), false},
		{"uncased ignores case", "    Image|contains: 'CMD'\n", "Image", stringObj(`C:\Windows\cmd.exe`), true},
		// A backslash before a wildcard escapes it, so a path wildcard is
		// written `*\cmd.exe` or `C:\\*\\cmd.exe` -- never `C:\*\cmd.exe`,
		// which asks for a literal asterisk. The two cases below pin both.
		{"wildcard star", "    Image: '*\\cmd.exe'\n", "Image", stringObj(`C:\Windows\cmd.exe`), true},
		{"wildcard between escaped backslashes", "    Image: 'C:\\\\*\\\\cmd.exe'\n", "Image", stringObj(`C:\Windows\cmd.exe`), true},
		{"wildcard question", "    Ext: 'ex?'\n", "Ext", stringObj("exe"), true},
		{"escaped star is literal", "    Name: 'a\\*b'\n", "Name", stringObj("axxb"), false},
		{"escaped star matches star", "    Name: 'a\\*b'\n", "Name", stringObj("a*b"), true},
		{"regex", "    CommandLine|re: '-e(nc|ncodedcommand) [A-Za-z0-9+/=]{20,}'\n", "CommandLine", stringObj("pwsh -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"), true},
		{"regex case flag", "    CommandLine|re|i: 'MIMIKATZ'\n", "CommandLine", stringObj("run mimikatz now"), true},
		{"cidr hit", "    DestinationIp|cidr: '10.0.0.0/8'\n", "DestinationIp", stringObj("10.4.9.1"), true},
		{"cidr miss", "    DestinationIp|cidr: '10.0.0.0/8'\n", "DestinationIp", stringObj("192.168.1.1"), false},
		{"gt", "    Bytes|gt: 1000\n", "Bytes", intObj(4096), true},
		{"gt miss", "    Bytes|gt: 1000\n", "Bytes", intObj(12), false},
		{"lte boundary", "    Bytes|lte: 1000\n", "Bytes", intObj(1000), true},
		{"exists true", "    ParentImage|exists: true\n", "ParentImage", stringObj("x"), true},
		{"windash slash", "    CommandLine|windash|contains: ' -enc '\n", "CommandLine", stringObj("pwsh /enc AAAA"), true},
		{"windash endash", "    CommandLine|windash|contains: ' -enc '\n", "CommandLine", stringObj("pwsh \u2013enc AAAA"), true},
		{"windash original", "    CommandLine|windash|contains: ' -enc '\n", "CommandLine", stringObj("pwsh -enc AAAA"), true},
		{"list is or", "    Image|endswith:\n      - '\\cmd.exe'\n      - '\\wscript.exe'\n", "Image", stringObj(`C:\wscript.exe`), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := sigmaParseRule(t, sigmaRuleFor(tt.body))
			event := sigmaEvent(t, map[string]object.Object{tt.field: tt.value})
			if got := sigmaBool(t, sigmaMatched(t, rule, event), "matched"); got != tt.want {
				t.Errorf("matched = %v, want %v", got, tt.want)
			}
		})
	}
}

// |all is the difference between "any of these" and "all of these" on one
// field, and getting it backwards silently changes what every rule using it
// means.
func TestSigmaAllModifier(t *testing.T) {
	body := "    CommandLine|contains|all:\n      - 'Invoke-'\n      - 'DownloadString'\n"
	rule := sigmaParseRule(t, sigmaRuleFor(body))

	both := sigmaEvent(t, map[string]object.Object{"CommandLine": stringObj("Invoke-Expression (New-Object Net.WebClient).DownloadString('h')")})
	if !sigmaBool(t, sigmaMatched(t, rule, both), "matched") {
		t.Errorf("|all did not match a value containing both")
	}
	one := sigmaEvent(t, map[string]object.Object{"CommandLine": stringObj("Invoke-Expression 1")})
	if sigmaBool(t, sigmaMatched(t, rule, one), "matched") {
		t.Errorf("|all matched a value containing only one")
	}
}

// The |utf16le|base64offset|contains chain is the reason base64 modifiers
// exist: the attacker's string sits UTF-16-encoded inside a base64 blob at an
// offset the encoder never told anyone.
func TestSigmaBase64OffsetFindsAStringInsideAnEncodedCommand(t *testing.T) {
	rule := sigmaParseRule(t, sigmaRuleFor("    CommandLine|utf16le|base64offset|contains: 'IEX'\n"))

	// Encode the way PowerShell does -- UTF-16LE, then base64 -- with the
	// interesting string at each of the three offsets a blob can put it.
	for offset := 0; offset < 3; offset++ {
		payload := strings.Repeat("A", offset) + "IEX (New-Object Net.WebClient)"
		encoded := sigmaB64(sigmaUTF16(payload, false, false))
		event := sigmaEvent(t, map[string]object.Object{"CommandLine": stringObj("powershell -enc " + encoded)})
		if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
			t.Errorf("offset %d: the encoded IEX was not found in %q", offset, encoded)
		}
	}

	// And it does not fire on an encoded command that does not carry it.
	clean := sigmaB64(sigmaUTF16("Get-ChildItem C:\\", false, false))
	event := sigmaEvent(t, map[string]object.Object{"CommandLine": stringObj("powershell -enc " + clean)})
	if sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Errorf("base64offset fired on an encoded command without the string")
	}
}

func TestSigmaNullAndFieldref(t *testing.T) {
	absent := sigmaParseRule(t, sigmaRuleFor("    ParentImage: null\n"))
	if !sigmaBool(t, sigmaMatched(t, absent, sigmaEvent(t, map[string]object.Object{"Image": stringObj("x")})), "matched") {
		t.Errorf("a null value did not match an absent field")
	}
	if sigmaBool(t, sigmaMatched(t, absent, sigmaEvent(t, map[string]object.Object{"ParentImage": stringObj("x")})), "matched") {
		t.Errorf("a null value matched a field that was present")
	}

	ref := sigmaParseRule(t, sigmaRuleFor("    Image|fieldref: 'ParentImage'\n"))
	same := sigmaEvent(t, map[string]object.Object{"Image": stringObj("a.exe"), "ParentImage": stringObj("A.EXE")})
	if !sigmaBool(t, sigmaMatched(t, ref, same), "matched") {
		t.Errorf("|fieldref did not match two equal fields")
	}
	different := sigmaEvent(t, map[string]object.Object{"Image": stringObj("a.exe"), "ParentImage": stringObj("b.exe")})
	if sigmaBool(t, sigmaMatched(t, ref, different), "matched") {
		t.Errorf("|fieldref matched two different fields")
	}
}

func TestSigmaKeywordsSearchEveryValue(t *testing.T) {
	rule := sigmaParseRule(t, "title: t\ndetection:\n  keywords:\n    - 'mimikatz'\n    - 'sekurlsa'\n  condition: keywords\n")
	nested := sigmaEvent(t, map[string]object.Object{
		"message": stringObj("nothing here"),
		"extra": makeHashObject(map[string]object.Object{
			"args": &object.Array{Elements: []object.Object{stringObj("sekurlsa::logonpasswords")}},
		}),
	})
	if !sigmaBool(t, sigmaMatched(t, rule, nested), "matched") {
		t.Errorf("a keyword search did not reach a nested value")
	}
	clean := sigmaEvent(t, map[string]object.Object{"message": stringObj("routine login")})
	if sigmaBool(t, sigmaMatched(t, rule, clean), "matched") {
		t.Errorf("a keyword search matched an event carrying neither keyword")
	}
}

func TestSigmaConditionQuantifiers(t *testing.T) {
	detection := "title: t\ndetection:\n" +
		"  selection_a:\n    A: 1\n" +
		"  selection_b:\n    B: 2\n" +
		"  selection_c:\n    C: 3\n" +
		"  condition: "

	cases := []struct {
		condition string
		fields    map[string]object.Object
		want      bool
	}{
		{"all of selection*", map[string]object.Object{"A": intObj(1), "B": intObj(2), "C": intObj(3)}, true},
		{"all of selection*", map[string]object.Object{"A": intObj(1), "B": intObj(2)}, false},
		{"all of them", map[string]object.Object{"A": intObj(1), "B": intObj(2), "C": intObj(3)}, true},
		{"1 of selection*", map[string]object.Object{"B": intObj(2)}, true},
		{"1 of them", map[string]object.Object{"Z": intObj(9)}, false},
		{"any of selection*", map[string]object.Object{"C": intObj(3)}, true},
		{"2 of selection*", map[string]object.Object{"A": intObj(1)}, false},
		{"2 of selection*", map[string]object.Object{"A": intObj(1), "C": intObj(3)}, true},
		{"selection_a and not selection_b", map[string]object.Object{"A": intObj(1)}, true},
		{"selection_a and not selection_b", map[string]object.Object{"A": intObj(1), "B": intObj(2)}, false},
		{"(selection_a or selection_b) and not selection_c", map[string]object.Object{"B": intObj(2)}, true},
		{"not selection_a", map[string]object.Object{"B": intObj(2)}, true},
	}

	for index, tt := range cases {
		t.Run(strconv.Itoa(index)+" "+tt.condition, func(t *testing.T) {
			rule := sigmaParseRule(t, detection+tt.condition+"\n")
			event := sigmaEvent(t, tt.fields)
			if got := sigmaBool(t, sigmaMatched(t, rule, event), "matched"); got != tt.want {
				t.Errorf("%q matched = %v, want %v", tt.condition, got, tt.want)
			}
		})
	}
}

// Every refusal here is a rule this engine cannot evaluate. Each one has to
// fail at parse time, because the alternative is a rule that sits in a ruleset
// looking like coverage and never fires.
func TestSigmaRefusesWhatItCannotEvaluate(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want string
	}{
		{
			"aggregation",
			"title: t\ndetection:\n  selection:\n    A: 1\n  condition: selection | count() by B > 5\n",
			"aggregation",
		},
		{
			"near",
			"title: t\ndetection:\n  selection:\n    A: 1\n  other:\n    B: 2\n  condition: selection | near other\n",
			"aggregation",
		},
		{
			"timeframe",
			"title: t\ndetection:\n  selection:\n    A: 1\n  timeframe: 15m\n  condition: selection\n",
			"timeframe",
		},
		{
			"unknown modifier",
			"title: t\ndetection:\n  selection:\n    A|startswithish: 1\n  condition: selection\n",
			"unknown modifier",
		},
		{
			"expand placeholder",
			"title: t\ndetection:\n  selection:\n    A|expand: '%admins%'\n  condition: selection\n",
			"|expand",
		},
		{
			"undefined identifier",
			"title: t\ndetection:\n  selection:\n    A: 1\n  condition: selection and filter\n",
			"does not define",
		},
		{
			"pattern matching nothing",
			"title: t\ndetection:\n  selection:\n    A: 1\n  condition: selection and not all of filter*\n",
			"matches none of the search identifiers",
		},
		{
			"rule collection",
			"title: t\naction: global\ndetection:\n  selection:\n    A: 1\n  condition: selection\n",
			"rule collections",
		},
		{
			"no detection block",
			"title: t\nlevel: high\n",
			"no detection block",
		},
		{
			"no condition",
			"title: t\ndetection:\n  selection:\n    A: 1\n",
			"no condition",
		},
		{
			"two comparisons on one field",
			"title: t\ndetection:\n  selection:\n    A|contains|startswith: 'x'\n  condition: selection\n",
			"can only be compared one way",
		},
		{
			"bad cidr",
			"title: t\ndetection:\n  selection:\n    Ip|cidr: 'not-a-network'\n  condition: selection\n",
			"CIDR notation",
		},
		{
			"bad regex",
			"title: t\ndetection:\n  selection:\n    A|re: '([unclosed'\n  condition: selection\n",
			"does not compile",
		},
		{
			"unclosed paren",
			"title: t\ndetection:\n  selection:\n    A: 1\n  condition: (selection\n",
			"unclosed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(SigmaParse(stringObj(tt.rule)))
			if errObj == nil {
				t.Fatalf("sigma_parse accepted a rule it cannot evaluate")
			}
			if !strings.Contains(errObj.Message, tt.want) {
				t.Errorf("error %q does not name %q", errObj.Message, tt.want)
			}
		})
	}
}

// A rule that did not match because the evidence never carried the field is a
// different answer from a rule that looked and disagreed. Reporting them the
// same way is how a blind spot gets written down as a clean host.
func TestSigmaReportsTheFieldsItCouldNotFind(t *testing.T) {
	rule := sigmaParseRule(t, sigmaEncodedPowerShell)
	event := sigmaEvent(t, map[string]object.Object{"Image": stringObj(`C:\powershell.exe`)})
	result := sigmaMatched(t, rule, event)

	if sigmaBool(t, result, "matched") {
		t.Fatalf("matched an event missing the fields it reads")
	}
	missing := strings.Join(sigmaStrings(t, result, "fields_missing"), ",")
	if missing != "CommandLine,User" {
		t.Errorf("fields_missing = %q, want CommandLine,User", missing)
	}
	if read := strings.Join(sigmaStrings(t, result, "fields_read"), ","); read != "Image" {
		t.Errorf("fields_read = %q, want Image", read)
	}
}

func TestSigmaParseAllLoadsARulesetAndRefusesAPartialOne(t *testing.T) {
	ruleset := sigmaEncodedPowerShell + "\n---\n" + sigmaRuleFor("    EventID: 4688\n")
	result, errObj := unwrapPair(t, SigmaParseAll(stringObj(ruleset)))
	if errObj != nil {
		t.Fatalf("sigma_parse_all: %s", errObj.Message)
	}
	rules, ok := result.(*object.Array)
	if !ok || len(rules.Elements) != 2 {
		t.Fatalf("sigma_parse_all returned %v rules, want 2", result.Inspect())
	}

	// One bad rule fails the whole call. A ruleset that loads all but one of
	// its rules is worse than one that fails, because nobody goes looking.
	broken := sigmaEncodedPowerShell + "\n---\ntitle: broken\ndetection:\n  selection:\n    A: 1\n  condition: selection and missing\n"
	_, errObj = unwrapPairNoFatal(SigmaParseAll(stringObj(broken)))
	if errObj == nil {
		t.Fatalf("sigma_parse_all accepted a ruleset with a rule that does not compile")
	}
	if !strings.Contains(errObj.Message, "document 1") {
		t.Errorf("error %q does not say which document failed", errObj.Message)
	}
}

func TestSigmaScanOverATimeline(t *testing.T) {
	ruleset := sigmaEncodedPowerShell + "\n---\n" +
		"title: Process Creation\nid: p-1\nlevel: low\ndetection:\n  selection:\n    EventID: 4688\n  condition: selection\n"

	events := &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{
			"Image":       stringObj(`C:\powershell.exe`),
			"CommandLine": stringObj(`powershell -enc AAAA`),
			"User":        stringObj(`CORP\jdoe`),
			"EventID":     intObj(4688),
		}),
		makeHashObject(map[string]object.Object{
			"Image":       stringObj(`C:\notepad.exe`),
			"CommandLine": stringObj(`notepad.exe`),
			"User":        stringObj(`CORP\jdoe`),
			"EventID":     intObj(4688),
		}),
		makeHashObject(map[string]object.Object{"kind": stringObj("mft"), "ts": intObj(1)}),
	}}

	result, errObj := unwrapPair(t, SigmaScan(stringObj(ruleset), events))
	if errObj != nil {
		t.Fatalf("sigma_scan: %s", errObj.Message)
	}
	report, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("sigma_scan returned %T", result)
	}

	if got := sigmaInt(t, report, "rules"); got != 2 {
		t.Errorf("rules = %d, want 2", got)
	}
	if got := sigmaInt(t, report, "events"); got != 3 {
		t.Errorf("events = %d, want 3", got)
	}
	// The encoded command line hits once; the EventID rule hits the two process
	// events and not the MFT record.
	if got := sigmaInt(t, report, "matched"); got != 3 {
		t.Errorf("matched = %d, want 3", got)
	}

	byLevel, ok := hashValueByKey(report, "by_level").(*object.Hash)
	if !ok {
		t.Fatalf("by_level is not a hash")
	}
	if got := sigmaObjectString(hashValueByKey(byLevel, "high")); got != "1" {
		t.Errorf("by_level.high = %q, want 1", got)
	}
	if got := sigmaObjectString(hashValueByKey(byLevel, "low")); got != "2" {
		t.Errorf("by_level.low = %q, want 2", got)
	}

	hits, ok := hashValueByKey(report, "hits").(*object.Array)
	if !ok || len(hits.Elements) != 3 {
		t.Fatalf("hits is not three entries")
	}
	first, ok := hits.Elements[0].(*object.Hash)
	if !ok {
		t.Fatalf("a hit is not a hash")
	}
	if hashValueByKey(first, "event") == nil {
		t.Errorf("a hit does not carry the event it fired on")
	}
	if got := sigmaObjectString(hashValueByKey(first, "event_index")); got != "0" {
		t.Errorf("event_index = %q, want 0", got)
	}
}

// The coverage question: every field of the ruleset that no event in the scan
// carried. A rule reading Image over a timeline with no Image field did not
// clear the host.
func TestSigmaScanNamesFieldsNoEventCarried(t *testing.T) {
	ruleset := "title: t\ndetection:\n  selection:\n    Image|endswith: '\\cmd.exe'\n    CommandLine|contains: 'x'\n  condition: selection\n"
	events := &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{"Image": stringObj(`C:\cmd.exe`)}),
	}}
	result, errObj := unwrapPair(t, SigmaScan(stringObj(ruleset), events))
	if errObj != nil {
		t.Fatalf("sigma_scan: %s", errObj.Message)
	}
	report := result.(*object.Hash)
	if got := strings.Join(sigmaStrings(t, report, "unmatched_fields"), ","); got != "CommandLine" {
		t.Errorf("unmatched_fields = %q, want CommandLine", got)
	}
}

func TestSigmaArgumentErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
		want string
	}{
		{"parse arity", func() object.Object { return SigmaParse() }, "wrong number of arguments"},
		{"parse type", func() object.Object { return SigmaParse(intObj(1)) }, "must be BYTES or STRING"},
		{"parse ruleset", func() object.Object {
			return SigmaParse(stringObj(sigmaEncodedPowerShell + "\n---\ntitle: b\ndetection:\n  s:\n    A: 1\n  condition: s\n"))
		}, "sigma_parse_all"},
		{"match arity", func() object.Object { return SigmaMatch(stringObj("x")) }, "wrong number of arguments"},
		{"match event type", func() object.Object {
			return SigmaMatch(stringObj(sigmaRuleFor("    A: 1\n")), intObj(3))
		}, "must be HASH"},
		{"scan rules type", func() object.Object { return SigmaScan(intObj(1), &object.Array{}) }, "must be STRING, HASH or ARRAY"},
		{"scan events type", func() object.Object {
			return SigmaScan(stringObj(sigmaRuleFor("    A: 1\n")), intObj(1))
		}, "must be HASH or ARRAY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := unwrapPairNoFatal(tt.call())
			if errObj == nil {
				t.Fatalf("call was accepted")
			}
			if !strings.Contains(errObj.Message, tt.want) {
				t.Errorf("error %q does not contain %q", errObj.Message, tt.want)
			}
		})
	}
}

// A search identifier whose value is a list of mappings is an OR of groups.
// Getting this wrong turns an OR into an AND and quietly halves a ruleset.
func TestSigmaListOfMappingsIsAnOr(t *testing.T) {
	rule := sigmaParseRule(t, "title: t\ndetection:\n  selection:\n    - Image|endswith: '\\\\cmd.exe'\n    - Image|endswith: '\\\\wscript.exe'\n  condition: selection\n")

	for _, image := range []string{`C:\Windows\cmd.exe`, `C:\Users\a\wscript.exe`} {
		event := sigmaEvent(t, map[string]object.Object{"Image": stringObj(image)})
		if !sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
			t.Errorf("%s did not match either branch", image)
		}
	}
	event := sigmaEvent(t, map[string]object.Object{"Image": stringObj(`C:\Windows\notepad.exe`)})
	if sigmaBool(t, sigmaMatched(t, rule, event), "matched") {
		t.Errorf("a list of mappings matched something in neither branch")
	}
}

// Two field tests in one mapping are AND-ed. This is the other half of the
// pair above, and the pair is where a matcher is usually wrong.
func TestSigmaFieldsInOneMappingAreAnded(t *testing.T) {
	rule := sigmaParseRule(t, sigmaRuleFor("    Image|endswith: '\\\\cmd.exe'\n    User: 'SYSTEM'\n"))

	both := sigmaEvent(t, map[string]object.Object{"Image": stringObj(`C:\cmd.exe`), "User": stringObj("SYSTEM")})
	if !sigmaBool(t, sigmaMatched(t, rule, both), "matched") {
		t.Errorf("both fields held and the group did not match")
	}
	one := sigmaEvent(t, map[string]object.Object{"Image": stringObj(`C:\cmd.exe`), "User": stringObj("jdoe")})
	if sigmaBool(t, sigmaMatched(t, rule, one), "matched") {
		t.Errorf("one field held and the group matched anyway")
	}
}

// Windows rules routinely name nested fields with dots. A key that literally
// contains a dot wins over the traversal, because that is what the event says
// it is called.
func TestSigmaDottedFieldNames(t *testing.T) {
	rule := sigmaParseRule(t, sigmaRuleFor("    winlog.event_data.TargetUserName: 'svc_backup'\n"))

	nested := sigmaEvent(t, map[string]object.Object{
		"winlog": makeHashObject(map[string]object.Object{
			"event_data": makeHashObject(map[string]object.Object{"TargetUserName": stringObj("svc_backup")}),
		}),
	})
	if !sigmaBool(t, sigmaMatched(t, rule, nested), "matched") {
		t.Errorf("a dotted field name did not traverse into the event")
	}

	flat := sigmaEvent(t, map[string]object.Object{"winlog.event_data.TargetUserName": stringObj("svc_backup")})
	if !sigmaBool(t, sigmaMatched(t, rule, flat), "matched") {
		t.Errorf("a key that literally contains dots was not found")
	}
}

// `selection and not 1 of filter_optional_*` is the idiom most of SigmaHQ is
// written in, so it gets its own test rather than being inferred from the
// quantifier table.
func TestSigmaOptionalFilterIdiom(t *testing.T) {
	rule := sigmaParseRule(t, "title: t\ndetection:\n"+
		"  selection:\n    EventID: 4688\n"+
		"  filter_optional_system:\n    User: 'SYSTEM'\n"+
		"  filter_optional_known:\n    Image|endswith: '\\\\backup.exe'\n"+
		"  condition: selection and not 1 of filter_optional_*\n")

	cases := []struct {
		name   string
		fields map[string]object.Object
		want   bool
	}{
		{"unfiltered", map[string]object.Object{"EventID": intObj(4688), "User": stringObj("jdoe"), "Image": stringObj("a.exe")}, true},
		{"filtered by user", map[string]object.Object{"EventID": intObj(4688), "User": stringObj("SYSTEM"), "Image": stringObj("a.exe")}, false},
		{"filtered by image", map[string]object.Object{"EventID": intObj(4688), "User": stringObj("jdoe"), "Image": stringObj(`C:\backup.exe`)}, false},
		{"wrong event", map[string]object.Object{"EventID": intObj(1), "User": stringObj("jdoe"), "Image": stringObj("a.exe")}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := sigmaBool(t, sigmaMatched(t, rule, sigmaEvent(t, tt.fields)), "matched"); got != tt.want {
				t.Errorf("matched = %v, want %v", got, tt.want)
			}
		})
	}
}

// fields_missing must not depend on the shape of the condition: a search the
// boolean would short-circuit past is still a search the rule reads.
func TestSigmaMissingFieldsDoNotDependOnEvaluationOrder(t *testing.T) {
	forward := sigmaParseRule(t, "title: t\ndetection:\n  a:\n    A: 1\n  b:\n    B: 2\n  condition: a and b\n")
	backward := sigmaParseRule(t, "title: t\ndetection:\n  a:\n    A: 1\n  b:\n    B: 2\n  condition: b and a\n")
	event := sigmaEvent(t, map[string]object.Object{"Z": intObj(9)})

	for _, rule := range []*object.Hash{forward, backward} {
		result := sigmaMatched(t, rule, event)
		if got := strings.Join(sigmaStrings(t, result, "fields_missing"), ","); got != "A,B" {
			t.Errorf("condition %q reported fields_missing = %q, want A,B",
				sigmaObjectString(hashValueByKey(rule, "condition")), got)
		}
	}
}

// sigma_scan takes rules that are already compiled, which is how a ruleset
// loaded once gets reused across several timelines.
func TestSigmaScanAcceptsParsedRules(t *testing.T) {
	rules, errObj := unwrapPair(t, SigmaParseAll(stringObj(sigmaEncodedPowerShell)))
	if errObj != nil {
		t.Fatalf("sigma_parse_all: %s", errObj.Message)
	}
	events := &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{
			"Image":       stringObj(`C:\powershell.exe`),
			"CommandLine": stringObj(`powershell -enc AAAA`),
			"User":        stringObj(`CORP\jdoe`),
		}),
	}}
	result, errObj := unwrapPair(t, SigmaScan(rules, events))
	if errObj != nil {
		t.Fatalf("sigma_scan: %s", errObj.Message)
	}
	if got := sigmaInt(t, result.(*object.Hash), "matched"); got != 1 {
		t.Errorf("matched = %d, want 1", got)
	}
}

// A quantifier target with no wildcard names exactly one identifier. If the
// resolution were a substring match, `all of selection` would silently pull in
// selection_extra and the rule would mean something its author did not write.
func TestSigmaQuantifierTargetIsNotASubstringMatch(t *testing.T) {
	rule := sigmaParseRule(t, "title: t\ndetection:\n"+
		"  selection:\n    A: 1\n"+
		"  selection_extra:\n    B: 2\n"+
		"  condition: all of selection\n")

	if got := sigmaObjectString(hashValueByKey(rule, "condition")); got != "all of selection" {
		t.Fatalf("condition = %q", got)
	}
	only := sigmaEvent(t, map[string]object.Object{"A": intObj(1)})
	if !sigmaBool(t, sigmaMatched(t, rule, only), "matched") {
		t.Errorf("`all of selection` did not hold when selection held")
	}
}
