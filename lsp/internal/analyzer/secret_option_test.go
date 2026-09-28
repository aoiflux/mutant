package analyzer

import (
	"strings"
	"testing"
)

func TestSecretOptionFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a passphrase handed to record_open",
			`record_open("exhibit.mrec", {"passphrase": "hunter2"});`,
			"`record_open` refuses an option named \"passphrase\": a passphrase is not an argument. Key material " +
				"must not sit in program text",
		},
		{
			"a password handed to case_key_open",
			`let key, err = case_key_open("case.key", {"password": pw});`,
			"`case_key_open` refuses an option named \"password\"",
		},
		{
			"a key handed to ledger_open",
			`let opened, err = ledger_open("ledger", "examiner", {"key": k});`,
			"`ledger_open` refuses an option named \"key\"",
		},
		{
			"a secret handed to review_list, through a name bound once",
			`let opts = {"secret": s};
let reviews, err = review_list(1, opts);`,
			"`review_list` refuses an option named \"secret\"",
		},
		{
			"the options of record_seal, which are not optional",
			`record_seal("image.bin", "exhibit.mrec", [], {"default": "open", "passphrase": p});`,
			"`record_seal` refuses an option named \"passphrase\"",
		},
		{
			"inside a function",
			`let reopen = fn(path) {
    return case_key_open(path, {"passphrase": "hunter2"});
};`,
			"`case_key_open` refuses an option named \"passphrase\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caseRuleMessages(t, "secretOption", tc.src+"\n", DefaultLintConfig())
			if len(got) != 1 || !strings.HasPrefix(got[0], tc.want) {
				t.Fatalf("got %q, want one message starting %q", got, tc.want)
			}
			if !strings.HasSuffix(got[0], "It is asked for at the terminal.") {
				t.Errorf("the message does not end with the run time's sentence: %q", got[0])
			}
		})
	}
}

// One report per call, at the first secret written: the run time refuses the
// call at whichever it meets first.
func TestSecretOptionReportsTheFirstSecretWritten(t *testing.T) {
	src := `record_open("exhibit.mrec", {"view": "counsel", "password": p, "passphrase": q});` + "\n"
	snapshot := New().Analyze(src)
	var found int
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if !strings.Contains(d.Message, caseRuleMarkers["secretOption"]) {
			continue
		}
		found++
		if !strings.Contains(d.Message, `"password"`) {
			t.Errorf("reported %q, want the first secret written, \"password\"", d.Message)
		}
		if start := int(d.Range.Start.Character); src[start:start+len(`"password"`)] != `"password"` {
			t.Errorf("the report starts at column %d, not at the key", start)
		}
	}
	if found != 1 {
		t.Fatalf("got %d reports for one call, want 1", found)
	}
}

// The names are matched exactly and only where the run time looks for them: at
// the top of the options hash of a builtin that refuses one.
func TestSecretOptionIsSilentWhereTheRunTimeDoesNotRefuse(t *testing.T) {
	sources := []string{
		// Not a secret's name, as the run time spells them.
		`record_open("exhibit.mrec", {"Passphrase": "hunter2"});`,
		`record_open("exhibit.mrec", {"view": "counsel"});`,
		// A builtin that does not refuse one.
		`csv_parse(data, {"password": "hunter2"});`,
		// Not the options hash: record_open's first argument is its path.
		`record_open({"passphrase": "hunter2"});`,
		// Deeper than the run time looks.
		`case_write("manifest.json", {"sign": {"passphrase": "hunter2"}});`,
		// A key that is not a literal is a key this cannot know.
		`record_open("exhibit.mrec", {name: "hunter2"});`,
		// A name bound twice holds whichever hash was bound last.
		"let opts = {\"passphrase\": \"hunter2\"};\nopts = {};\nrecord_open(\"exhibit.mrec\", opts);",
		// A call the signature does not fit is the arity rule's.
		`record_open("exhibit.mrec", {"passphrase": "hunter2"}, 3);`,
		// A shadowed name is not the builtin.
		"let record_open = fn(path, opts) { opts };\nrecord_open(\"exhibit.mrec\", {\"passphrase\": \"hunter2\"});",
	}
	for _, src := range sources {
		if got := caseRuleMessages(t, "secretOption", src+"\n", DefaultLintConfig()); len(got) != 0 {
			t.Errorf("%s: got %q, want no secretOption report", src, got)
		}
	}
}
