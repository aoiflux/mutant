package analyzer

import (
	"strings"
	"testing"
)

func TestFilteredLedgerHandleFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a handle under a view, written into",
			`let under, err = ledger_under_view(ledger, "counsel");
let id, aerr = ledger_add_node(under["handle"], {"finding": "x"});`,
			"`ledger_add_node` does not read under a view, and argument 1 is a handle `ledger_under_view` " +
				"returned, so the call is refused when it runs.",
		},
		{
			"a read that does not read under a view",
			`let under, err = ledger_under_view(ledger, "counsel");
let handle = under["handle"];
let stats, serr = ledger_stats(handle);`,
			"`ledger_stats` does not read under a view",
		},
		{
			"the call's result indexed where it is made",
			`let stats, err = ledger_stats(ledger_under_view(ledger, "counsel")["handle"]);`,
			"`ledger_stats` does not read under a view",
		},
		{
			"a disclosure made through one",
			`let under, err = ledger_under_view(ledger, "counsel");
disclose_to_passphrase(under["handle"], record, "counsel", "counsel@example.org");`,
			"`disclose_to_passphrase` does not read under a view",
		},
		{
			"inside a callback, as the disclosure example reads a ledger",
			`each(["counsel"], fn(view) {
    let under, err = ledger_under_view(ledger, view);
    ledger_compact(under["handle"]);
});`,
			"`ledger_compact` does not read under a view",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := caseRuleMessages(t, "filteredLedgerHandle", tc.src+"\n", DefaultLintConfig())
			if len(got) != 1 || !strings.HasPrefix(got[0], tc.want) {
				t.Fatalf("got %q, want one message starting %q", got, tc.want)
			}
			// It says what does read through one, and what to pass instead.
			for _, part := range []string{"Only ledger_node, ledger_edge,", "`ledger_close` drops it",
				"Pass the ledger's own handle"} {
				if !strings.Contains(got[0], part) {
					t.Errorf("the message does not say %q: %q", part, got[0])
				}
			}
		})
	}
}

func TestFilteredLedgerHandleIsSilentWhereTheRunTimeAccepts(t *testing.T) {
	under := "let under, err = ledger_under_view(ledger, \"counsel\");\n"
	sources := []string{
		// The reads that read under a view, and ledger_close.
		under + `let node, nerr = ledger_node(under["handle"], 7);`,
		under + `let shown, qerr = ledger_query_nodes(under["handle"], {"types": [1]});`,
		under + `let walked, perr = ledger_provenance(under["handle"], 7, 4);`,
		under + `ledger_close(under["handle"]);`,
		// The ledger's own handle, the result's other fields, and the handle
		// ledger_open returns, which is the ledger's own.
		under + `ledger_add_node(ledger, {"finding": "x"});`,
		under + `ledger_stats(under["ledger"]);`,
		"let opened, err = ledger_open(\"ledger\", \"examiner\");\nledger_stats(opened[\"handle\"]);",
		// Names bound more than once, and a handle a function hands back.
		"let under, err = ledger_under_view(ledger, \"counsel\");\nunder = ledger_open(\"l\", \"e\");\nledger_stats(under[\"handle\"]);",
		under + "let h = under[\"handle\"];\nh = ledger;\nledger_stats(h);",
		under + "let pick = fn(u) { u[\"handle\"] };\nledger_stats(pick(under));",
		// A shadowed name is not the builtin.
		"let ledger_under_view = fn(l, v) { {\"handle\": l} };\nlet under = ledger_under_view(ledger, \"counsel\");\nledger_stats(under[\"handle\"]);",
		// A call the signature does not fit is the arity rule's.
		under + `ledger_stats(under["handle"], 2);`,
	}
	for _, src := range sources {
		if got := caseRuleMessages(t, "filteredLedgerHandle", src+"\n", DefaultLintConfig()); len(got) != 0 {
			t.Errorf("%s: got %q, want no filteredLedgerHandle report", src, got)
		}
	}
}
