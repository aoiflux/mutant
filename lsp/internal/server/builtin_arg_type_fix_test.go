package server

import (
	"encoding/json"
	"strings"
	"testing"

	"mutant/lsp/internal/analyzer"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// argTypeDiagnostic builds the diagnostic the analyzer publishes for an
// argument of the wrong kind, covering the given range.
func argTypeDiagnostic(want, got string, rng lsp.Range) lsp.Diagnostic {
	source := "mutant-lint"
	severity := lsp.DiagnosticSeverityWarning
	return lsp.Diagnostic{
		Range:    rng,
		Severity: &severity,
		Source:   &source,
		Message:  "argument 1 to `str_upper` must be " + want + ", got " + got,
		Data: map[string]any{
			"rule": analyzer.ArgTypeDiagnosticRule,
			"want": want,
			"got":  got,
		},
	}
}

func spanOnFirstLine(startChar, endChar int) lsp.Range {
	return lsp.Range{
		Start: lsp.Position{Line: 0, Character: lsp.UInteger(startChar)},
		End:   lsp.Position{Line: 0, Character: lsp.UInteger(endChar)},
	}
}

// TestBuiltinArgTypeQuickFixWrapsArgument checks the offered edit actually
// produces `to_string(42)` — two zero-width inserts that bracket the argument,
// rather than a replacement that would have to reproduce its text.
func TestBuiltinArgTypeQuickFixWrapsArgument(t *testing.T) {
	const uri = lsp.DocumentUri("file:///fix.mut")
	// putln(str_upper(42));
	//                 ^^ argument at characters 16..18
	rng := spanOnFirstLine(16, 18)

	actions := quickFixesForBuiltinArgType(uri, argTypeDiagnostic("STRING", "INTEGER", rng))
	if len(actions) != 1 {
		t.Fatalf("expected exactly one quick fix, got %d", len(actions))
	}

	action := actions[0]
	if !strings.Contains(action.Title, "to_string") {
		t.Errorf("title %q does not name the conversion", action.Title)
	}
	if action.Edit == nil {
		t.Fatal("quick fix carries no edit")
	}

	edits := action.Edit.Changes[uri]
	if len(edits) != 2 {
		t.Fatalf("expected two edits (open and close), got %d", len(edits))
	}

	open, closing := edits[0], edits[1]
	if open.NewText != "to_string(" || open.Range.Start != rng.Start || open.Range.End != rng.Start {
		t.Errorf("opening edit should insert %q at the argument start, got %q at %+v", "to_string(", open.NewText, open.Range)
	}
	if closing.NewText != ")" || closing.Range.Start != rng.End || closing.Range.End != rng.End {
		t.Errorf("closing edit should insert %q at the argument end, got %q at %+v", ")", closing.NewText, closing.Range)
	}
}

// TestBuiltinArgTypeQuickFixDeclinesUnsafeConversions is the important half.
//
// to_int, to_float and to_bool all return a (value, err) MULTI_VALUE, so
// wrapping an argument in one produces code that fails at run time with
// "must be INTEGER, got MULTI_VALUE". A fix that turns a warning into a runtime
// error is worse than no fix, so nothing is offered when STRING is not among
// the accepted kinds.
func TestBuiltinArgTypeQuickFixDeclinesUnsafeConversions(t *testing.T) {
	const uri = lsp.DocumentUri("file:///fix.mut")
	rng := spanOnFirstLine(16, 19)

	for _, tc := range []struct {
		name string
		want string
		got  string
		why  string
	}{
		{"integer wanted", "INTEGER", "STRING", "to_int returns a (value, err) pair that cannot be nested"},
		{"float wanted", "FLOAT", "STRING", "to_float returns a (value, err) pair that cannot be nested"},
		{"boolean wanted", "BOOLEAN", "STRING", "to_bool returns a (value, err) pair that cannot be nested"},
		{"numeric union wanted", "INTEGER|FLOAT", "STRING", "neither conversion returns a bare value"},
		{"array argument", "STRING", "ARRAY", "to_string would stringify the debug rendering of a collection"},
		{"hash argument", "STRING", "HASH", "to_string would stringify the debug rendering of a collection"},
		{"function argument", "STRING", "FUNCTION", "a function has no meaningful string form"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if actions := quickFixesForBuiltinArgType(uri, argTypeDiagnostic(tc.want, tc.got, rng)); len(actions) != 0 {
				t.Errorf("offered %d fixes for want=%s got=%s, but %s", len(actions), tc.want, tc.got, tc.why)
			}
		})
	}
}

// TestBuiltinArgTypeQuickFixOffersOnUnionContainingString covers the shape that
// makes re-deriving from Data worthwhile: a parameter such as len's accepts
// several kinds, and the fix has to see STRING among them.
func TestBuiltinArgTypeQuickFixOffersOnUnionContainingString(t *testing.T) {
	const uri = lsp.DocumentUri("file:///fix.mut")
	rng := spanOnFirstLine(10, 14)

	if actions := quickFixesForBuiltinArgType(uri, argTypeDiagnostic("STRING|ARRAY|HASH", "BOOLEAN", rng)); len(actions) != 1 {
		t.Fatalf("expected one fix for a union that accepts STRING, got %d", len(actions))
	}
}

// TestBuiltinArgTypeQuickFixIgnoresForeignDiagnostics keeps the provider from
// firing on anything that is not its own payload.
func TestBuiltinArgTypeQuickFixIgnoresForeignDiagnostics(t *testing.T) {
	const uri = lsp.DocumentUri("file:///fix.mut")
	rng := spanOnFirstLine(0, 4)

	for name, data := range map[string]any{
		"no data":          nil,
		"other rule":       map[string]any{"rule": "builtinArity", "want": "STRING", "got": "INTEGER"},
		"not a map":        "builtinArgType",
		"missing want":     map[string]any{"rule": analyzer.ArgTypeDiagnosticRule, "got": "INTEGER"},
		"missing got":      map[string]any{"rule": analyzer.ArgTypeDiagnosticRule, "want": "STRING"},
		"empty kind entry": map[string]any{"rule": analyzer.ArgTypeDiagnosticRule, "want": "STRING|", "got": "INTEGER"},
	} {
		t.Run(name, func(t *testing.T) {
			diagnostic := argTypeDiagnostic("STRING", "INTEGER", rng)
			diagnostic.Data = data
			if actions := quickFixesForBuiltinArgType(uri, diagnostic); len(actions) != 0 {
				t.Errorf("offered a fix for %s", name)
			}
		})
	}
}

// TestArgTypeDiagnosticDataSurvivesJSON is the reason every value in the
// payload is a string.
//
// Diagnostic.Data is carried to the client in publishDiagnostics and handed
// back in the codeAction request, so the provider never sees the map the
// analyzer built — it sees whatever survived encoding. A number would come back
// as a float64 and a struct as a map, either of which would make the in-process
// tests above pass while the real editor path returned nothing.
func TestArgTypeDiagnosticDataSurvivesJSON(t *testing.T) {
	const uri = lsp.DocumentUri("file:///fix.mut")
	rng := spanOnFirstLine(16, 18)
	original := argTypeDiagnostic("STRING|ARRAY|HASH", "INTEGER", rng)

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshalling the diagnostic: %v", err)
	}
	var roundTripped lsp.Diagnostic
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("unmarshalling the diagnostic: %v", err)
	}

	actions := quickFixesForBuiltinArgType(uri, roundTripped)
	if len(actions) != 1 {
		t.Fatalf("expected one quick fix after a JSON round trip, got %d", len(actions))
	}
	if edits := actions[0].Edit.Changes[uri]; len(edits) != 2 {
		t.Fatalf("expected two edits after a JSON round trip, got %d", len(edits))
	}
}
