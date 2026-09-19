package analyzer

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// withHostGOOS temporarily overrides the simulated host OS for a test.
func withHostGOOS(t *testing.T, goos string) {
	t.Helper()
	previous := hostGOOS
	hostGOOS = goos
	t.Cleanup(func() { hostGOOS = previous })
}

func messagesContaining(diags []struct {
	source, message string
}, substr string) int {
	count := 0
	for _, d := range diags {
		if strings.Contains(d.message, substr) {
			count++
		}
	}
	return count
}

// collectMessages flattens diagnostics into (source,message) pairs for assertions.
func collectMessages(src string) []struct{ source, message string } {
	snapshot := New().Analyze(src)
	raw := Diagnostics(snapshot, DefaultLintConfig())
	out := make([]struct{ source, message string }, 0, len(raw))
	for _, d := range raw {
		source := ""
		if d.Source != nil {
			source = *d.Source
		}
		out = append(out, struct{ source, message string }{source: source, message: d.Message})
	}
	return out
}

func TestPlatformSupportDiagnosticFiresOnUnsupportedHost(t *testing.T) {
	// process_modules is Windows/Linux only. On macOS the LSP should warn.
	withHostGOOS(t, "darwin")
	msgs := collectMessages("let mods, err = process_modules(1);\n")

	found := false
	for _, m := range msgs {
		if strings.Contains(m.message, "process_modules") && strings.Contains(m.message, "not supported on darwin") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a platform-support warning for process_modules on darwin, got %+v", msgs)
	}
}

func TestPlatformSupportDiagnosticSilentOnSupportedHost(t *testing.T) {
	withHostGOOS(t, "windows")
	msgs := collectMessages("let mods, err = process_modules(1);\n")

	for _, m := range msgs {
		if strings.Contains(m.message, "not supported on") {
			t.Fatalf("did not expect a platform-support warning on windows, got %q", m.message)
		}
	}
}

func TestPlatformSupportDiagnosticSilentForCrossPlatformBuiltin(t *testing.T) {
	withHostGOOS(t, "darwin")
	// fs_read works everywhere; no platform warning regardless of host.
	msgs := collectMessages("let data, err = fs_read(\"/tmp/x\");\n")
	for _, m := range msgs {
		if strings.Contains(m.message, "not supported on") {
			t.Fatalf("did not expect a platform-support warning for fs_read, got %q", m.message)
		}
	}
}

func TestUnreachableCodeAfterReturn(t *testing.T) {
	src := "let f = fn() {\n    return 1;\n    let dead = 2;\n    return dead;\n};\n"
	msgs := collectMessages(src)
	if messagesContaining(msgs, "unreachable code after `return`") == 0 {
		t.Fatalf("expected an unreachable-code diagnostic after return, got %+v", msgs)
	}
}

func TestNoUnreachableCodeForNormalFlow(t *testing.T) {
	src := "let f = fn(x) {\n    let y = x + 1;\n    return y;\n};\n"
	msgs := collectMessages(src)
	if messagesContaining(msgs, "unreachable code") != 0 {
		t.Fatalf("did not expect unreachable-code diagnostics, got %+v", msgs)
	}
}

func TestUnderscoreDiscardIsNotDuplicate(t *testing.T) {
	// `_` is the discard identifier and may be bound repeatedly (e.g. the error
	// half of several `let value, _ = ...` pairs) without being a duplicate.
	src := "let a, _ = fs_read(\"x\");\nlet b, _ = fs_read(\"y\");\nputln(a, b);\n"
	for _, m := range collectMessages(src) {
		if strings.Contains(m.message, "duplicate") && strings.Contains(m.message, "`_`") {
			t.Fatalf("`_` should not be flagged as a duplicate declaration, got %q", m.message)
		}
	}
}

func TestHoverShowsCapabilityCategory(t *testing.T) {
	hover, ok := builtinHoverText("fs_read")
	if !ok {
		t.Fatalf("fs_read missing hover")
	}
	if !strings.Contains(hover, "_Category: filesystem_") {
		t.Fatalf("fs_read hover missing category, got %q", hover)
	}
}

func TestHoverShowsPlatformConstraint(t *testing.T) {
	hover, ok := builtinHoverText("process_modules")
	if !ok {
		t.Fatalf("process_modules missing hover")
	}
	if !strings.Contains(hover, "Platforms:") || !strings.Contains(hover, "windows") {
		t.Fatalf("process_modules hover missing platform constraint, got %q", hover)
	}
}

// The platform rule decides shadowing the way the build does.
//
// It used to see only the file's imports, which is not what the rule needed to
// know: `process.modules(1)` is a call to the builtin only when nothing in the
// file has bound `process`, and a let or a parameter binds it just as an import
// does. So a program that never touched process_modules was told it would not
// run on this machine -- a warning about portability, which is exactly the kind
// an author acts on, pointing at a function the program does not call.
//
// darwin is simulated because the assertion has to mean the same thing wherever
// the suite runs.
func TestPlatformSupportIsSilentWhenTheFamilyNameIsBound(t *testing.T) {
	withHostGOOS(t, "darwin")

	for _, c := range []struct{ name, src string }{
		{
			name: "a let holds a struct",
			src: "struct Holder { modules };\n" +
				"let process = Holder{modules: 7};\n" +
				"process.modules(1);\n",
		},
		{
			name: "a parameter holds one",
			src:  "let take = fn(process) { return process.modules(1); };\n",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if n := messagesContaining(collectMessages(c.src), "not supported on darwin"); n != 0 {
				t.Fatalf("a field read on a value the file bound was reported as a call to "+
					"process_modules:\n\n%s", c.src)
			}
		})
	}
}

// And the other direction, which is the one a filter would get wrong: a struct
// TYPE named after the family shadows nothing. A type name never enters the
// compiler's symbol table, so the build folds `process.modules` to the builtin
// and runs it -- or refuses to, on a platform that does not have it, which is
// precisely what this rule exists to say first.
func TestPlatformSupportStillFiresWhenAStructCarriesTheFamilyName(t *testing.T) {
	withHostGOOS(t, "darwin")

	const src = "struct process { modules };\nprocess.modules(1);\n"
	if n := messagesContaining(collectMessages(src), "not supported on darwin"); n == 0 {
		t.Fatalf("no platform warning for a call the build compiles as process_modules:\n\n%s", src)
	}
}

func TestCompletionDetailCarriesCategory(t *testing.T) {
	snapshot := New().Analyze("")
	items := snapshot.CompletionItemsAt(lsp.Position{Line: 0, Character: 0})
	for _, item := range items {
		if item.Label == "db_open" {
			if item.Detail == nil || !strings.Contains(*item.Detail, "graph database") {
				t.Fatalf("db_open completion detail = %v, want it to name the graph database category", item.Detail)
			}
			return
		}
	}
	t.Fatalf("db_open not found among completion items")
}
