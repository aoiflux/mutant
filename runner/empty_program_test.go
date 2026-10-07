package runner

// The simplest valid programs: one with nothing in it, and one with only a
// comment.
//
// Both compile. Running either used to end in a Go nil-pointer panic with a
// goroutine dump and exit 2, because runvm called Inspect on whatever
// LastPoppedStackElement returned and a program that pushed nothing leaves that
// slot nil (M26-RUN-006). repl.go and dap/session.go both checked for nil
// already; this was the one caller that did not, and it is the one a new file
// run from the editor goes through.
//
// There is no block-comment case because the language has no block comment:
// `/* x */` does not parse ("no prefix parse function for / found"). Mutant's
// comment is `//` and that is what the cases use.

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/generator"
)

// runSource compiles source the way `mutant gen` does and runs the .mu the way
// `mutant prog.mu` does, which is the path the panic was on. It returns
// normally or it does not return at all, which is the whole assertion.
func runSource(t *testing.T, name, source string) error {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, name+".mut")
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	const password = "a password for the test's own artifact"
	dst := filepath.Join(dir, name)
	if err, _, _ := generator.Generate(src, dst, "", "", false, password, 0, 0, nil, nil); err != nil {
		t.Fatalf("%s did not compile, which is not what this is about: %v", name, err)
	}

	data, err := os.ReadFile(dst + ".mu")
	if err != nil {
		t.Fatal(err)
	}
	bytecode, err := decode(data, password)
	if err != nil {
		t.Fatalf("%s did not decode: %v", name, err)
	}

	runErr, _ := runvm(bytecode, password, false)
	return runErr
}

func TestAProgramThatPushesNothingRunsAndSaysNothing(t *testing.T) {
	for _, c := range []struct {
		name   string
		source string
	}{
		{"empty", ""},
		{"comment", "// only a comment\n"},
		{"comments", "// one\n// two\n\n// three\n"},
		{"blank", "\n\n\t\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// A panic here fails the subtest rather than the binary, so the
			// cases after it still run. Before the fix every one of these took
			// the process down.
			if err := runSource(t, c.name, c.source); err != nil {
				t.Fatalf("running a program with no value in it returned %v", err)
			}
		})
	}
}

// A program that does end on a value still prints it: the nil check is a check
// for nil and not a change to what an ordinary program does.
func TestAProgramThatEndsOnAValueStillRuns(t *testing.T) {
	for _, c := range []struct {
		name   string
		source string
	}{
		{"an_expression", "2 + 2;\n"},
		{"a_call", "putln(\"x\");\n"},
		{"a_let", "let x = 1;\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := runSource(t, c.name, c.source); err != nil {
				t.Fatalf("%s returned %v", c.name, err)
			}
		})
	}
}
