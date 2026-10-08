package main

import (
	"os"
	"strings"
	"testing"
)

// brokenBanner is the file M26-TOOL-014 was reported against: a triple-quoted
// literal whose first row ends in three spaces, and one line below it that
// does not parse.
//
// The three spaces are the whole point, so they are written as \x20 rather
// than typed -- no editor, formatter or trailing-whitespace hook can quietly
// remove the thing under test.
const (
	bannerRowOne  = "row one\x20\x20\x20"
	brokenBanner  = "let banner = \"\"\"\n" + bannerRowOne + "\nrow two\n\"\"\";\nputln(len(banner));\nlet broken = ;\n"
	parsingBanner = "let banner = \"\"\"\n" + bannerRowOne + "\nrow two\n\"\"\";\nputln(len(banner));\n"
)

// TestFmtRefusesAFileWithParseErrors is M26-TOOL-014.
//
// `mutant fmt` wrote the formatter's whitespace-only fallback over any file
// that failed to parse, printed "formatted:" and exited 0. With no tree, that
// fallback could not tell a line of code from a line inside a triple-quoted
// string, so the banner lost the three spaces at the end of its first row: a
// silent edit to string data, in the one case the tool had already failed to
// understand the file.
//
// All three modes are checked, because all three were wrong and only one of
// them was obviously so. `--check` already exited 1, but for the wrong
// reason -- it was reporting a whitespace diff it had invented against a file
// it could not format -- and `--stdout` printed that same invented text and
// exited 0.
func TestFmtRefusesAFileWithParseErrors(t *testing.T) {
	for _, mode := range []struct {
		name string
		args []string
	}{
		{"in place", nil},
		{"--check", []string{"--check"}},
		{"--stdout", []string{"--stdout"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			path := writeTemp(t, "badfmt.mut", brokenBanner)
			args := append(append([]string{"mutant", "fmt"}, mode.args...), path)

			var code int
			var stdout string
			stderr := captureStderr(t, func() {
				stdout = captureStdout(t, func() { code = handleFmtCommand(args) })
			})

			if code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != brokenBanner {
				t.Errorf("the file was rewritten:\n got %q\nwant %q", string(after), brokenBanner)
			}

			// The refusal says which file and why, in `mutant lint`'s shape.
			if !strings.Contains(stderr, "does not parse; left unchanged") {
				t.Errorf("stderr does not refuse the file:\n%s", stderr)
			}
			if !strings.Contains(stderr, "[mutant-parser]") {
				t.Errorf("stderr does not report the parse error:\n%s", stderr)
			}

			// None of the three may claim to have done anything.
			for _, claim := range []string{"formatted:", "would reformat:"} {
				if strings.Contains(stdout+stderr, claim) {
					t.Errorf("output claims %q for a file that does not parse:\nstdout:\n%s\nstderr:\n%s", claim, stdout, stderr)
				}
			}
			if strings.Contains(stdout, "row one") {
				t.Errorf("a refused file's contents were printed to stdout:\n%s", stdout)
			}
		})
	}
}

// TestFmtStillFormatsTheSameFileOnceItParses is the control. The defect was
// never in the printer: the identical banner, in a file with nothing wrong
// with it, keeps its trailing spaces and the command succeeds.
func TestFmtStillFormatsTheSameFileOnceItParses(t *testing.T) {
	path := writeTemp(t, "goodfmt.mut", parsingBanner)

	if code := handleFmtCommand([]string{"mutant", "fmt", path}); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), bannerRowOne) {
		t.Fatalf("fmt edited the inside of a string literal:\n%q", string(after))
	}
}
