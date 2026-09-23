package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// classifiedDiagnostics returns every classifiedPlaintext diagnostic in src.
// Its one message says "refuses classified plaintext".
func classifiedDiagnostics(t *testing.T, src string, config LintConfig) []lsp.Diagnostic {
	t.Helper()

	snapshot := New().Analyze(src)
	var out []lsp.Diagnostic
	for _, d := range Diagnostics(snapshot, config) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "refuses classified plaintext") {
			out = append(out, d)
		}
	}
	return out
}

func TestClassifiedPlaintextFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a read handed straight to putln",
			`putln(record_read(r, 0, 4));`,
			"`putln` refuses classified plaintext, and argument 1 holds the plaintext `record_read` read out of a classified record",
		},
		{
			"a read held in a name, written to a file",
			`let address, err = record_read(r, 551, 19);
let _, werr = fs_write("address.txt", address);`,
			"`fs_write` refuses classified plaintext, and argument 2 holds `address`, the plaintext `record_read`",
		},
		{
			// bytes_slice carries the mark to the slice, so the slice is as
			// refused as the buffer it came from.
			"a slice of a read",
			`let address, err = record_read(r, 551, 19);
let part, serr = bytes_slice(address, 0, 7);
putln(part);`,
			"`putln` refuses classified plaintext, and argument 1 holds `part`, the plaintext `record_read`",
		},
		{
			"the bytes of a partial read, posted",
			`let whole, err = record_read_partial(r, 0, 1471);
let _, perr = http_post("http://127.0.0.1/", whole["bytes"]);`,
			"`http_post` refuses classified plaintext, and argument 2 holds the plaintext `record_read_partial`",
		},
		{
			// The run time looks inside containers, so a literal holding the
			// buffer is refused as surely as the buffer.
			"a read inside a hash literal",
			`let address, err = record_read(r, 551, 19);
case_note("the victim", {"address": address});`,
			"`case_note` refuses classified plaintext, and argument 2 holds a hash holding the plaintext `record_read`",
		},
		{
			"a read inside an array literal",
			`let address, err = record_read(r, 551, 19);
putln(["address:", address]);`,
			"argument 1 holds an array holding the plaintext `record_read`",
		},
		{
			"a read inside a function",
			`let dump = fn(r) {
    let secret, err = record_read(r, 0, 16);
    let _, werr = fs_append("dump.bin", secret);
};`,
			"`fs_append` refuses classified plaintext, and argument 2 holds `secret`",
		},
		{
			// The whole partial result is a hash holding the marked buffer.
			"a partial read's whole hash",
			`let whole, err = record_read_partial(r, 0, 1471);
let _, lerr = ledger_add_node(ledger, whole);`,
			"`ledger_add_node` refuses classified plaintext, and argument 2 holds `whole`, the plaintext `record_read_partial`",
		},
		{
			"a read inside a struct literal",
			`struct Finding { address; }
let address, err = record_read(r, 551, 19);
putln(Finding { address: address });`,
			"argument 1 holds a struct holding the plaintext `record_read`",
		},
		{
			// The run time refuses at the first argument holding any, so there
			// is one report per call, and it names that argument.
			"the plaintext in two arguments",
			`let address, err = record_read(r, 551, 19);
putln("address:", address, address);`,
			"argument 2 holds `address`",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifiedDiagnostics(t, tc.src, DefaultLintConfig())
			if len(got) != 1 {
				t.Fatalf("got %d classifiedPlaintext diagnostics, want 1: %v", len(got), got)
			}
			if !strings.Contains(got[0].Message, tc.want) {
				t.Errorf("message\n  %s\ndoes not contain\n  %s", got[0].Message, tc.want)
			}
			if !strings.Contains(got[0].Message, "`record_release(buffer, reason)`") {
				t.Errorf("the message does not name the way to comply: %s", got[0].Message)
			}
		})
	}
}

func TestClassifiedPlaintextStaysQuiet(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// The way to comply: the release is recorded, and its result is not
			// marked.
			"a released copy",
			`let address, err = record_read(r, 551, 19);
let released, lerr = record_release(address, "the complainant's own address");
let _, werr = fs_write("address.txt", released);`,
		},
		{
			"a name given a second value",
			`let address, err = record_read(r, 551, 19);
address = "redacted";
putln(address);`,
		},
		{
			"a name bound twice",
			`let address, err = record_read(r, 551, 19);
let address = "redacted";
putln(address);`,
		},
		{
			// One byte of a buffer is an integer and carries nothing.
			"an index into a read",
			`let address, err = record_read(r, 551, 19);
putln(address[0]);`,
		},
		{
			"the holes of a partial read",
			`let whole, err = record_read_partial(r, 0, 1471);
putln(whole["holes"]);`,
		},
		{
			// Only record_read_partial's hash keeps the buffer under `bytes`. The
			// same key on any other hash is whatever that hash put there.
			"the bytes entry of a hash that is not a partial read",
			`let address, err = record_read(r, 551, 19);
let entry = {"bytes": 19, "raw": address};
putln(entry["bytes"]);`,
		},
		{
			"a read that is not handed to a sink",
			`let address, err = record_read(r, 551, 19);
let n = len(address);
putln(n);`,
		},
		{
			"a user function's result",
			`let read = fn(r) {
    let b, err = record_read(r, 0, 4);
    return b;
};
putln(read(r));`,
		},
		{
			"a shadowed record_read",
			`let record_read = fn(r, o, l) { return "nothing"; };
putln(record_read(r, 0, 4));`,
		},
		{
			"a shadowed sink",
			`let fs_write = fn(p, v) { return true; };
let address, err = record_read(r, 551, 19);
fs_write("address.txt", address);`,
		},
		{
			// `a + b` carries the mark only when both sides are buffers, which
			// the rule cannot know, so it says nothing.
			"a concatenation",
			`let address, err = record_read(r, 551, 19);
putln(address + other);`,
		},
		{
			// A name from an enclosing scope is not followed into a function.
			"a read captured by a function",
			`let address, err = record_read(r, 551, 19);
let show = fn() { putln(address); };`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifiedDiagnostics(t, tc.src, DefaultLintConfig()); len(got) != 0 {
				t.Errorf("got %d classifiedPlaintext diagnostics, want none: %v", len(got), got)
			}
		})
	}
}

func TestClassifiedPlaintextCanBeTurnedOff(t *testing.T) {
	config := DefaultLintConfig()
	config.ClassifiedPlaintext = LintSeverityOff
	if got := classifiedDiagnostics(t, `putln(record_read(r, 0, 4));`, config); len(got) != 0 {
		t.Errorf("an 'off' rule reported %d diagnostics", len(got))
	}
}

// The record_disclosure example writes the address out once on purpose, to
// show the run time refusing it. The editor has to flag exactly that line --
// and nothing else in a program that reads, releases and discloses plaintext
// all the way through.
func TestTheDisclosureExampleIsFlaggedWhereItMeansToBeRefused(t *testing.T) {
	path := filepath.Join("..", "..", "..", "examples", "forensics", "record_disclosure.mut")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)

	got := classifiedDiagnostics(t, src, DefaultLintConfig())
	if len(got) != 1 {
		t.Fatalf("got %d classifiedPlaintext diagnostics in the example, want 1: %v", len(got), got)
	}

	const refused = `fs_write(output_directory + "/address.txt", address)`
	want := -1
	for i, line := range strings.Split(src, "\n") {
		if strings.Contains(line, refused) {
			want = i
			break
		}
	}
	if want < 0 {
		t.Fatalf("the example no longer contains %q", refused)
	}
	if int(got[0].Range.Start.Line) != want {
		t.Errorf("the diagnostic is on line %d, want %d (the deliberate fs_write): %s",
			got[0].Range.Start.Line+1, want+1, got[0].Message)
	}
}
