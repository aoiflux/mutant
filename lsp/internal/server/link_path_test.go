package server

// M26-LSP-002: a string literal in a document could send the language server
// to the network, or at a device, from the goroutine that reads the client's
// messages.
//
// The hard part of this row is the assertion. At HEAD the UNC case ALREADY
// returns zero links -- it returns them after the network has timed out, and a
// count cannot see a delay. Measured on the host this was written on: a bare
// os.Stat of a UNC path that does not resolve took 5.5 s, and 42 s through the
// handler, while every other editor request waited. "No links" is therefore
// not evidence of anything, and timing is not an assertion.
//
// So the fix is shaped to be observable. linkCandidate decides without
// touching the filesystem, which makes a refusal testable with no I/O at all,
// and statInRoot is a variable, which makes "the filesystem was never asked"
// something a test can state rather than infer. Those two are what is checked
// here.

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

// bs is a single backslash, built from its code point so that no editor,
// patch tool or shell between here and the file can halve it.
var bs = string(rune(92))

func TestLinkCandidateRefusesWhatReachesTheNetworkOrADevice(t *testing.T) {
	// Every one of these is a literal a document may contain, and every one of
	// them is refused with no syscall. The list is not a denylist the fix
	// consults -- filepath.IsLocal is -- it is the evidence that the allowlist
	// covers the cases a denylist would have had to enumerate.
	docDir := filepath.Join(t.TempDir(), "case")
	roots := []string{docDir}

	unc := bs + bs + "host" + bs + "share" + bs + "secret.img"
	for _, value := range []string{
		unc,                                   // the row's case
		"//host/share/secret.img",             // the same, in the other slash
		bs + bs + "?" + bs + "C:" + bs + "x",  // the \\?\ device prefix
		bs + bs + "." + bs + "PhysicalDrive0", // a raw device
		bs + "??" + bs + "UNC" + bs + "host" + bs + "s", // the NT object path
		"C:" + bs + "Windows" + bs + "win.ini",          // an absolute path outside any root
		"/etc/shadow",                                   // the same on POSIX
		"C:x",                                           // drive-relative: another drive's cwd
		"secret.img:hidden",                             // an alternate data stream
		"../../../../Windows/win.ini",                   // traversal out of every root
		"..",                                            // the shortest traversal
		"",                                              // empty
		"with" + string(rune(0)) + "nul",                // an embedded NUL
		"two" + string(rune(10)) + "lines",              // an embedded newline
	} {
		if _, ok := linkCandidate(docDir, roots, value); ok {
			t.Errorf("linkCandidate allowed %q; a document chooses this string, so it must be "+
				"decided before anything is asked of the filesystem", value)
		}
	}
}

func TestLinkCandidateAllowsAnOrdinaryPath(t *testing.T) {
	// The false-refusal guard. A rule that refused everything would pass the
	// test above and silently delete the feature.
	base := t.TempDir()
	docDir := filepath.Join(base, "case", "notes")
	roots := []string{docDir, filepath.Join(base, "case")}

	for _, tt := range []struct {
		value string
		root  string
		rel   string
	}{
		{"data.bin", docDir, "data.bin"},
		{"./data.bin", docDir, "data.bin"},
		{"sub/data.bin", docDir, filepath.Join("sub", "data.bin")},
		// Up and back down, which is how an examiner refers to an image from a
		// notes file -- allowed because the case directory is a root.
		{"../evidence/usb.img", filepath.Join(base, "case"), filepath.Join("evidence", "usb.img")},
	} {
		got, ok := linkCandidate(docDir, roots, tt.value)
		if !ok {
			t.Errorf("linkCandidate refused %q, which names a file inside a chosen root", tt.value)
			continue
		}
		if got.rel != tt.rel {
			t.Errorf("linkCandidate(%q).rel = %q, want %q", tt.value, got.rel, tt.rel)
		}
		if filepath.Clean(got.root) != filepath.Clean(tt.root) {
			t.Errorf("linkCandidate(%q).root = %q, want %q", tt.value, got.root, tt.root)
		}
		if !filepath.IsLocal(got.rel) {
			t.Errorf("linkCandidate(%q).rel = %q, which is not local; os.Root is entitled to refuse it",
				tt.value, got.rel)
		}
	}
}

// statCounter replaces statInRoot for one test and records what it was asked.
func statCounter(t *testing.T) *[]string {
	t.Helper()
	asked := []string{}
	previous := statInRoot
	statInRoot = func(root *os.Root, name string) (fs.FileInfo, error) {
		asked = append(asked, name)
		return previous(root, name)
	}
	t.Cleanup(func() { statInRoot = previous })
	return &asked
}

func TestARefusedLiteralIsNeverHandedToTheFilesystem(t *testing.T) {
	// This is the row's real assertion. No test can watch the wire, and a link
	// count cannot see a 42-second delay, but "the filesystem was never asked"
	// is exactly what has to be true for the stall to be impossible.
	dir := t.TempDir()
	unc := bs + bs + "host" + bs + "share" + bs + "secret.img"
	src := "let a = fs_read(" + quote(unc) + ");\n" +
		"let b = fs_read(" + quote("//host/share/secret.img") + ");\n" +
		"let c = fs_read(" + quote("data.bin") + ");\n"
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	docPath := filepath.Join(dir, "prog.mut")
	if err := os.WriteFile(docPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(false)
	initializeServer(t, s)
	uri := string(pathToURI(docPath))
	openMutantDoc(t, s, uri, src)

	asked := statCounter(t)
	links, err := s.documentLinks(&glsp.Context{}, &lsp.DocumentLinkParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
	})
	if err != nil {
		t.Fatalf("documentLinks error: %v", err)
	}

	for _, name := range *asked {
		if strings.Contains(name, "host") || strings.Contains(name, "share") {
			t.Errorf("the handler asked the filesystem about %q; that is the lookup that goes to "+
				"the network, on the one goroutine that reads the client's messages", name)
		}
	}
	// And the harness is live: the ordinary literal WAS asked about, so a
	// zero-call result above means refused and not "nothing ran".
	if len(*asked) == 0 {
		t.Fatal("the handler asked about nothing at all, so this test proves nothing")
	}
	if len(links) != 1 {
		t.Errorf("got %d link(s), want 1 (data.bin alone)", len(links))
	}
}

func TestADocumentLinkBudgetBoundsOneRequest(t *testing.T) {
	// A document naming more distinct existing files than the budget allows
	// must stop asking. Without a bound, one document decides how long every
	// other request waits.
	dir := t.TempDir()
	var b strings.Builder
	const n = documentLinkStatBudget + 50
	for i := 0; i < n; i++ {
		name := "f" + itoa(i) + ".bin"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		b.WriteString("let x" + itoa(i) + " = fs_read(" + quote(name) + ");\n")
	}
	src := b.String()
	docPath := filepath.Join(dir, "prog.mut")
	if err := os.WriteFile(docPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(false)
	initializeServer(t, s)
	uri := string(pathToURI(docPath))
	openMutantDoc(t, s, uri, src)

	asked := statCounter(t)
	if _, err := s.documentLinks(&glsp.Context{}, &lsp.DocumentLinkParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
	}); err != nil {
		t.Fatalf("documentLinks error: %v", err)
	}
	if len(*asked) > documentLinkStatBudget {
		t.Errorf("one request made %d filesystem lookups, over the budget of %d",
			len(*asked), documentLinkStatBudget)
	}
	if len(*asked) == 0 {
		t.Error("one request made no lookups at all, so the budget is not what stopped it")
	}
}

func TestARepeatedLiteralIsAskedAboutOnce(t *testing.T) {
	// The budget counts lookups, so a document repeating one name must not
	// spend it. This is also what keeps a long document of one filename cheap.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("let x" + itoa(i) + " = fs_read(" + quote("data.bin") + ");\n")
	}
	src := b.String()
	docPath := filepath.Join(dir, "prog.mut")
	if err := os.WriteFile(docPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(false)
	initializeServer(t, s)
	uri := string(pathToURI(docPath))
	openMutantDoc(t, s, uri, src)

	asked := statCounter(t)
	links, err := s.documentLinks(&glsp.Context{}, &lsp.DocumentLinkParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
	})
	if err != nil {
		t.Fatalf("documentLinks error: %v", err)
	}
	if len(*asked) != 1 {
		t.Errorf("one filename named 20 times cost %d lookups, want 1", len(*asked))
	}
	if len(links) != 20 {
		t.Errorf("got %d links, want 20: every occurrence is still underlined", len(links))
	}
}

func TestASymlinkLeavingTheRootIsNotLinked(t *testing.T) {
	// The case no lexical rule can see: a purely local literal whose target is
	// elsewhere. os.Root refuses to resolve it, which is why the containment
	// check is a filesystem primitive and not string arithmetic.
	base := t.TempDir()
	inside := filepath.Join(base, "case")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.img")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(inside, "escape.img")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("this host does not allow creating a symbolic link (needs the privilege or developer mode)")
		}
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "real.img"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := "let a = fs_read(" + quote("escape.img") + ");\n" +
		"let b = fs_read(" + quote("real.img") + ");\n"
	docPath := filepath.Join(inside, "prog.mut")
	if err := os.WriteFile(docPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(false)
	initializeServer(t, s)
	uri := string(pathToURI(docPath))
	openMutantDoc(t, s, uri, src)

	links, err := s.documentLinks(&glsp.Context{}, &lsp.DocumentLinkParams{
		TextDocument: lsp.TextDocumentIdentifier{URI: lsp.DocumentUri(uri)},
	})
	if err != nil {
		t.Fatalf("documentLinks error: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("got %d link(s), want 1: real.img is linked and escape.img is not", len(links))
	}
	if got := string(*links[0].Target); !strings.Contains(got, "real.img") {
		t.Errorf("the one link points at %q, want real.img", got)
	}
}

// quote renders a Mutant RAW string literal, r"...". It has to be raw: an
// ordinary literal goes through readQuotedBody and processes escapes, so a
// Windows path written in one would reach the analyzer as something else, and
// the test would be asserting about a string the fix never sees. A raw literal
// has no escapes at all -- lexer.go says that is what raw means -- which is
// also why it is the form an examiner would use for such a path.
func quote(s string) string {
	q := string(rune(34))
	return "r" + q + s + q
}

// itoa avoids importing strconv for three call sites in a test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
