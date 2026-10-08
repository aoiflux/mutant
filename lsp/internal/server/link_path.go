package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// documentLinkStatBudget bounds how many distinct literals one documentLink
// request asks the filesystem about.
//
// A link is only offered for a path that exists, so the only way to know is to
// ask -- and the request is answered on the single goroutine that reads the
// client's messages, so every other editor feature waits behind the answers.
// A document may name any number of distinct relative paths, while the 123
// example programs in this tree hold at most 139 string literals of any kind.
// 1024 is far above every real script and bounds one request at a thousand
// local lookups.
//
//mutant:limit count
const documentLinkStatBudget = 1024

// statInRoot is os.Root.Stat behind a variable so a test can prove that a
// refused literal is never handed to the filesystem at all. That is the only
// honest observable for "no network attempt was made": no test can watch the
// wire, and timing is not an assertion.
//
// Stat rather than Lstat, which is a deliberate departure from the obvious
// reading of "do not follow anything". Stat resolves the final component, and
// os.Root refuses a symbolic link that leaves the root -- so Stat answers
// three questions in one call: does it exist, is the thing it names inside the
// root, and is it a file. Lstat would answer the first and skip the second,
// and a link offered for a symlink is followed by the editor, not by us.
var statInRoot = func(root *os.Root, name string) (fs.FileInfo, error) {
	return root.Stat(name)
}

// linkTarget is one literal that may be asked about: a root the operator chose
// and a name relative to it. Nothing in it has touched the filesystem.
type linkTarget struct {
	root string // an absolute directory
	rel  string // filepath.IsLocal(rel) is true
}

// linkCandidate decides, WITHOUT TOUCHING THE FILESYSTEM, whether value may be
// resolved at all, and under which root.
//
// It is an allowlist. The document's own text chooses value, so the question is
// not "is this one of the spellings that reach the network or a device" -- that
// list is the platform's, not ours, and it grows: on Windows it runs to a UNC
// path in either slash, the \\?\ and \??\ device prefixes, the \??\UNC\ form, a
// drive-relative C:foo, an alternate data stream x:s, and the reserved names
// NUL, CON, PRN, AUX, COM1..9 and LPT1..9 with their extension, trailing-dot
// and superscript-digit variants. The question is "does this land inside a
// directory the operator chose". Everything else is refused.
//
// Two layers, because neither is sufficient alone, and this was measured on
// this host rather than assumed:
//
//   - filepath.IsLocal is the lexical test. It is false for every spelling
//     listed above except one: IsLocal("CON.txt") is TRUE. It also costs no
//     syscall, which is what makes a refusal testable with no I/O at all.
//   - os.Root is the containment test, and it is what closes that one case.
//     Measured: root.Stat refuses NUL, CON, CON.txt, COM1, COM1.txt, con.TXT,
//     PRN, CONIN$ and the stream form name:stream, each in under a
//     millisecond, as well as any ".." escape and any symbolic link leaving
//     the root. A bare os.Stat of a UNC path that does not resolve took 5.5
//     seconds on the same host, and 42 seconds through the handler.
//
// A literal that is already local is taken relative to the document's own
// directory and cannot leave it. One that is not is resolved first and then has
// to come back out local relative to one of the roots -- which is what keeps
// "../evidence/usb.img" working inside a case directory while
// "../../../../Windows/win.ini" does not. The IsLocal test on the result is not
// redundant: it is what refuses a drive-relative C:foo, whose join can land
// inside a root while still naming another drive's current directory.
//
// sema.resolveImport made the same choice for import spellings and gives the
// same reason: it never stats, so it is safe on the keystroke path.
func linkCandidate(docDir string, roots []string, value string) (linkTarget, bool) {
	if value == "" || strings.ContainsAny(value, "\n\r\x00") {
		return linkTarget{}, false
	}
	local := filepath.FromSlash(value)
	if filepath.IsLocal(local) {
		// Cleaned, so that "./data.bin" and "data.bin" are one name: the
		// handler's budget counts distinct literals, and two spellings of one
		// file should cost one lookup.
		return linkTarget{root: docDir, rel: filepath.Clean(local)}, true
	}
	if rooted(local) && !filepath.IsAbs(local) {
		// A path that begins with a separator but names no volume -- "/etc/x"
		// on Windows -- is rooted on the CURRENT DRIVE, not here. Joining it to
		// the document's directory would resolve it somewhere the platform
		// never would, and the join lands inside a root, so it would then be
		// allowed. Refused instead: on POSIX the same spelling is absolute and
		// takes the loop below, which is where it belongs.
		return linkTarget{}, false
	}
	if !filepath.IsAbs(local) {
		local = filepath.Join(docDir, local)
		if !filepath.IsAbs(local) {
			return linkTarget{}, false
		}
	}
	for _, root := range roots {
		if root == "" || !filepath.IsAbs(root) {
			continue
		}
		rel, err := filepath.Rel(root, local)
		if err != nil || !filepath.IsLocal(rel) {
			continue
		}
		return linkTarget{root: root, rel: rel}, true
	}
	return linkTarget{}, false
}

// rooted reports whether a path begins with a separator. filepath has no
// exported form of this question: IsAbs answers a different one, because on
// Windows a rooted path with no volume is not absolute.
func rooted(p string) bool {
	return p != "" && os.IsPathSeparator(p[0])
}

// linkRoots returns the directories a document link may point inside: the
// document's own directory first, then the workspace roots captured at
// initialize.
//
// The document's directory has to be in the list. A single file opened with no
// folder leaves s.roots empty, and without it such a session would lose the
// feature entirely rather than being restricted -- which is the shape the
// existing document-link test has.
//
// It takes the read lock because the background scan reads the same field on
// its own goroutine and setRoots writes it; setRoots says why that matters.
func (s *Server) linkRoots(docDir string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roots := make([]string, 0, len(s.roots)+1)
	roots = append(roots, docDir)
	seen := map[string]struct{}{canonicalPath(docDir): {}}
	for _, root := range s.roots {
		key := canonicalPath(root)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, root)
	}
	return roots
}

// rootOpener opens each root at most once per request and closes them all
// together. Opening a root is a directory handle; a document naming a thousand
// literals under one root should pay for one.
type rootOpener struct {
	open map[string]*os.Root
}

func (r *rootOpener) get(dir string) (*os.Root, bool) {
	if r.open == nil {
		r.open = map[string]*os.Root{}
	}
	if root, ok := r.open[dir]; ok {
		return root, root != nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		// Remembered as a failure so a thousand literals under an unopenable
		// root cost one attempt rather than a thousand.
		r.open[dir] = nil
		return nil, false
	}
	r.open[dir] = root
	return root, true
}

func (r *rootOpener) closeAll() {
	for _, root := range r.open {
		if root != nil {
			root.Close()
		}
	}
}

// resolveLinkTarget returns the absolute path a literal names, if the literal
// is allowed and names an existing file inside a root the operator chose.
func (r *rootOpener) resolveLinkTarget(t linkTarget) (string, bool) {
	root, ok := r.get(t.root)
	if !ok {
		return "", false
	}
	info, err := statInRoot(root, t.rel)
	if err != nil || info.IsDir() {
		return "", false
	}
	return filepath.Join(t.root, t.rel), true
}
