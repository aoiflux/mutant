package module

import (
	"fmt"
	"strings"
)

// InvalidPathError reports an import path that could never name a file,
// independently of what is on disk.
type InvalidPathError struct {
	// Importer is the file that wrote the import, filled in by the graph walk.
	// The resolver itself does not know it.
	Importer string
	Spelling string
	Reason   string
}

func (e *InvalidPathError) Error() string {
	if e.Importer == "" {
		return fmt.Sprintf("invalid import path %q: %s", e.Spelling, e.Reason)
	}
	return fmt.Sprintf("%s: invalid import path %q: %s", e.Importer, e.Spelling, e.Reason)
}

// NotFoundError reports an import that named no file.
//
// It lists every candidate that was tried rather than only the spelling. The
// spelling is already in the reader's source; what they do not know, and what
// decides whether the fix is a corrected path or another --module-path, is
// where the compiler looked.
type NotFoundError struct {
	// Importer is the file that wrote the import, filled in by the graph walk.
	// The resolver knows the directory it searched from, but not which file
	// asked -- and the file is what the reader has to open to fix it.
	Importer    string
	Spelling    string
	ImporterDir string
	Searched    []string
}

func (e *NotFoundError) Error() string {
	var b strings.Builder
	if e.Importer != "" {
		b.WriteString(e.Importer)
		b.WriteString(": ")
	}
	fmt.Fprintf(&b, "cannot find module %q", e.Spelling)
	if len(e.Searched) == 0 {
		b.WriteString(": no directory was searched (pass --module-path <dir> to add one)")
		return b.String()
	}

	b.WriteString("; searched:")
	for _, candidate := range e.Searched {
		b.WriteString("\n  ")
		b.WriteString(candidate)
	}
	b.WriteString("\nadd a directory to the search with --module-path <dir>")
	return b.String()
}

// CycleError reports an import cycle as the chain that closed it.
//
// Chain runs from the entry point of the cycle to the import that returned to
// it, with the repeated file appearing at both ends -- `main.mut -> a.mut ->
// b.mut -> a.mut`. Naming only the offending file would leave the reader to
// reconstruct the path themselves, which is the whole difficulty.
type CycleError struct {
	Chain []string
}

func (e *CycleError) Error() string {
	return "import cycle: " + strings.Join(e.Chain, " -> ")
}

// ReadError reports a file that resolved but could not be read.
type ReadError struct {
	Path string
	Err  error
}

func (e *ReadError) Error() string {
	return fmt.Sprintf("cannot read module %s: %v", e.Path, e.Err)
}

func (e *ReadError) Unwrap() error { return e.Err }

// ParseError reports a module that could not be parsed. Errors holds the
// parser's own messages, already carrying their own file:line:col prefixes.
type ParseError struct {
	Path   string
	Errors []string
}

func (e *ParseError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("cannot parse module %s", e.Path)
	}
	return fmt.Sprintf("cannot parse module %s:\n  %s", e.Path, strings.Join(e.Errors, "\n  "))
}

// DuplicateNamespaceError reports two imports in one file that bind the same
// name.
//
// This is worth its own error because the collision is usually invisible in
// the source: an unaliased import takes its namespace from the file's base
// name, so `import "a/util.mut"` and `import "b/util.mut"` both bind `util`
// while looking like two unrelated lines. Silently letting the last one win
// would make `util.f()` resolve to whichever import happened to be written
// second.
type DuplicateNamespaceError struct {
	Importer  string
	Namespace string
	First     string
	Second    string
}

func (e *DuplicateNamespaceError) Error() string {
	return fmt.Sprintf(
		"%s: two imports bind the name %q: %q and %q; give one an alias, as in `import other %q`",
		e.Importer, e.Namespace, e.First, e.Second, e.Second,
	)
}
