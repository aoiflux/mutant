// Package api is the exported facade over the language-tooling internals
// (formatter and analyzer) that live under lsp/internal. It exists so the root
// `mutant` CLI can offer `mutant fmt` / `mutant lint` without importing internal
// packages (Go forbids importing another tree's internal/), and without pulling
// LSP wire types into callers.
package api

import (
	"os"
	"path/filepath"

	"mutant/lexer"
	"mutant/lsp/internal/analyzer"
	"mutant/lsp/internal/server"
	"mutant/parser"
	"mutant/sema"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// Format returns the canonical formatting of Mutant source. It is idempotent and
// degrades to whitespace normalization on a hard parse error.
func Format(src string) string {
	return server.FormatSource(src)
}

// Severity is the importance of a diagnostic.
type Severity string

const (
	SeverityError       Severity = "error"
	SeverityWarning     Severity = "warning"
	SeverityInformation Severity = "information"
	SeverityHint        Severity = "hint"
)

// Diagnostic is a single lint/parse finding. Line and Column are 1-based for
// human-facing CLI output.
type Diagnostic struct {
	Line     int
	Column   int
	Severity Severity
	Message  string
	// Source is the producing subsystem, e.g. "mutant-parser", "mutant-lint",
	// "mutant-format".
	Source string
}

// Lint analyzes Mutant source and returns its diagnostics using the default lint
// configuration (the same rules the language server ships with).
func Lint(src string) []Diagnostic {
	return diagnosticsOf(analyzer.New().Analyze(src))
}

// Project is a set of files that can see one another.
//
// Lint(src) is handed a string with no file context, so it cannot know what an
// import names and must not guess: a name that crosses a module boundary --  a
// struct name, an enum name, a macro name, all written bare -- is a name it can
// say nothing about. `mutant lint` never had to be in that position. It already
// expands its arguments into every .mut file it is about to read, and that list
// is the closure the editor builds by scanning a root.
//
// The workspace is the same sema.Workspace the language server holds, so the
// CLI's answer and the editor's answer are one answer by construction rather
// than by two implementations agreeing.
type Project struct {
	analyzer  *analyzer.Analyzer
	workspace *sema.Workspace
}

// NewProject files what every path declares, so that linting any one of them
// knows what its imports name.
//
// A file that cannot be read is skipped and a file that will not parse is filed
// as a module with nothing in it -- FactsOf's own rule, and the difference
// matters: an unparseable import target should stop answering rather than start
// answering from somewhere else.
//
// It reads no file the caller did not name. An import that points outside the
// given set leaves the closure incomplete, which sema reports as Provisional,
// and a Provisional answer renders nothing.
//
// It parses every file, and Lint parses each one again, because the facts of
// every file have to exist before any file is analysed. Over the 123 .mut files
// in examples/ that second pass costs `mutant lint` about 100ms -- 290-350ms
// before, 340-500ms after -- paid once per invocation of an explicit command.
// Collapsing it means holding the parsed programs and an analyzer entry point
// that takes one, which is a second path through the analyzer for a saving
// nobody is waiting on. The number is here so that trade can be reopened with a
// new number rather than an opinion.
func NewProject(paths []string) *Project {
	project := &Project{analyzer: analyzer.New(), workspace: sema.NewWorkspace(nil)}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		program := parser.New(lexer.New(string(src))).ParseProgram()
		project.workspace.PutFile(fileURI(path), path, program)
	}
	return project
}

// Lint analyzes one file as part of the project.
//
// src is passed rather than re-read so that a caller holding the bytes does not
// read the file twice, and so that an editor-shaped caller can lint what is on
// screen rather than what is on disk.
func (p *Project) Lint(path, src string) []Diagnostic {
	if p == nil {
		return Lint(src)
	}
	return diagnosticsOf(p.analyzer.AnalyzeInWorkspace(path, src, p.workspace))
}

func fileURI(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	return "file:///" + filepath.ToSlash(absolute)
}

func diagnosticsOf(snapshot *analyzer.Snapshot) []Diagnostic {
	raw := analyzer.Diagnostics(snapshot, analyzer.DefaultLintConfig())
	out := make([]Diagnostic, 0, len(raw))
	for _, d := range raw {
		out = append(out, Diagnostic{
			Line:     int(d.Range.Start.Line) + 1,
			Column:   int(d.Range.Start.Character) + 1,
			Severity: severityString(d.Severity),
			Message:  d.Message,
			Source:   sourceString(d.Source),
		})
	}
	return out
}

func severityString(s *lsp.DiagnosticSeverity) Severity {
	if s == nil {
		return SeverityWarning
	}
	switch *s {
	case lsp.DiagnosticSeverityError:
		return SeverityError
	case lsp.DiagnosticSeverityWarning:
		return SeverityWarning
	case lsp.DiagnosticSeverityInformation:
		return SeverityInformation
	case lsp.DiagnosticSeverityHint:
		return SeverityHint
	default:
		return SeverityWarning
	}
}

func sourceString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
