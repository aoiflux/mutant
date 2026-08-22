// Package api is the exported facade over the language-tooling internals
// (formatter and analyzer) that live under lsp/internal. It exists so the root
// `mutant` CLI can offer `mutant fmt` / `mutant lint` without importing internal
// packages (Go forbids importing another tree's internal/), and without pulling
// LSP wire types into callers.
package api

import (
	"mutant/lsp/internal/analyzer"
	"mutant/lsp/internal/server"

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
	snapshot := analyzer.New().Analyze(src)
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
