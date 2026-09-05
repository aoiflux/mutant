package object

import (
	"fmt"
	"sort"
	"strings"
)

type Error struct {
	Message string
	Context string
	Related map[string]string

	// File, Line and Column locate the call that produced the error. They are
	// stamped by the VM, which is the only place that knows both the error and
	// the instruction being executed; a builtin knows what went wrong and
	// nothing about where it was called from.
	//
	// Line is zero when the program carries no line table -- compiled before
	// positions existed, or stripped for distribution.
	File   string
	Line   int
	Column int

	// EndLine and EndColumn bound the construct that produced the error, so a
	// report can underline it rather than pointing at its first character.
	// Zero when only a start position was recorded.
	EndLine   int
	EndColumn int

	// SourceLine is the text of Line, copied out of the program's embedded
	// source at the moment the error was stamped. It travels with the error so
	// that a caller holding one long after the fact -- a log line, a value
	// returned through three functions -- can still show what failed without
	// the program or its source being reachable.
	SourceLine string

	// Stack is the rendered call stack, innermost first. It is deliberately
	// absent from Inspect: errors are ordinary values in Mutant's (value, err)
	// idiom, so a program that catches one and prints it in a loop would emit
	// a full traceback per iteration. The stack is for the report a program
	// dies with, not for every error a program handles.
	Stack []string
}

// Location renders the position as file:line:col, or line:col when the file is
// unknown. Empty when there is no position at all.
func (e *Error) Location() string {
	if e == nil || e.Line <= 0 {
		return ""
	}
	if e.File == "" {
		return fmt.Sprintf("%d:%d", e.Line, e.Column)
	}
	return fmt.Sprintf("%s:%d:%d", e.File, e.Line, e.Column)
}

// SpanUnderline builds a caret row under text covering the columns
// [startCol, endCol), both 1-based, as rustc and Python 3.11 do. An endCol at
// or before startCol underlines a single column, which is what a construct
// whose end was never recorded gets.
//
// Tabs in the leading whitespace are copied through rather than replaced with
// spaces, so the carets stay under the code whatever tab width the reader's
// terminal is set to.
//
// It lives here rather than in the VM because two callers need it: the fatal
// report, which renders a whole traceback, and an error value that outlived the
// frame it was raised in and carries only its own line.
func SpanUnderline(text string, startCol, endCol int) string {
	runes := []rune(text)

	start := startCol - 1
	if start < 0 {
		start = 0
	}
	if start > len(runes) {
		start = len(runes)
	}

	width := endCol - startCol
	if width < 1 {
		width = 1
	}
	if start+width > len(runes) {
		width = len(runes) - start
	}
	if width < 1 {
		width = 1
	}

	var b strings.Builder
	for i := 0; i < start; i++ {
		if runes[i] == '\t' {
			b.WriteRune('\t')
			continue
		}
		b.WriteRune(' ')
	}
	b.WriteString(strings.Repeat("^", width))
	return b.String()
}

// Snippet renders the source line this error was raised on with the failing
// span underlined, as two tab-indented lines. Empty when no source line
// travelled with the error.
func (e *Error) Snippet() string {
	if e == nil || e.Line <= 0 || strings.TrimSpace(e.SourceLine) == "" {
		return ""
	}

	endCol := 0
	switch {
	case e.EndLine > e.Line:
		endCol = len([]rune(e.SourceLine)) + 1
	case e.EndLine == e.Line:
		endCol = e.EndColumn
	}

	number := fmt.Sprintf("%d", e.Line)
	gutter := strings.Repeat(" ", len(number))

	return fmt.Sprintf("\t  %s | %s\n\t  %s | %s",
		number, e.SourceLine,
		gutter, SpanUnderline(e.SourceLine, e.Column, endCol))
}

// Traceback renders the recorded call stack, one frame per tab-indented line,
// for the caller that is about to report this error as fatal.
func (e *Error) Traceback() string {
	if e == nil || len(e.Stack) == 0 {
		return ""
	}
	return "\t" + strings.Join(e.Stack, "\n\t")
}

func (e *Error) Type() ObjectType { return ERROR_OBJ }
func (e *Error) Inspect() string {
	if e == nil {
		return "ERROR:<nil>"
	}

	parts := []string{"ERROR:" + e.Message}
	if location := e.Location(); location != "" {
		parts = append(parts, "at "+location)
	}
	if e.Context != "" {
		parts = append(parts, "context="+e.Context)
	}
	if len(e.Related) > 0 {
		keys := make([]string, 0, len(e.Related))
		for key := range e.Related {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		relatedParts := make([]string, 0, len(keys))
		for _, key := range keys {
			relatedParts = append(relatedParts, fmt.Sprintf("%s=%s", key, e.Related[key]))
		}
		parts = append(parts, "related={"+strings.Join(relatedParts, ",")+"}")
	}

	return strings.Join(parts, " ")
}
