package object

import (
	"fmt"
	"sort"
	"strings"
)

type Error struct {
	Message string
	Context string

	// Related carries whatever else the raiser knows: the path that failed, the
	// offset it failed at, the bytes actually read, the record that was being
	// parsed. It is Object-valued rather than string-valued so an integer stays
	// an integer and a buffer stays a buffer. An error that has to spell every
	// fact as text forces its reader to parse them back out, and the parse is
	// where facts get lost -- a 20-byte serial becomes a truncated one, an
	// offset becomes a string that sorts lexically.
	//
	// Two things follow from Object being an interface rather than a string:
	//
	//   - Inspect renders each value through the value's own Inspect, and
	//     Inspect is the de-facto identity function for error equality, so two
	//     errors compare equal only when their related values render alike.
	//   - Anything that gob-encodes an Error must register the concrete object
	//     types first, via serialize.RegisterGobTypes. This used to be a plain
	//     struct of concrete types that needed no registration. It is not one
	//     any more.
	Related map[string]Object

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

// inspectRelated renders one related value. A key present with a nil value is
// a bug in whatever raised the error, and this is the report trying to explain
// an earlier failure -- so it names the hole rather than panicking inside it.
func inspectRelated(value Object) string {
	if value == nil {
		return "null"
	}
	return value.Inspect()
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
			relatedParts = append(relatedParts, fmt.Sprintf("%s=%s", key, inspectRelated(e.Related[key])))
		}
		parts = append(parts, "related={"+strings.Join(relatedParts, ",")+"}")
	}

	return strings.Join(parts, " ")
}

// errorFieldNames lists every field a .mut program can read off an error, in
// declaration order. It exists so the field set can be enumerated -- by a test
// pinning the shape, by tooling -- rather than only probed one name at a time.
var errorFieldNames = []string{
	"message", "context", "related",
	"file", "line", "column", "end_line", "end_column",
	"source_line", "stack",
}

// ErrorFieldNames returns the readable field names of an error.
func ErrorFieldNames() []string {
	names := make([]string, len(errorFieldNames))
	copy(names, errorFieldNames)
	return names
}

// Field resolves one field of an error by the name a .mut program spells, for
// both `err.message` and `err["message"]`. The second return is false for a
// name that is not a field; the caller substitutes its own null, because the
// two engines hold different null singletons and object cannot import either.
//
// One table, read by both spellings and both engines, is the point: a field
// that exists under dot access and not under indexing would be a difference
// nobody could explain.
//
// Every field is always present, whatever the build. A stripped binary has no
// line table, so `line` reads 0 and `file` reads "" -- it does not stop being a
// field. That is what keeps a program that inspects position from having to
// know how it was compiled. See StripDebugInfo: strip removes the table, never
// the shape.
//
// The composite fields are rebuilt on each read rather than cached: `related`
// and `stack` hand back a fresh hash and array, so a program that mutates one
// does not edit the error it came from. The values inside `related` are shared
// rather than deep-copied -- a buffer is not duplicated because someone read
// the field it hangs off.
func (e *Error) Field(name string) (Object, bool) {
	if e == nil {
		return nil, false
	}

	switch name {
	case "message":
		return &String{Value: e.Message}, true
	case "context":
		return &String{Value: e.Context}, true
	case "related":
		return e.relatedHash(), true
	case "file":
		return &String{Value: e.File}, true
	case "line":
		return &Integer{Value: int64(e.Line)}, true
	case "column":
		return &Integer{Value: int64(e.Column)}, true
	case "end_line":
		return &Integer{Value: int64(e.EndLine)}, true
	case "end_column":
		return &Integer{Value: int64(e.EndColumn)}, true
	case "source_line":
		return &String{Value: e.SourceLine}, true
	case "stack":
		elements := make([]Object, 0, len(e.Stack))
		for _, frame := range e.Stack {
			elements = append(elements, &String{Value: frame})
		}
		return &Array{Elements: elements}, true
	}

	return nil, false
}

// relatedHash renders Related as a mutant hash keyed by string.
//
// A nil value under a key is a bug in the raiser -- the same one inspectRelated
// names -- and it becomes a Null here rather than a Go nil, because a nil
// Object inside a hash is a panic waiting for whichever builtin walks it next.
func (e *Error) relatedHash() *Hash {
	pairs := make(map[HashKey]HashPair, len(e.Related))
	for name, value := range e.Related {
		key := &String{Value: name}
		if value == nil {
			value = &Null{}
		}
		pairs[key.HashKey()] = HashPair{Key: key, Value: value}
	}
	return &Hash{Pairs: pairs}
}
