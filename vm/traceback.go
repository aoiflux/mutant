package vm

// A traceback answers the question a failing program does not otherwise
// answer: not what went wrong, which the error message already says, but where.
//
// The frame stack that produces it has always been here -- Frame carries the
// closure it is running and the offset it is running at. What was missing was
// anything to resolve that offset against. Each CompiledFunction now carries a
// line table, so a frame's ip becomes a line, and a stack of frames becomes a
// stack of lines. See code/linetable.go and roadmap item L-3.
//
// Frames render innermost first, so the failure site sits directly beneath the
// error message rather than at the end of a list the reader has to scroll.
//
// Four things go beyond naming the line, all of them free at runtime and all of
// them gone from a release build along with the tables they read:
//
//   - The source line is quoted and the failing span underlined, because
//     "line 74" is a lookup and `total / count(xs)` with the second division
//     underlined is an answer.
//   - Each frame prints the arguments it was called with. The VM has them on
//     the stack at the frame's base pointer and the function carries its
//     parameter names, so a frame can say inner(n=10, d=0) rather than inner.
//     Neither Python nor rustc does this; for a dynamic language where the
//     interesting question is usually "what was actually passed", it is the
//     most useful line in the report.
//   - Repeated frames collapse. A runaway recursion produces a thousand
//     identical frames, and a report a reader scrolls past is a report nobody
//     reads.
//   - A macro-produced instruction names the macro's definition as well as its
//     call, since the call site contains none of the logic that failed.

import (
	"errors"
	"fmt"
	"strings"

	"mutant/object"
)

const (
	mainFrameName      = "<main>"
	anonymousFrameName = "<anonymous>"

	// maxRenderedArgValue caps how much of one argument is shown. A frame that
	// was handed a 4MB buffer should say so in a few characters.
	maxRenderedArgValue = 48

	// maxRenderedArgs caps how many arguments are named before the rest are
	// summarised.
	maxRenderedArgs = 6

	// maxCycleLength is the longest repeating call cycle that collapses. It
	// covers direct recursion and the mutual kind that actually occurs;
	// searching further costs more than the lines it would save.
	maxCycleLength = 8

	// minCycleRepeats is how many times a cycle must run before collapsing.
	// Two occurrences are a coincidence worth reading; three are a loop.
	minCycleRepeats = 3

	// maxRenderedFrames bounds the report after collapsing, for the deep stack
	// that is deep without repeating.
	maxRenderedFrames = 40
)

// TracebackFrame is one entry in a rendered call stack.
//
// Line is zero when the frame's function carries no line table: it was compiled
// before positions existed, or stripped for distribution. Such a frame still
// renders, by name, because knowing the shape of the call stack is worth
// something even without lines.
//
// EndLine and EndColumn bound the source construct the frame is executing, so a
// report can underline it. They are zero when only a start position was
// recorded, and the underline degrades to a single caret.
//
// Args are the rendered arguments the frame was called with, already labelled
// with parameter names where the function carries them.
//
// MacroLine is non-zero only for an instruction a macro produced, and points at
// the macro's definition rather than its call. Line already points at the call.
type TracebackFrame struct {
	Function string
	File     string
	Line     int
	Column   int

	EndLine   int
	EndColumn int

	Args []string

	MacroLine   int
	MacroColumn int
}

// Signature renders the frame's function with the arguments it received.
func (f TracebackFrame) Signature() string {
	if len(f.Args) == 0 {
		return f.Function
	}
	return f.Function + "(" + strings.Join(f.Args, ", ") + ")"
}

func (f TracebackFrame) String() string {
	var b strings.Builder

	b.WriteString("at ")
	b.WriteString(f.Signature())

	switch {
	case f.Line > 0 && f.File != "":
		fmt.Fprintf(&b, " (%s:%d:%d)", f.File, f.Line, f.Column)
	case f.Line > 0:
		fmt.Fprintf(&b, " (line %d:%d)", f.Line, f.Column)
	case f.File != "":
		fmt.Fprintf(&b, " (%s)", f.File)
	}

	if f.MacroLine > 0 {
		fmt.Fprintf(&b, ", expanded from a macro defined at line %d:%d", f.MacroLine, f.MacroColumn)
	}

	return b.String()
}

// sameSite reports whether two frames are the same call at the same place,
// which is what makes a repeat a repeat.
func (f TracebackFrame) sameSite(other TracebackFrame) bool {
	return f.Function == other.Function && f.Line == other.Line && f.Column == other.Column
}

// Traceback renders the call stack as it stands right now, innermost first.
//
// It reads state rather than changing any, so it is safe to call from a
// deferred recover -- which is the point, since a fault unwinds the Go stack
// while leaving the VM's frame stack exactly as the failure found it.
func (vm *VM) Traceback() []TracebackFrame {
	if vm == nil || vm.frameIndex <= 0 {
		return nil
	}

	file := ""
	if vm.bytecode != nil {
		file = vm.bytecode.SourceFile
	}

	frames := make([]TracebackFrame, 0, vm.frameIndex)
	for i := vm.frameIndex - 1; i >= 0; i-- {
		frame := vm.frames[i]
		if frame == nil || frame.cl == nil || frame.cl.Fn == nil {
			continue
		}
		fn := frame.cl.Fn

		entry := TracebackFrame{Function: fn.Name, File: file, Args: vm.frameArguments(frame)}
		if entry.Function == "" {
			entry.Function = anonymousFrameName
		}

		// ip is the offset of the instruction being executed, and is -1 until
		// the frame's first fetch. A frame that has not started yet has no
		// position, only a name.
		if frame.ip >= 0 {
			if line, col, ok := fn.LineTable.At(frame.ip); ok {
				entry.Line, entry.Column = line, col
			}
			if line, col, ok := fn.EndTable.At(frame.ip); ok {
				entry.EndLine, entry.EndColumn = line, col
			}
			if line, col, ok := fn.MacroTable.At(frame.ip); ok {
				entry.MacroLine, entry.MacroColumn = line, col
			}
		}

		frames = append(frames, entry)
	}

	return frames
}

// frameArguments reads the values a frame was called with off the stack.
//
// A frame's arguments sit at its base pointer, in order, which is the calling
// convention every call in this VM uses. The names come from the function; a
// function compiled without them labels its arguments positionally.
//
// Everything here is bounds-checked and the whole thing is recovered, because
// it runs on a path that is already failing -- often because the stack is in a
// state no instruction left behind. A traceback that panics while explaining a
// panic is worse than one that omits the arguments.
func (vm *VM) frameArguments(frame *Frame) (args []string) {
	defer func() {
		if recover() != nil {
			args = nil
		}
	}()

	fn := frame.cl.Fn
	count := fn.NumParams
	if count <= 0 || frame.bp < 0 {
		return nil
	}

	// Parameter names are debug info and are stripped together with the line
	// tables, so their absence is how this tells a local build from a
	// distributed one. That gate is the point rather than a side effect:
	// values live encrypted on the stack, and rendering them decrypts them.
	// A .mu that left the machine does not print its own runtime values back
	// out because something inside it divided by zero.
	if len(fn.Params) == 0 {
		return nil
	}

	shown := count
	if shown > maxRenderedArgs {
		shown = maxRenderedArgs
	}

	args = make([]string, 0, shown+1)
	for i := 0; i < shown; i++ {
		slot := frame.bp + i
		if slot < 0 || slot >= len(vm.stack) {
			break
		}

		// Stack values are encrypted at rest; decryptForUse is what every
		// other reader of the stack goes through, and it returns the value
		// untouched when it is not encrypted.
		value := renderArgValue(vm.decryptForUse(vm.stack[slot]))
		if i < len(fn.Params) && fn.Params[i] != "" {
			value = fn.Params[i] + "=" + value
		}
		args = append(args, value)
	}

	if count > shown {
		args = append(args, fmt.Sprintf("... %d more", count-shown))
	}
	if len(args) == 0 {
		return nil
	}
	return args
}

// renderArgValue renders one argument compactly. An absent value is a slot the
// caller never filled, which happens when a frame is inspected before its
// arguments are in place.
func renderArgValue(obj object.Object) string {
	if obj == nil {
		return "<unset>"
	}

	// Bytes renders as full hex deliberately, because Inspect doubles as the
	// identity function for equality and deduplication. A traceback is the one
	// caller that only ever wanted a preview, so it asks for one rather than
	// materialising a megabyte of hex to then cut it back to forty characters.
	if buf, ok := obj.(*object.Bytes); ok {
		return buf.Preview(maxRenderedArgValue / 4)
	}

	text := strings.Join(strings.Fields(obj.Inspect()), " ")
	if len(text) > maxRenderedArgValue {
		text = text[:maxRenderedArgValue-3] + "..."
	}
	if text == "" {
		return string(obj.Type())
	}
	return text
}

// RuntimeError is a VM failure carrying the call stack it happened on.
//
// Error() returns the underlying message unchanged, so everything that formats
// or matches VM errors today keeps working and the traceback is something a
// caller asks for rather than something it has to parse back out.
//
// Source is the program's own text, carried along so the rendered traceback can
// quote the lines it names. It is empty for a program compiled without debug
// info, and the traceback then renders positions without snippets.
type RuntimeError struct {
	Err    error
	Frames []TracebackFrame
	Source string
}

func (e *RuntimeError) Error() string { return e.Err.Error() }
func (e *RuntimeError) Unwrap() error { return e.Err }

// Traceback renders the frames one per line, each indented by a tab, with the
// source line quoted and the failing span underlined beneath any frame whose
// position can be resolved against the carried source.
func (e *RuntimeError) Traceback() string {
	if e == nil || len(e.Frames) == 0 {
		return ""
	}
	return renderFrames(e.Frames, e.Source)
}

// renderFrames is the shared renderer: collapse repeats, cap the length, and
// annotate each surviving frame with its source line.
func renderFrames(frames []TracebackFrame, source string) string {
	lines := make([]string, 0, len(frames)*3)

	for _, entry := range collapseCycles(frames) {
		if entry.note != "" {
			lines = append(lines, "\t"+entry.note)
			continue
		}

		lines = append(lines, "\t"+entry.frame.String())
		lines = append(lines, snippetFor(entry.frame, source)...)
	}

	return strings.Join(lines, "\n")
}

// tracebackEntry is either a frame or a note standing in for frames that were
// collapsed away.
type tracebackEntry struct {
	frame TracebackFrame
	note  string
}

// collapseCycles replaces a repeating run of frames with one copy of the run
// and a note saying how many times it repeated, then truncates whatever is
// still too long.
//
// It looks for the shortest cycle first, so a self-recursive function collapses
// as itself rather than as some longer pattern containing it. A cycle has to
// run minCycleRepeats times to count: two passes through a pair of mutually
// recursive functions is something a reader wants to see in full.
func collapseCycles(frames []TracebackFrame) []tracebackEntry {
	out := make([]tracebackEntry, 0, len(frames))

	for i := 0; i < len(frames); {
		length, repeats := cycleAt(frames, i)
		if repeats < minCycleRepeats {
			out = append(out, tracebackEntry{frame: frames[i]})
			i++
			continue
		}

		for offset := 0; offset < length; offset++ {
			out = append(out, tracebackEntry{frame: frames[i+offset]})
		}

		noun := "frame"
		if length > 1 {
			noun = fmt.Sprintf("%d frames", length)
		}
		out = append(out, tracebackEntry{
			note: fmt.Sprintf("... previous %s repeated %d more times ...", noun, repeats-1),
		})

		i += length * repeats
	}

	return truncateEntries(out)
}

// cycleAt finds the shortest run starting at i that repeats consecutively, and
// how many times it does. A length of 1 with 1 repeat means no cycle.
func cycleAt(frames []TracebackFrame, i int) (length, repeats int) {
	for length = 1; length <= maxCycleLength && i+length <= len(frames); length++ {
		count := 1
		for {
			next := i + length*count
			if next+length > len(frames) || !runsMatch(frames, i, next, length) {
				break
			}
			count++
		}
		if count >= minCycleRepeats {
			return length, count
		}
	}
	return 1, 1
}

func runsMatch(frames []TracebackFrame, a, b, length int) bool {
	for offset := 0; offset < length; offset++ {
		if !frames[a+offset].sameSite(frames[b+offset]) {
			return false
		}
	}
	return true
}

// truncateEntries keeps the innermost and outermost frames of a stack that is
// long without repeating. The failure is at one end and the entry point at the
// other; the middle of a forty-deep stack is where the least information is.
func truncateEntries(entries []tracebackEntry) []tracebackEntry {
	if len(entries) <= maxRenderedFrames {
		return entries
	}

	head := maxRenderedFrames * 3 / 4
	tail := maxRenderedFrames - head
	omitted := len(entries) - head - tail

	out := make([]tracebackEntry, 0, maxRenderedFrames+1)
	out = append(out, entries[:head]...)
	out = append(out, tracebackEntry{
		note: fmt.Sprintf("... %d frames omitted ...", omitted),
	})
	out = append(out, entries[len(entries)-tail:]...)
	return out
}

// snippetFor renders the source line a frame is executing and an underline
// beneath the span that failed, or nothing when either is unavailable.
//
// The gutter is built to the width of the line number so the bar under a
// three-digit line still lines up with the one under a one-digit line.
func snippetFor(frame TracebackFrame, source string) []string {
	if frame.Line <= 0 || source == "" {
		return nil
	}

	text, ok := sourceLine(source, frame.Line)
	if !ok || strings.TrimSpace(text) == "" {
		return nil
	}

	number := fmt.Sprintf("%d", frame.Line)
	gutter := strings.Repeat(" ", len(number))

	return []string{
		fmt.Sprintf("\t  %s | %s", number, text),
		fmt.Sprintf("\t  %s | %s", gutter, underlineFor(text, frame)),
	}
}

// sourceLine pulls one 1-based line out of the program text.
func sourceLine(source string, line int) (string, bool) {
	if line <= 0 {
		return "", false
	}

	lines := strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n")
	if line > len(lines) {
		return "", false
	}
	return strings.TrimRight(lines[line-1], "\r"), true
}

// underlineFor builds the caret row for a frame. A span ending on a later line
// underlines to the end of this one; a span whose end was never recorded gets a
// single caret.
func underlineFor(text string, frame TracebackFrame) string {
	endCol := 0
	switch {
	case frame.EndLine > frame.Line:
		endCol = len([]rune(text)) + 1
	case frame.EndLine == frame.Line:
		endCol = frame.EndColumn
	}
	return object.SpanUnderline(text, frame.Column, endCol)
}

// attachTraceback wraps an error leaving the execution loop with the stack it
// failed on.
//
// Wrapping happens here, at the one boundary every failure crosses, rather than
// at the fifty-odd sites that construct these errors. It also means a fault --
// which arrives by panic and never touches an error return -- gets the same
// treatment as an ordinary failure, so which of the two happened no longer
// decides whether the user gets a location.
//
// An error that already carries frames keeps them. execLoop re-enters itself
// through CallClosureSync, and the inner stack is the more specific one.
func (vm *VM) attachTraceback(err error) error {
	if err == nil {
		return nil
	}

	var existing *RuntimeError
	if errors.As(err, &existing) {
		return err
	}

	frames := vm.Traceback()
	if len(frames) == 0 {
		return err
	}

	source := ""
	if vm.bytecode != nil {
		source = vm.bytecode.SourceText
	}

	return &RuntimeError{Err: err, Frames: frames, Source: source}
}

// decorateError stamps the current source position and call stack onto an
// error a builtin produced.
//
// A builtin knows what went wrong and nothing about where it was called from;
// the VM knows both. This is the one place the two meet, so it is where the
// position is written. Fields already set are left alone -- an error that
// travelled out of a nested call keeps the position it was raised at.
//
// Errors are ordinary values in Mutant's (value, err) idiom, so this must also
// reach inside a MultiValue: the error half of a pair is the usual way one is
// returned.
func (vm *VM) decorateError(obj object.Object) object.Object {
	switch value := obj.(type) {
	case *object.Error:
		vm.stampError(value)
	case *object.MultiValue:
		if value == nil {
			return obj
		}
		for _, inner := range value.Values {
			if errObj, ok := inner.(*object.Error); ok {
				vm.stampError(errObj)
			}
		}
	}
	return obj
}

func (vm *VM) stampError(err *object.Error) {
	if err == nil || err.Line > 0 {
		return
	}

	frames := vm.Traceback()
	if len(frames) == 0 {
		return
	}

	top := frames[0]
	err.File, err.Line, err.Column = top.File, top.Line, top.Column
	err.EndLine, err.EndColumn = top.EndLine, top.EndColumn

	if vm.bytecode != nil {
		if text, ok := sourceLine(vm.bytecode.SourceText, top.Line); ok {
			err.SourceLine = text
		}
	}

	err.Stack = make([]string, 0, len(frames))
	for _, frame := range frames {
		err.Stack = append(err.Stack, frame.String())
	}
}
