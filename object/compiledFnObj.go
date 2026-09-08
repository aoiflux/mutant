package object

import (
	"fmt"
	"mutant/code"
)

type CompiledFunction struct {
	Instructions code.Instructions
	NumLocals    int
	NumParams    int

	// CapturedLocals are the local slot indices an inner function closes over,
	// ascending. The VM boxes exactly these slots when it pushes the frame --
	// after the arguments are in place, so a captured *parameter* needs no
	// special case -- and the compiler has already rewritten every read and
	// write of them to the cell opcodes.
	//
	// This is semantic, not debug information, and must never join
	// ByteCode.StripDebugInfo's list: a release build that lost it would stop
	// boxing and quietly resume the by-value capture bug it exists to fix.
	// Empty is not "unknown", it is "this function has no captured locals",
	// which is also what every .mu compiled before boxing existed says -- and
	// correctly so, since none of them can contain a cell.
	CapturedLocals []int

	// Name is the function's source name, or empty for an anonymous literal.
	// It exists so a traceback can say which function a frame is in; nothing
	// resolves or dispatches on it.
	Name string

	// Params are the declared parameter names, in order. They exist so a
	// traceback can print the arguments a frame was called with: the VM holds
	// them on the stack at the frame's base pointer, but only the compiler
	// knows what they were called. Empty for a function compiled without
	// debug info, in which case a frame renders its arguments positionally.
	//
	// len(Params) is NumParams for every function this compiler produces; the
	// renderer does not assume it and pairs whichever is shorter.
	Params []string

	// LineTable maps an offset in Instructions back to the line and column
	// that produced it. MacroTable does the same for the macro definition an
	// instruction was expanded from, and is populated only for the stretches
	// of the stream that came out of a macro.
	//
	// Both are empty for a function compiled before positions existed and for
	// one whose positions were deliberately removed -- see
	// compiler.ByteCode.StripDebugInfo. A consumer cannot tell those apart,
	// which is intended.
	LineTable  code.LineTable
	MacroTable code.LineTable

	// EndTable maps the same offsets to where the source construct ends, in
	// the same encoding. LineTable alone gives a point, which is enough to
	// name a line and no help at all in `total / count(xs)` -- two divisions
	// and one column. With both ends the reporter can underline the span that
	// failed, the way rustc and Python 3.11 do.
	EndTable code.LineTable
}

func (cf *CompiledFunction) Type() ObjectType { return COMPILED_FN_OBJ }
func (cf *CompiledFunction) Inspect() string  { return fmt.Sprintf("Compiled Function[%p]", cf) }
