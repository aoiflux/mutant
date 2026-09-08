package object

import "fmt"

// Cell is one storage location that a frame slot and a closure's capture entry
// both point at.
//
// It exists because a closure's Free array used to hold copies. Capturing by
// value makes `fn(x) { let acc = 0; let add = fn(n) { acc = acc + n; };
// add(1); return acc; }` answer 0 forever: the closure accumulates into storage
// the enclosing frame cannot see. The tree-walking evaluator has never had that
// problem -- Environment.Update walks the outer chain and writes the one binding
// -- so the fix is not a semantics choice, it is making the VM agree with the
// reference implementation it already ships alongside.
//
// A local the compiler saw an inner function capture is *boxed*: its stack slot
// holds a *Cell rather than the value, and every closure that captures it holds
// that same *Cell. One location, and both engines' writes land in it.
//
// The cell is a handle, not a value. Two consequences the rest of the runtime
// depends on:
//
//   - It is never encrypted. encryptForStorage returns a new object, and a new
//     object is a copy -- which is precisely the aliasing this type exists to
//     establish. Value is what gets encrypted at rest, on the way in, and
//     decrypted on the way out, so the guarantee locals already had is
//     unchanged. See mutil.EncryptObject and object.encryptObjectSecure, both
//     of which carry an explicit *Cell arm saying so.
//   - It never reaches gob. Cells are created at frame entry from
//     CompiledFunction.CapturedLocals and die with the frame; nothing in a .mu
//     file describes one.
//
// A Cell can never be a user-visible value: no expression produces one, and the
// only opcodes that move one are the two capture loads. That is what makes the
// VM's `if cell, ok := x.(*Cell)` checks decidable rather than a guess -- a
// non-cell in a Free slot means bytecode compiled before boxing existed.
type Cell struct{ Value Object }

func (c *Cell) Type() ObjectType { return CELL_OBJ }

// Inspect renders the cell's contents, not the cell. Nothing should ever print
// one -- but a traceback that hits an unexpected cell is more useful showing
// what is inside it than showing an address.
func (c *Cell) Inspect() string {
	if c == nil || c.Value == nil {
		return "null"
	}
	return c.Value.Inspect()
}

// String makes a cell legible in %v-style Go debugging output without going
// through Inspect, which callers may have wrapped.
func (c *Cell) String() string { return fmt.Sprintf("Cell[%p]", c) }
