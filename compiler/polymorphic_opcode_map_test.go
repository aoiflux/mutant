package compiler

import (
	"bytes"
	"testing"

	"mutant/code"
	"mutant/object"
)

// The bug that made opcode remapping unusable: the rewrite walked each stream
// one byte at a time and replaced anything matching a defined opcode, so an
// operand byte holding such a value was rewritten as though it were an opcode.
//
// OpConstant 5 encodes as 00 00 05. Every one of those three bytes is a defined
// opcode value (OpConstant, OpConstant, OpDiv), and only the first is one.
func TestRemappingLeavesOperandBytesAlone(t *testing.T) {
	original := code.Make(code.OpConstant, 5)

	engine := NewPolymorphicEngine(10, 4242)
	forward, _ := opcodeTables(engine.generateOpcodeMapping())

	// Without this the test could pass on a permutation that happens to fix
	// those two bytes, proving nothing.
	if forward[0x00] == 0x00 && forward[0x05] == 0x05 {
		t.Fatal("this seed maps both operand byte values to themselves; the test cannot tell the two implementations apart")
	}

	out, ok := remapOpcodes(original, forward)
	if !ok {
		t.Fatal("remapOpcodes declined a well-formed instruction")
	}

	if out[0] != forward[original[0]] {
		t.Errorf("the opcode byte was not remapped: got %d, want %d", out[0], forward[original[0]])
	}
	if !bytes.Equal(out[1:], original[1:]) {
		t.Errorf("operand bytes were rewritten: got % x, want % x", out[1:], original[1:])
	}
}

// The reverse table has to undo the rewrite exactly, decoded the way the VM
// decodes it: read a byte, map it back, and take the operand width from the
// opcode that comes out. If the widths did not line up under that reading, the
// VM would walk straight off an instruction boundary.
func TestReverseTableUndoesTheRewrite(t *testing.T) {
	const program = `
	struct Point { x; y; };
	enum Color { Red, Green };
	let f = fn(n) { if (n > 0) { return n; }; return 0; };
	let p = Point { x: 1, y: 2 };
	let c = Color.Green;
	let t = 0;
	for (let i = 0; i < 5; i = i + 1) { t = t + f(i); };
	t;
	`

	comp := New()
	if err := comp.Compile(parse(program)); err != nil {
		t.Fatalf("compile: %s", err)
	}
	baseline := comp.ByteCode()

	streams := []code.Instructions{baseline.Instructions}
	for _, c := range baseline.Constants {
		if fn, ok := c.(*object.CompiledFunction); ok {
			streams = append(streams, fn.Instructions)
		}
	}
	if len(streams) < 2 {
		t.Fatal("the test program compiled no functions; it no longer covers the constants pool")
	}

	engine := NewPolymorphicEngine(10, 20260824)
	forward, reverse := opcodeTables(engine.generateOpcodeMapping())

	for i, original := range streams {
		remapped, ok := remapOpcodes(original, forward)
		if !ok {
			t.Fatalf("stream %d: remapOpcodes declined a stream the compiler just emitted", i)
		}

		restored := unmapOpcodes(t, remapped, reverse)
		if !bytes.Equal(restored, original) {
			t.Errorf("stream %d did not survive the round trip:\n got % x\nwant % x", i, restored, original)
		}
	}
}

// Bytes that are not defined opcodes must map to themselves in both directions.
// Laundering one into a valid instruction would turn an undecodable stream --
// which fails loudly -- into a decodable one that runs the wrong thing.
func TestUndefinedOpcodeValuesMapToThemselves(t *testing.T) {
	engine := NewPolymorphicEngine(10, 31337)
	forward, reverse := opcodeTables(engine.generateOpcodeMapping())

	checked := 0
	for b := 0; b <= 0xFF; b++ {
		if _, err := code.Lookup(byte(b)); err == nil {
			continue
		}

		if forward[b] != byte(b) {
			t.Errorf("undefined byte %d is rewritten to %d", b, forward[b])
		}
		if reverse[b] != byte(b) {
			t.Errorf("undefined byte %d decodes to %d", b, reverse[b])
		}
		checked++
	}

	if checked == 0 {
		t.Fatal("every byte value is a defined opcode; this test checks nothing")
	}
}

// Remapping is all or nothing. A program with some streams rewritten and some
// not cannot be described by one reverse table: applying it would destroy the
// streams that were left alone.
func TestRemappingDeclinesRatherThanPartiallyRewriting(t *testing.T) {
	comp := New()
	if err := comp.Compile(parse(`let f = fn() { return 1; }; f();`)); err != nil {
		t.Fatalf("compile: %s", err)
	}
	bc := comp.ByteCode()

	// One compiled function that cannot be decoded is enough to call it off.
	corrupted := false
	for _, c := range bc.Constants {
		if fn, ok := c.(*object.CompiledFunction); ok {
			fn.Instructions = code.Instructions{0xFE}
			corrupted = true
			break
		}
	}
	if !corrupted {
		t.Fatal("the test program compiled no functions")
	}

	before := make(code.Instructions, len(bc.Instructions))
	copy(before, bc.Instructions)

	NewPolymorphicEngine(10, 1).mutateOpcodes(bc)

	if bc.OpcodeMap != nil {
		t.Error("a reverse table was shipped for a program that could not be fully remapped")
	}
	if !bytes.Equal(bc.Instructions, before) {
		t.Error("the main stream was rewritten even though a function stream could not be")
	}
}

// unmapOpcodes reverses a remapped stream the way the VM reads one: map the byte
// back first, then take the operand width from the opcode that produces.
func unmapOpcodes(t *testing.T, ins code.Instructions, reverse []byte) code.Instructions {
	t.Helper()

	out := make(code.Instructions, len(ins))
	copy(out, ins)

	for i := 0; i < len(out); {
		real := reverse[ins[i]]

		def, err := code.Lookup(real)
		if err != nil {
			t.Fatalf("byte %d at offset %d decodes to %d, which is not an opcode", ins[i], i, real)
		}

		width := 1
		for _, w := range def.OperandWidths {
			width += w
		}
		if i+width > len(out) {
			t.Fatalf("%s at offset %d runs past the end of the stream", def.Name, i)
		}

		out[i] = real
		i += width
	}

	return out
}
