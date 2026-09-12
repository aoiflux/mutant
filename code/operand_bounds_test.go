package code

import (
	"strings"
	"testing"
)

// TestMakeRejectsOversizedOperands pins the bound rather than the wrap.
//
// Operand widths are fixed, so an out-of-range index does not fail to encode --
// it truncates. `OpConstant 65536` used to assemble as `OpConstant 0`, giving a
// program that compiled, linked and ran while loading the wrong constant.
func TestMakeRejectsOversizedOperands(t *testing.T) {
	tests := []struct {
		name    string
		op      Opcode
		operand int
	}{
		{"two-byte operand one past the limit", OpConstant, 0x10000},
		{"two-byte operand far past the limit", OpConstant, 1 << 24},
		{"negative two-byte operand", OpConstant, -1},
		{"one-byte operand one past the limit", OpGetLocal, 0x100},
		{"negative one-byte operand", OpGetLocal, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected a panic for an operand that cannot be encoded")
				}
				msg, ok := r.(string)
				if !ok {
					t.Fatalf("expected a string panic value, got %T", r)
				}
				if !strings.Contains(msg, "does not fit") {
					t.Fatalf("unhelpful panic message: %s", msg)
				}
			}()
			Make(tt.op, tt.operand)
		})
	}
}

// TestMakeAcceptsBoundaryOperands guards the other edge: the largest encodable
// value must still assemble, and must round-trip through ReadOperands.
func TestMakeAcceptsBoundaryOperands(t *testing.T) {
	tests := []struct {
		name    string
		op      Opcode
		operand int
	}{
		{"two-byte zero", OpConstant, 0},
		{"two-byte maximum", OpConstant, 0xFFFF},
		{"one-byte zero", OpGetLocal, 0},
		{"one-byte maximum", OpGetLocal, 0xFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ins := Make(tt.op, tt.operand)
			if len(ins) == 0 {
				t.Fatalf("expected an instruction for %s %d", tt.name, tt.operand)
			}

			def, err := Lookup(byte(tt.op))
			if err != nil {
				t.Fatalf("lookup failed: %v", err)
			}
			operands, _ := ReadOperands(def, ins[1:])
			if len(operands) != 1 || operands[0] != tt.operand {
				t.Fatalf("round trip gave %v, want [%d]", operands, tt.operand)
			}
		})
	}
}
