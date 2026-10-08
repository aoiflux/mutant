package vm

import (
	"strings"
	"testing"

	"mutant/code"
	"mutant/compiler"
	"mutant/object"
)

// The unknown-opcode arm used to name one cause and get it wrong more often
// than it got it right.
//
// Its reasoning was about the byte the compiler emitted: opcodes are only ever
// appended and a value once emitted never changes meaning, so an unknown one
// can only come from a newer toolchain. But the byte that reaches the arm is
// whatever the instruction stream decrypted to, and that key derives from
// (instruction length, password). A stream decrypted under the wrong length
// produces uniformly random bytes, most of which are not opcodes -- which is
// how M26-TOOL-013 presented: every REPL session that defined a helper and
// called it on the next line was told to upgrade mutant.
//
// The message now names the local causes first and keeps the toolchain one.
// This test pins all of it, because the value of a diagnostic is entirely in
// what a reader does next.
func TestUnknownOpcodeMessageNamesDecryptionAndToolchain(t *testing.T) {
	machine := New(&compiler.ByteCode{
		Instructions: []byte{250, byte(code.OpTrue), byte(code.OpPop)},
		Constants:    []object.Object{},
	})

	err := machine.Run()
	if err == nil {
		t.Fatal("the VM ran a program containing an opcode it does not know")
	}

	message := err.Error()
	for _, want := range []string{
		"unknown opcode",
		"did not decode",
		"damaged",
		"wrong key",
		"newer version of mutant",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("error = %q, want it to mention %q", message, want)
		}
	}
}
