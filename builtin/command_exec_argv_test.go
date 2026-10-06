package builtin

import (
	"os/exec"
	"strings"
	"testing"

	"mutant/object"
)

// TestExecArgvRefusesWhatIsNotAnArgv covers the caller mistakes, which come
// back as an error object and not as a result saying the command failed.
//
// The distinction is the owner's rule of 2026-10-06: a builtin either works and
// answers properly, or it fails loudly. A command that ran and exited non-zero
// is an answer and belongs in the result hash; an argv that was never an argv
// is not, and would otherwise be indistinguishable from a program that is not
// installed.
func TestExecArgvRefusesWhatIsNotAnArgv(t *testing.T) {
	cases := []struct {
		name string
		args []object.Object
	}{
		{"no arguments", nil},
		{"two arguments", []object.Object{&object.Array{}, &object.Array{}}},
		{"a command string instead of an argv", []object.Object{
			&object.String{Value: "sh -c 'echo hi'"},
		}},
		{"an empty argv", []object.Object{
			&object.Array{Elements: []object.Object{}},
		}},
		{"a number among the arguments", []object.Object{
			&object.Array{Elements: []object.Object{
				&object.String{Value: "sh"},
				&object.Integer{Value: 7},
			}},
		}},
		{"a program that is only spaces", []object.Object{
			&object.Array{Elements: []object.Object{
				&object.String{Value: "   "},
			}},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, errObj := unwrapPair(t, ExecArgv(tc.args...))
			if errObj == nil {
				t.Fatalf("expected an error object, got result %v", result)
			}
			if errObj.Message == "" {
				t.Fatalf("the error object says nothing")
			}
		})
	}
}

// TestExecArgvRunsTheInvocationItIsGiven is the whole point of the builtin: the
// caller writes the shell and its flags out, and nothing in Mutant interprets
// them, so a shell whose flag is not -c is reachable too.
func TestExecArgvRunsTheInvocationItIsGiven(t *testing.T) {
	shell := ""
	for _, candidate := range []string{"bash", "sh"} {
		if _, err := exec.LookPath(candidate); err == nil {
			shell = candidate
			break
		}
	}
	if shell == "" {
		t.Skip("no bash or sh on PATH")
	}

	result, errObj := unwrapPair(t, ExecArgv(&object.Array{Elements: []object.Object{
		&object.String{Value: shell},
		&object.String{Value: "-c"},
		&object.String{Value: "echo hi"},
	}}))
	if errObj != nil {
		t.Fatalf("exec_argv: %s", errObj.Message)
	}

	hash, isHash := result.(*object.Hash)
	if !isHash {
		t.Fatalf("exec_argv returned %T, want HASH", result)
	}
	failure, isString := hashValueByKey(hash, "error").(*object.String)
	if !isString || failure.Value != "" {
		t.Fatalf("exec_argv reported an error: %v", hashValueByKey(hash, "error"))
	}
	stdout, isString := hashValueByKey(hash, "stdout").(*object.String)
	if !isString {
		t.Fatalf("stdout is not a STRING: %v", hashValueByKey(hash, "stdout"))
	}
	if strings.TrimSpace(stdout.Value) != "hi" {
		t.Fatalf("exec_argv printed %q, want \"hi\"", stdout.Value)
	}
}

// TestExecArgvReportsAMissingProgramInTheResult pins which of the two shapes a
// missing program takes. It is an outcome of running, not a caller mistake, so
// it comes back in the result hash with ok false and the reason in error --
// never silently, and never as a success.
func TestExecArgvReportsAMissingProgramInTheResult(t *testing.T) {
	result, errObj := unwrapPair(t, ExecArgv(&object.Array{Elements: []object.Object{
		&object.String{Value: "mutant-no-such-program-exists"},
	}}))
	if errObj != nil {
		t.Fatalf("a missing program should be a result, not an error object: %s", errObj.Message)
	}

	hash, isHash := result.(*object.Hash)
	if !isHash {
		t.Fatalf("exec_argv returned %T, want HASH", result)
	}
	ok, isBool := hashValueByKey(hash, "ok").(*object.Boolean)
	if !isBool || ok.Value {
		t.Fatalf("a missing program was reported as ok: %v", hashValueByKey(hash, "ok"))
	}
	message, isString := hashValueByKey(hash, "error").(*object.String)
	if !isString || !strings.Contains(message.Value, "mutant-no-such-program-exists") {
		t.Fatalf("the error does not name the program: %v", hashValueByKey(hash, "error"))
	}
}
