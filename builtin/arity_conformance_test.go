package builtin

import (
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// The language server derives its argument-count diagnostic from the teaching
// signatures in this package, so a signature that disagrees with its builtin is
// no longer a documentation nit — it becomes a warning on correct code. This
// file is the gate that keeps the two honest by asking the implementations
// themselves.
//
// Only one direction of disagreement can produce a false positive. The lint
// rejects a call whose argument count falls outside [min, max], so the harmful
// case is a signature narrower than the implementation: the runtime accepts a
// count the editor underlines. Probing counts *outside* the declared range is
// therefore both the interesting direction and the safe one — every builtin
// validates its argument count before it looks at the arguments, so an illegal
// count returns from the prologue without the body running. That is what makes
// it safe to probe fs_delete, net_connect and process_kill here without
// touching a file, a socket or a process.
//
// The opposite direction — a signature wider than the implementation — costs a
// missed diagnostic rather than a false one, and could only be probed by
// calling builtins with counts they accept. That would run the bodies, so it is
// deliberately not tested here.

// arityProbeSkip names the builtins the probe must not call, with the reason.
//
// The skip only matters for a builtin that turns out to have no argument-count
// check, because one that has such a check returns before its body runs. The
// list is deliberately conservative: it is cheaper to leave a handful of
// builtins verified by the corpus lint than to have `go test` block on stdin or
// generate a key pair.
// Every name here is pinned in handCheckedArities below, so skipping the call
// does not mean skipping the verification.
var arityProbeSkip = map[string]string{
	"gets":                 "reads stdin; an unchecked call would block the test run",
	"db_open":              "opens or creates a graph database on disk",
	"security_diagnostics": "runs the anti-debug and anti-tamper probes",
	"debug_status":         "runs the anti-debug probes",
	"sandbox_status":       "runs the sandbox-detection probes",
	"process_hash":         "hashes the running executable; file I/O and slow",

	// The higher-order builtins register a stub Fn that only reports "must be
	// applied to a function inside a running program" (higher_order.go); both
	// executors intercept them via HigherOrderKind before the stub is reached,
	// so the stub never sees an argument count and the probe cannot observe the
	// real check. TestHigherOrderArityMatchesExecutors covers them instead.
	"map":     "arity is enforced by the executor, not the registered stub",
	"filter":  "arity is enforced by the executor, not the registered stub",
	"reduce":  "arity is enforced by the executor, not the registered stub",
	"each":    "arity is enforced by the executor, not the registered stub",
	"sort_by": "arity is enforced by the executor, not the registered stub",
}

// handCheckedArities pins the argument counts of the builtins the probe must
// not call, read off their implementations rather than inferred.
//
// Without this, a name on the skip list would be a name nothing verifies, and
// the skip list would be the easiest place for a signature bug to hide — which
// is exactly what happened to tls_generate_ca and tls_generate_cert, whose
// optionsArg accepted any number of arguments while their signatures documented
// one. They now check their count and are probed like everything else.
var handCheckedArities = map[string][2]int{
	"gets":                 {0, 0}, // gets.go: len(args) != 0
	"db_open":              {0, 0}, // db.go: len(args) != 0
	"security_diagnostics": {0, 0}, // security_status.go: len(args) != 0
	"debug_status":         {0, 0}, // security_status.go: len(args) != 0
	"sandbox_status":       {0, 0}, // security_status.go: len(args) != 0
	"process_hash":         {0, 1}, // system_forensics.go: sfParsePIDArg rejects len(args) > 1
}

// TestSkippedBuiltinsAreHandChecked keeps the skip list honest: a builtin may be
// too dangerous to call, but not too dangerous to verify.
func TestSkippedBuiltinsAreHandChecked(t *testing.T) {
	for name := range arityProbeSkip {
		if strings.Contains(arityProbeSkip[name], "executor") {
			continue // covered by the vm package's own conformance test
		}
		want, pinned := handCheckedArities[name]
		if !pinned {
			t.Errorf("%s is skipped by the probe but has no hand-checked arity; read its implementation and pin it", name)
			continue
		}

		signature, _, _, ok := TeachingDoc(name)
		if !ok {
			t.Errorf("%s has no teaching doc", name)
			continue
		}
		_, params, ok := ParseSignature(signature)
		if !ok {
			t.Errorf("%s has an unparseable signature %q", name, signature)
			continue
		}
		if minArgs, maxArgs := SignatureArity(params); minArgs != want[0] || maxArgs != want[1] {
			t.Errorf("%s: signature %q implies {min:%d max:%d}, but the implementation was read as {min:%d max:%d}",
				name, signature, minArgs, maxArgs, want[0], want[1])
		}
	}

	for name := range handCheckedArities {
		if _, skipped := arityProbeSkip[name]; !skipped {
			t.Errorf("%s is pinned by hand but is no longer skipped; probe it instead of pinning it", name)
		}
	}
}

// callWithNulls invokes a builtin with n NULL arguments, converting a panic
// into a returned value.
//
// A builtin that panics on a wrong argument count is a real defect — nothing
// stops a Mutant program from writing that call, and a panic escaping a builtin
// takes down the VM rather than producing a catchable error — so the probe
// reports it rather than crashing the test binary and losing every other result.
func callWithNulls(fn BuiltinFunction, n int) (result object.Object, recovered any) {
	args := make([]object.Object, n)
	for i := range args {
		args[i] = &object.Null{}
	}

	defer func() { recovered = recover() }()

	result = fn(args...)
	return result, nil
}

// isArityError reports whether obj is the error a builtin returns for a wrong
// argument count. "wrong number of arguments" is the only phrasing used for it
// across the package; every other newError message describes a value or a type.
//
// Most of the standard library follows the (value, err) convention and returns
// a MULTI_VALUE whose tail carries the error, so the error has to be looked for
// inside one as well as at the top level.
func isArityError(obj object.Object) bool {
	switch v := obj.(type) {
	case *object.Error:
		return strings.Contains(v.Message, "wrong number of arguments")
	case *object.MultiValue:
		for _, value := range v.Values {
			if isArityError(value) {
				return true
			}
		}
	}
	return false
}

// TestSignatureArityMatchesImplementation calls every builtin with argument
// counts its signature says are illegal and requires the implementation to
// agree. A disagreement is a signature bug: the builtin accepts a count the
// signature forbids, and anything deriving a contract from that signature —
// the arity lint above all — would flag working code.
func TestSignatureArityMatchesImplementation(t *testing.T) {
	var (
		probed      int
		unprobeable []string
		skipped     []string
	)

	for _, def := range Builtins {
		name := def.Name
		if name == "" || def.Builtin == nil {
			continue
		}

		if reason, ok := arityProbeSkip[name]; ok {
			skipped = append(skipped, name+" ("+reason+")")
			continue
		}

		signature, _, _, ok := TeachingDoc(name)
		if !ok {
			t.Errorf("builtin %q is registered but has no teaching doc", name)
			continue
		}
		_, params, ok := ParseSignature(signature)
		if !ok {
			t.Errorf("builtin %q has an unparseable signature %q", name, signature)
			continue
		}
		minArgs, maxArgs := SignatureArity(params)

		// One count below the minimum and one above the maximum are enough:
		// every builtin's check is a comparison against the count, so if it
		// rejects the nearest illegal value it rejects the ones beyond it.
		illegal := make([]int, 0, 2)
		if minArgs > 0 {
			illegal = append(illegal, minArgs-1)
		}
		if maxArgs >= 0 {
			illegal = append(illegal, maxArgs+1)
		}
		if len(illegal) == 0 {
			// A variadic tail with no required parameters — putln(...values) —
			// has no illegal argument count to probe with.
			unprobeable = append(unprobeable, name)
			continue
		}

		probed++
		for _, n := range illegal {
			result, recovered := callWithNulls(def.Builtin.Fn, n)
			switch {
			case recovered != nil:
				t.Errorf("%s: %s panicked on %d arguments (%v); a wrong argument count must return an error, not crash the VM",
					name, signature, n, recovered)
			case !isArityError(result):
				t.Errorf("%s: signature %q forbids %d arguments but the implementation accepted them (returned %s); the signature is wrong or too narrow",
					name, signature, n, describe(result))
			}
		}
	}

	sort.Strings(skipped)
	sort.Strings(unprobeable)
	t.Logf("arity conformance: probed %d of %d builtins; %d have no illegal argument count (%s); %d skipped:\n  %s",
		probed, len(Builtins), len(unprobeable), strings.Join(unprobeable, ", "),
		len(skipped), strings.Join(skipped, "\n  "))
}

// describe renders a probe result for a failure message without dumping a
// large payload into the test log.
func describe(obj object.Object) string {
	if obj == nil {
		return "nil"
	}
	if err, ok := obj.(*object.Error); ok {
		return "ERROR: " + err.Message
	}
	text := string(obj.Type())
	if inspected := obj.Inspect(); len(inspected) <= 60 {
		text += " " + inspected
	}
	return text
}
