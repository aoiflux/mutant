package builtin

import (
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// A return contract is a claim about code in another file, and the editor now
// renders it on every hover. This file asks the implementations to back it.
//
// The two halves of a contract are verified by two different probes, because
// they are observable under different conditions.
//
// The SHAPE — bare value or (value, err) pair — is observable for free, and with
// no exposure at all. Every builtin validates its argument count before it
// touches an argument, and the error it returns for a wrong count comes back in
// the builtin's own shape: resultAndError(nil, newError(...)) yields a
// MULTI_VALUE, a bare `return newError(...)` yields an *object.Error. So the
// same illegal-count call the arity probe already makes reveals the shape, and
// nothing reaches a file, a socket or a process to find it out.
//
// The KINDS of the success value need a call that actually succeeds, so they are
// only probed for the pure categories, where the arguments are values rather
// than paths and addresses. Everywhere else the kinds come from reading the
// implementation, and the coverage log below says so rather than implying more.

// returnShapeProbeSkip names the builtins the shape probe must not call. It is
// the arity probe's skip list for the same reasons — a call that would block on
// stdin, open a database, or run the anti-debug checks — with the higher-order
// builtins added, since their registered stub is never what runs.
var returnShapeProbeSkip = map[string]string{
	"gets":                 "reads stdin; an unchecked call would block the test run",
	"db_open":              "opens or creates a graph database on disk",
	"security_diagnostics": "runs the anti-debug and anti-tamper probes",
	"debug_status":         "runs the anti-debug probes",
	"sandbox_status":       "runs the sandbox-detection probes",
	"process_hash":         "hashes the running executable; file I/O and slow",

	"map":     "shape comes from the executor, not the registered stub",
	"filter":  "shape comes from the executor, not the registered stub",
	"reduce":  "shape comes from the executor, not the registered stub",
	"each":    "shape comes from the executor, not the registered stub",
	"sort_by": "shape comes from the executor, not the registered stub",
}

// handCheckedReturnShapes pins the shape of every builtin the probe skips, read
// off the implementation rather than inferred.
//
// Without this a skipped name would be a name nothing verifies, and the skip
// list becomes the easiest place for a wrong contract to hide — which is exactly
// what happened to tls_generate_ca's arity last round.
var handCheckedReturnShapes = map[string]bool{
	"gets":                 false, // gets.go: returns &object.String / newError
	"db_open":              true,  // db.go: resultAndError(intObj(...), nil)
	"security_diagnostics": true,  // security_status.go: resultAndError(makeHashObject(...), nil)
	"debug_status":         true,  // security_status.go: resultAndError(makeHashObject(...), nil)
	"sandbox_status":       true,  // security_status.go: resultAndError(makeHashObject(...), nil)
	"process_hash":         true,  // system_forensics.go: resultAndError(...)

	"map":     false, // vm/higher_order.go hoMap: returns &object.Array
	"filter":  false, // vm/higher_order.go hoFilter: returns &object.Array
	"reduce":  false, // vm/higher_order.go hoReduce: returns the accumulator
	"each":    false, // vm/higher_order.go hoEach: returns global.Null
	"sort_by": false, // vm/higher_order.go hoSortBy: returns &object.Array
}

// TestSkippedReturnShapesAreHandChecked keeps the skip list honest: a builtin may
// be too costly to call, but not too costly to verify.
func TestSkippedReturnShapesAreHandChecked(t *testing.T) {
	for name := range returnShapeProbeSkip {
		want, pinned := handCheckedReturnShapes[name]
		if !pinned {
			t.Errorf("%s is skipped by the shape probe but has no hand-checked shape; read its implementation and pin it", name)
			continue
		}
		spec, ok := ReturnSpec(name)
		if !ok {
			t.Errorf("%s has no teaching doc", name)
			continue
		}
		if spec.Pair != want {
			t.Errorf("%s: metadata declares pair=%t, but the implementation was read as pair=%t",
				name, spec.Pair, want)
		}
	}

	for name := range handCheckedReturnShapes {
		if _, skipped := returnShapeProbeSkip[name]; !skipped {
			t.Errorf("%s is pinned by hand but is no longer skipped; probe it instead of pinning it", name)
		}
	}
}

// TestReturnShapeMatchesImplementation calls every builtin with an argument
// count its signature forbids and reads the shape off the refusal.
//
// A disagreement is a real defect in the editor's output: hover would tell the
// reader to bind `let value, err = f()` for a builtin that actually puts its
// error in the first binding, or the reverse.
func TestReturnShapeMatchesImplementation(t *testing.T) {
	var probed, unprobeable, skipped []string

	for _, def := range Builtins {
		name := def.Name
		if name == "" || def.Builtin == nil {
			continue
		}
		if _, ok := returnShapeProbeSkip[name]; ok {
			skipped = append(skipped, name)
			continue
		}

		spec, ok := ReturnSpec(name)
		if !ok {
			t.Errorf("builtin %q is registered but has no teaching doc", name)
			continue
		}
		signature, _, _, _ := TeachingDoc(name)
		_, params, ok := ParseSignature(signature)
		if !ok {
			t.Errorf("builtin %q has an unparseable signature %q", name, signature)
			continue
		}

		count, ok := illegalArgCount(params)
		if !ok {
			// A variadic tail with no required parameters accepts every count,
			// so there is no refusal to read a shape off.
			unprobeable = append(unprobeable, name)
			continue
		}

		result, recovered := callWithNulls(def.Builtin.Fn, count)
		if recovered != nil {
			t.Errorf("%s panicked on %d arguments (%v)", name, count, recovered)
			continue
		}

		gotPair, ok := observedShape(result)
		if !ok {
			t.Errorf("%s: refusing %d arguments produced %s, which is neither an ERROR nor a MULTI_VALUE; the shape cannot be read",
				name, count, describe(result))
			continue
		}
		probed = append(probed, name)
		if gotPair != spec.Pair {
			t.Errorf("%s: metadata declares pair=%t, but the implementation returned %s — %s",
				name, spec.Pair, shapeName(gotPair), shapeAdvice(gotPair))
		}
	}

	sort.Strings(unprobeable)
	sort.Strings(skipped)
	t.Logf("return shape: probed %d of %d builtins; %d have no illegal argument count (%s); %d skipped (%s)",
		len(probed), len(Builtins), len(unprobeable), strings.Join(unprobeable, ", "),
		len(skipped), strings.Join(skipped, ", "))
}

// illegalArgCount picks one argument count the signature forbids. One below the
// minimum is preferred because it is the cheapest possible call.
func illegalArgCount(params []SignatureParam) (int, bool) {
	minArgs, maxArgs := SignatureArity(params)
	if minArgs > 0 {
		return minArgs - 1, true
	}
	if maxArgs >= 0 {
		return maxArgs + 1, true
	}
	return 0, false
}

// observedShape reports whether a refusal came back as a (value, err) pair. It
// reports false for anything that is neither shape, so an unreadable result is
// never silently counted as agreement.
func observedShape(obj object.Object) (pair bool, ok bool) {
	switch obj.(type) {
	case *object.MultiValue:
		return true, true
	case *object.Error:
		return false, true
	}
	return false, false
}

func shapeName(pair bool) string {
	if pair {
		return "a (value, err) MULTI_VALUE"
	}
	return "a bare ERROR"
}

func shapeAdvice(pair bool) string {
	if pair {
		return "declare it with pairRet, so hover tells the reader the error lands in the second binding"
	}
	return "declare it with ret, so hover does not promise a second binding that never arrives"
}

// TestReturnKindsMatchImplementation calls the pure builtins with valid
// arguments and checks the value that comes back is one the contract allows.
//
// Restricted to pureProbeCategories for the same reason the parameter probe is:
// only there does a call with real argument values compute rather than act.
func TestReturnKindsMatchImplementation(t *testing.T) {
	var confirmed, refused, skipped []string

	for _, def := range Builtins {
		name := def.Name
		if name == "" || def.Builtin == nil {
			continue
		}
		if _, ok := pureProbeCategories[CapabilityCategory(name)]; !ok {
			continue
		}
		if _, ok := returnShapeProbeSkip[name]; ok {
			skipped = append(skipped, name)
			continue
		}

		spec, _ := ReturnSpec(name)
		_, _, params, _ := TeachingDoc(name)

		args, ok := validArgsFor(params)
		if !ok {
			skipped = append(skipped, name+" (undeclared parameter kinds)")
			continue
		}

		result, recovered := callWithNulls2(def.Builtin.Fn, args)
		if recovered != nil {
			t.Errorf("%s panicked on a valid call (%v)", name, recovered)
			continue
		}

		value, ok := successValue(result, spec.Pair)
		if !ok {
			// The sample values are type-correct but not always meaningful — a
			// negative repeat count, an out-of-range index — so a refusal here
			// says nothing about the declared kind.
			refused = append(refused, name)
			continue
		}

		got := kindOf(value)
		if got == "" {
			refused = append(refused, name)
			continue
		}
		if !spec.allows(got) {
			t.Errorf("%s: contract says it returns %s, but a valid call returned %s",
				name, spec.KindsText(), got)
			continue
		}
		confirmed = append(confirmed, name)
	}

	sort.Strings(refused)
	sort.Strings(skipped)
	t.Logf("return kinds: confirmed %d builtins against a real call; %d refused the sample arguments (%s); %d skipped (%s)",
		len(confirmed), len(refused), strings.Join(refused, ", "), len(skipped), strings.Join(skipped, ", "))

	if len(confirmed) == 0 {
		t.Fatal("no builtin was confirmed; the probe is not exercising anything")
	}
}

// allows reports whether a kind satisfies the declared return.
func (r BuiltinReturnDoc) allows(kind ParamKind) bool {
	for _, declared := range r.Kinds {
		if declared == ParamAny || declared == kind {
			return true
		}
	}
	// A builtin that can also answer with null on a valid call — regex_find
	// declares STRING|NULL, but one that declares only STRING may still be
	// probed into its empty case, so NULL is never treated as a violation.
	return kind == ParamNull
}

// validArgsFor builds one argument per declared parameter, using a sample value
// of a kind that parameter accepts. It reports false when any required parameter
// has no declared kinds, since a NULL there would just be refused.
func validArgsFor(params []BuiltinParamDoc) ([]object.Object, bool) {
	args := make([]object.Object, 0, len(params))
	for _, p := range params {
		if p.Optional || p.Variadic {
			continue // exercise the shortest legal call
		}
		if len(p.Kinds) == 0 {
			return nil, false
		}
		kind := p.Kinds[0]
		if kind == ParamAny {
			kind = ParamString
		}
		if kind == ParamArray && len(p.Elem) > 0 {
			args = append(args, &object.Array{Elements: []object.Object{sampleForKind(p.Elem[0])}})
			continue
		}
		args = append(args, sampleForKind(kind))
	}
	return args, true
}

// callWithNulls2 invokes a builtin with the given arguments, converting a panic
// into a returned value so one bad builtin does not lose every other result.
func callWithNulls2(fn BuiltinFunction, args []object.Object) (result object.Object, recovered any) {
	defer func() { recovered = recover() }()
	result = fn(args...)
	return result, nil
}

// successValue digs the value half out of a result, reporting false when the
// call failed instead of succeeding.
func successValue(obj object.Object, pair bool) (object.Object, bool) {
	if _, isError := obj.(*object.Error); isError {
		return nil, false
	}
	multi, isMulti := obj.(*object.MultiValue)
	if !pair {
		if isMulti {
			return nil, false
		}
		return obj, obj != nil
	}
	if !isMulti || len(multi.Values) < 2 {
		return nil, false
	}
	if _, failed := multi.Values[1].(*object.Error); failed {
		return nil, false
	}
	return multi.Values[0], multi.Values[0] != nil
}

// kindOf names a runtime value in the vocabulary the contracts are written in,
// reporting "" for a type they cannot express.
func kindOf(obj object.Object) ParamKind {
	switch obj.(type) {
	case *object.String:
		return ParamString
	case *object.Integer:
		return ParamInt
	case *object.Float:
		return ParamFloat
	case *object.Boolean:
		return ParamBool
	case *object.Array:
		return ParamArray
	case *object.Hash:
		return ParamHash
	case *object.Null:
		return ParamNull
	}
	return ""
}
