package builtin

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// The argument-type diagnostic is only as trustworthy as the kinds declared in
// metadata.go, and those are a claim about code in another file. This asks the
// implementations to back the claim: for every declared position, calling the
// builtin with a kind that position does not accept must produce an error.
//
// The direction matters. A declaration narrower than the implementation is what
// turns into a warning on working code, and it is exactly what this catches — a
// probe that is accepted means the builtin tolerates a kind the metadata says
// it refuses.
//
// Safety comes from the same property that makes the declarations meaningful.
// Every declared position was written from a type assertion whose failure
// returns an error, so a call carrying a rejected kind there stops in the
// prologue. Nothing reaches a file, a socket or a process.

// pureProbeCategories are capability categories whose builtins compute rather
// than act. Only there is it safe to fill the *other* argument positions with
// real values of their declared kinds, which is what lets positions after the
// first be reached. Everywhere else the other positions are filled with NULL,
// so a builtin that validates left to right stops before position i and the
// probe records the position as unreached rather than risking a real path or
// address being acted on.
var pureProbeCategories = map[string]struct{}{
	"strings":              {},
	"text analysis":        {},
	"math":                 {},
	"bytes":                {},
	"structured data":      {},
	"hashing":              {},
	"time":                 {},
	"network intelligence": {},
}

// sampleForKind is a value of the given kind, used to fill the positions the
// probe is not currently testing.
func sampleForKind(kind ParamKind) object.Object {
	switch kind {
	case ParamString:
		return &object.String{Value: "mutant-probe"}
	case ParamInt:
		return &object.Integer{Value: 1}
	case ParamFloat:
		return &object.Float{Value: 1}
	case ParamBool:
		return &object.Boolean{Value: false}
	case ParamArray:
		return &object.Array{Elements: []object.Object{}}
	case ParamHash:
		return &object.Hash{Pairs: map[object.HashKey]object.HashPair{}}
	default:
		return &object.Null{}
	}
}

// rejectedKindFor picks a kind the parameter does not accept, preferring one
// that is unlikely to be coerced.
func rejectedKindFor(p BuiltinParamDoc) (ParamKind, bool) {
	for _, candidate := range []ParamKind{ParamBool, ParamArray, ParamHash, ParamString, ParamInt} {
		if !p.Accepts(candidate) {
			return candidate, true
		}
	}
	return "", false
}

// errorMessage digs the message out of a result, following the (value, err)
// convention into a MULTI_VALUE.
func errorMessage(obj object.Object) (string, bool) {
	switch v := obj.(type) {
	case *object.Error:
		return v.Message, true
	case *object.MultiValue:
		for _, value := range v.Values {
			if message, ok := errorMessage(value); ok {
				return message, true
			}
		}
	}
	return "", false
}

func TestDeclaredParamKindsMatchImplementation(t *testing.T) {
	var (
		confirmed int
		unreached []string
		skipped   int
	)

	for _, def := range Builtins {
		name := def.Name
		if name == "" || def.Builtin == nil {
			continue
		}
		if _, skip := arityProbeSkip[name]; skip {
			skipped++
			continue
		}
		params, ok := ParamSpecs(name)
		if !ok || len(params) == 0 {
			continue
		}
		_, pure := pureProbeCategories[CapabilityCategory(name)]

		// Only fixed positions are probed: a variadic tail absorbs every
		// remaining argument, so "position i" stops being one parameter.
		for i, param := range params {
			if param.Variadic || param.AcceptsAnyKind() {
				continue
			}
			rejected, ok := rejectedKindFor(param)
			if !ok {
				continue
			}

			// Supply enough arguments to reach position i and satisfy every
			// required parameter before it.
			count := i + 1
			for j, p := range params {
				if !p.Optional && !p.Variadic && j+1 > count {
					count = j + 1
				}
			}
			args := make([]object.Object, count)
			for j := range args {
				switch {
				case j == i:
					args[j] = sampleForKind(rejected)
				case pure && j < len(params) && len(params[j].Kinds) > 0:
					args[j] = sampleForKind(params[j].Kinds[0])
				default:
					args[j] = &object.Null{}
				}
			}

			result, recovered := callWithNulls(func(...object.Object) object.Object {
				return def.Builtin.Fn(args...)
			}, 0)
			if recovered != nil {
				t.Errorf("%s: passing %s at argument %d panicked (%v); a rejected kind must return an error",
					name, rejected, i+1, recovered)
				continue
			}

			message, isError := errorMessage(result)
			if !isError {
				t.Errorf("%s: parameter %q is declared %s, but passing %s there was accepted (returned %s); the declaration is narrower than the implementation",
					name, param.Name, param.KindsText(), rejected, describe(result))
				continue
			}

			// The error has to be about *this* position. A builtin that
			// validates earlier arguments first rejects the NULL filler before
			// reaching position i, which proves nothing either way.
			if strings.Contains(message, fmt.Sprintf("argument %d", i+1)) ||
				strings.Contains(message, fmt.Sprintf("position=%d", i+1)) ||
				(i == 0 && strings.Contains(message, "argument to")) {
				confirmed++
				continue
			}
			unreached = append(unreached, fmt.Sprintf("%s#%d", name, i+1))
		}
	}

	sort.Strings(unreached)
	t.Logf("parameter-kind conformance: %d declared positions confirmed against their implementations, "+
		"%d not reached (an earlier argument was rejected first), %d builtins skipped as unsafe to call",
		confirmed, len(unreached), skipped)
	if len(unreached) > 0 && len(unreached) <= 40 {
		t.Logf("not reached: %s", strings.Join(unreached, ", "))
	}
}
