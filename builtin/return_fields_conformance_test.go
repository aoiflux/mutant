package builtin

import (
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// The third half of a return contract, and the one nothing was checking.
//
// TestReturnShapeMatchesImplementation verifies bare-vs-pair and
// TestReturnKindsMatchImplementation verifies the kind of the success value.
// Neither looks at the *field names* of a HASH -- and those are what the editor
// renders on hover and what a .mut program actually types. `{path, bytes,
// format, sha256}` is declared in metadata.go and spelled again, as a literal,
// wherever the builtin builds its result; nothing linked the two, so a key the
// implementation renamed left the contract quoting one that no longer exists.
//
// The check runs one way on purpose: every key a real call returns must be
// declared. That catches a typo in either copy -- an implementation that emits
// "paths" produces an undeclared key, and metadata that declares "paths"
// leaves the real "path" undeclared -- without failing a builtin whose contract
// lists a field these sample arguments were never going to populate.
func TestEveryFieldAnImplementationReturnsIsDeclared(t *testing.T) {
	var confirmed, refused, skipped []string

	for _, def := range Builtins {
		name := def.Name
		if name == "" || def.Builtin == nil {
			continue
		}
		// Same gate the kinds probe uses: only categories that touch nothing
		// outside this process are called for real.
		if _, ok := pureProbeCategories[CapabilityCategory(name)]; !ok {
			continue
		}
		if _, ok := returnShapeProbeSkip[name]; ok {
			skipped = append(skipped, name)
			continue
		}

		spec, _ := ReturnSpec(name)
		if len(spec.Fields) == 0 {
			continue
		}

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

		value, ok := successValue(result, spec)
		if !ok {
			refused = append(refused, name)
			continue
		}
		hash, isHash := value.(*object.Hash)
		if !isHash || len(hash.Pairs) == 0 {
			refused = append(refused, name)
			continue
		}

		declared := make(map[string]bool, len(spec.Fields))
		for _, field := range spec.Fields {
			declared[field] = true
		}

		var undeclared []string
		for _, pair := range hash.Pairs {
			key, ok := pair.Key.(*object.String)
			if !ok {
				// A non-string key is not something a contract can name, and
				// no builtin is meant to return one.
				continue
			}
			if !declared[key.Value] {
				undeclared = append(undeclared, key.Value)
			}
		}

		if len(undeclared) > 0 {
			sort.Strings(undeclared)
			t.Errorf("%s: a valid call returned %s, which the return contract does not declare; "+
				"it declares %s. The hover card teaches the contract, so an undeclared key is a "+
				"field the editor will not know about",
				name, strings.Join(quoteAll(undeclared), ", "), strings.Join(quoteAll(spec.Fields), ", "))
			continue
		}
		confirmed = append(confirmed, name)
	}

	sort.Strings(refused)
	sort.Strings(skipped)
	t.Logf("return fields: confirmed %d builtins against a real call; %d refused the sample arguments (%s); %d skipped (%s)",
		len(confirmed), len(refused), strings.Join(refused, ", "), len(skipped), strings.Join(skipped, ", "))

	if len(confirmed) == 0 {
		t.Fatal("no builtin was confirmed; the probe is not exercising anything")
	}
}

func quoteAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, `"`+v+`"`)
	}
	return out
}
