package builtin

import (
	"sort"
	"strings"
	"testing"
)

// Guardrails for the return contracts, mirroring the ones metadata_param_test.go
// applies to parameters. These check the declarations are well formed; whether
// they match the implementations is return_conformance_test.go's job.

// TestEveryBuiltinDeclaresAReturn is what makes the editor's hover card uniform.
// A builtin with no declared return would render a card missing the one section
// every other card has, which is the inconsistency this contract exists to end.
func TestEveryBuiltinDeclaresAReturn(t *testing.T) {
	var missing []string
	for _, def := range Builtins {
		if def.Name == "" {
			continue
		}
		spec, ok := ReturnSpec(def.Name)
		if !ok {
			t.Errorf("builtin %q is registered but has no teaching doc", def.Name)
			continue
		}
		if len(spec.Kinds) == 0 {
			missing = append(missing, def.Name)
		}
		if strings.TrimSpace(spec.Doc) == "" {
			t.Errorf("builtin %q declares a return with no prose", def.Name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d builtins declare no return kinds: %s", len(missing), strings.Join(missing, ", "))
	}
}

// TestDeclaredReturnKindsAreValid holds the return kinds to the same closed set
// and the same no-contradictions rule as the parameter kinds: "yields anything"
// and "yields exactly these" cannot both be true.
func TestDeclaredReturnKindsAreValid(t *testing.T) {
	for name, doc := range builtinDocs {
		returns := doc.returns

		seen := make(map[ParamKind]struct{}, len(returns.kinds))
		hasAny := false
		for _, kind := range returns.kinds {
			if _, ok := validParamKinds[kind]; !ok {
				t.Errorf("builtin %q return: unknown kind %q", name, kind)
			}
			if _, dup := seen[kind]; dup {
				t.Errorf("builtin %q return: duplicate kind %q", name, kind)
			}
			seen[kind] = struct{}{}
			if kind == ParamAny {
				hasAny = true
			}
		}
		if hasAny && len(returns.kinds) > 1 {
			t.Errorf("builtin %q return: ParamAny is mixed with %d other kinds; either it yields anything or it yields exactly those",
				name, len(returns.kinds)-1)
		}

		// An element kind describes an array's contents, so it is meaningless
		// on a return that is not an array.
		if len(returns.elem) > 0 {
			if len(returns.kinds) != 1 || returns.kinds[0] != ParamArray {
				t.Errorf("builtin %q declares element kinds but returns %s, not a single ARRAY",
					name, returns.kinds)
			}
			for _, kind := range returns.elem {
				if _, ok := validParamKinds[kind]; !ok {
					t.Errorf("builtin %q return element: unknown kind %q", name, kind)
				}
			}
		}

		// Field names describe a hash, either the returned one or the ones
		// inside a returned array.
		if len(returns.fields) > 0 {
			if len(returns.kinds) != 1 || (returns.kinds[0] != ParamHash && returns.kinds[0] != ParamArray) {
				t.Errorf("builtin %q declares field names but returns %s, not a HASH or an ARRAY of them",
					name, returns.kinds)
			}
			seenField := make(map[string]struct{}, len(returns.fields))
			for _, field := range returns.fields {
				if field == "" {
					t.Errorf("builtin %q return: empty field name", name)
				}
				if _, dup := seenField[field]; dup {
					t.Errorf("builtin %q return: duplicate field name %q", name, field)
				}
				seenField[field] = struct{}{}
			}
		}
	}
}

// TestReturnTextRendersEveryShape pins the rendering the signature and the hover
// card are built from, including the pair form that is the whole reason this
// contract records a shape at all.
func TestReturnTextRendersEveryShape(t *testing.T) {
	tests := []struct {
		name    string
		returns BuiltinReturnDoc
		want    string
	}{
		{"bare scalar", BuiltinReturnDoc{Kinds: []ParamKind{ParamString}}, "STRING"},
		{"bare union", BuiltinReturnDoc{Kinds: []ParamKind{ParamInt, ParamFloat}}, "INTEGER|FLOAT"},
		{"pair scalar", BuiltinReturnDoc{Kinds: []ParamKind{ParamString}, Pair: true}, "(STRING, ERROR)"},
		{"bare typed array", BuiltinReturnDoc{Kinds: []ParamKind{ParamArray}, Elem: []ParamKind{ParamString}}, "[]STRING"},
		{"pair typed array", BuiltinReturnDoc{Kinds: []ParamKind{ParamArray}, Elem: []ParamKind{ParamHash}, Pair: true}, "([]HASH, ERROR)"},
		{"bare untyped array", BuiltinReturnDoc{Kinds: []ParamKind{ParamArray}}, "ARRAY"},
		{"undeclared", BuiltinReturnDoc{}, "ANY"},
		{"explicit any pair", BuiltinReturnDoc{Kinds: []ParamKind{ParamAny}, Pair: true}, "(ANY, ERROR)"},
	}

	for _, test := range tests {
		if got := test.returns.Text(); got != test.want {
			t.Errorf("%s: Text() = %q, want %q", test.name, got, test.want)
		}
	}
}

// TestReturnCoverage reports the shape split, which is the fact the contract
// exists to surface: which binding of `let a, b = f()` receives the error is not
// uniform across the standard library.
func TestReturnCoverage(t *testing.T) {
	var pair, bare, withFields, withElem, anyKind int
	for _, doc := range builtinDocs {
		if doc.returns.pair {
			pair++
		} else {
			bare++
		}
		if len(doc.returns.fields) > 0 {
			withFields++
		}
		if len(doc.returns.elem) > 0 {
			withElem++
		}
		if len(doc.returns.kinds) == 1 && doc.returns.kinds[0] == ParamAny {
			anyKind++
		}
	}
	t.Logf("returns: %d builtins yield (value, err) pairs, %d yield a bare value; "+
		"%d name their hash fields, %d name their element kind, %d are genuinely polymorphic (ANY)",
		pair, bare, withFields, withElem, anyKind)
}
