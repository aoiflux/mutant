package builtin

import (
	"strings"
	"testing"
)

// validParamKinds is the closed set a declared parameter may name. ParamAny is
// included: it records the verified fact that a parameter accepts anything.
var validParamKinds = map[ParamKind]struct{}{
	ParamAny:    {},
	ParamInt:    {},
	ParamFloat:  {},
	ParamString: {},
	ParamBool:   {},
	ParamArray:  {},
	ParamHash:   {},
	ParamFn:     {},
	ParamNull:   {},
}

// TestSignaturesParse asserts every teaching signature is in the one shape the
// parser supports and names the builtin it documents. This is the gate that
// lets ParseSignature be trusted as the source of a builtin's parameter shape.
func TestSignaturesParse(t *testing.T) {
	for name, doc := range builtinDocs {
		if doc.signature == "" {
			t.Errorf("builtin %q has a teaching doc with no signature", name)
			continue
		}

		parsedName, _, ok := ParseSignature(doc.signature)
		if !ok {
			t.Errorf("builtin %q: signature %q does not parse as name(params...)", name, doc.signature)
			continue
		}
		if parsedName != name {
			t.Errorf("builtin %q: signature %q declares name %q", name, doc.signature, parsedName)
		}
	}
}

// TestDeclaredParamsMatchSignature asserts that where a builtin lists parameter
// docs, they agree with its signature on count, spelling, and the `?` / `...`
// decorations. A builtin may list no parameters at all (many document
// themselves entirely in the summary); only a mismatch is an error.
func TestDeclaredParamsMatchSignature(t *testing.T) {
	for name, doc := range builtinDocs {
		if len(doc.params) == 0 {
			continue
		}

		_, signatureParams, ok := ParseSignature(doc.signature)
		if !ok {
			continue // reported by TestSignaturesParse
		}

		if len(doc.params) != len(signatureParams) {
			t.Errorf("builtin %q: signature %q has %d parameters, params list has %d",
				name, doc.signature, len(signatureParams), len(doc.params))
			continue
		}

		for i, declared := range doc.params {
			shape, ok := parseSignatureParam(declared.name)
			if !ok {
				t.Errorf("builtin %q: parameter %d name %q is not a valid parameter spelling",
					name, i, declared.name)
				continue
			}
			want := signatureParams[i]
			if shape != want {
				t.Errorf("builtin %q: parameter %d is %q in the params list but %q in signature %q",
					name, i, declared.name, signatureParamText(want), doc.signature)
			}
			if declared.doc == "" {
				t.Errorf("builtin %q: parameter %q has no doc text", name, declared.name)
			}
		}
	}
}

// TestDeclaredParamKindsAreValid asserts declared kinds come from the closed
// set, contain no duplicates, and never mix ParamAny with a concrete kind —
// "accepts anything" and "accepts exactly these" are contradictory claims, and
// silently honouring the ParamAny half would hide a real contract.
func TestDeclaredParamKindsAreValid(t *testing.T) {
	for name, doc := range builtinDocs {
		for _, param := range doc.params {
			seen := make(map[ParamKind]struct{}, len(param.kinds))
			hasAny := false
			for _, kind := range param.kinds {
				if _, ok := validParamKinds[kind]; !ok {
					t.Errorf("builtin %q parameter %q: unknown kind %q", name, param.name, kind)
				}
				if _, dup := seen[kind]; dup {
					t.Errorf("builtin %q parameter %q: duplicate kind %q", name, param.name, kind)
				}
				seen[kind] = struct{}{}
				if kind == ParamAny {
					hasAny = true
				}
			}
			if hasAny && len(param.kinds) > 1 {
				t.Errorf("builtin %q parameter %q: ParamAny cannot be combined with concrete kinds (%v)",
					name, param.name, param.kinds)
			}
			// An element contract only means something on an ARRAY parameter,
			// and the checker reads it only after the argument is known to be
			// one — declaring elements on anything else would silently never
			// fire.
			if len(param.elem) > 0 {
				seenElem := make(map[ParamKind]struct{}, len(param.elem))
				for _, kind := range param.elem {
					if _, ok := validParamKinds[kind]; !ok {
						t.Errorf("builtin %q parameter %q: unknown elem kind %q", name, param.name, kind)
					}
					if _, dup := seenElem[kind]; dup {
						t.Errorf("builtin %q parameter %q: duplicate elem kind %q", name, param.name, kind)
					}
					seenElem[kind] = struct{}{}
				}

				acceptsArray := false
				for _, kind := range param.kinds {
					if kind == ParamArray {
						acceptsArray = true
						break
					}
				}
				if !acceptsArray {
					t.Errorf("builtin %q parameter %q: declares elem kinds %v but does not accept ARRAY (%v)",
						name, param.name, param.elem, param.kinds)
				}
			}
		}
	}
}

// TestParamSpecsDeriveShape pins the derivation of Optional/Variadic from a
// parameter's spelling, which is what lets the two never disagree.
func TestParamSpecsDeriveShape(t *testing.T) {
	specs, ok := ParamSpecs(BuiltinNamePutf)
	if !ok {
		t.Fatalf("ParamSpecs(%q) returned no specs", BuiltinNamePutf)
	}
	if len(specs) != 2 {
		t.Fatalf("ParamSpecs(%q) = %d params, want 2", BuiltinNamePutf, len(specs))
	}
	if specs[0].Variadic || specs[0].Optional {
		t.Errorf("putf format: got optional=%v variadic=%v, want both false", specs[0].Optional, specs[0].Variadic)
	}
	if !specs[1].Variadic {
		t.Errorf("putf ...values: got variadic=false, want true")
	}

	helpSpecs, ok := ParamSpecs(BuiltinNameHelp)
	if !ok {
		t.Fatalf("ParamSpecs(%q) returned no specs", BuiltinNameHelp)
	}
	for _, spec := range helpSpecs {
		if !spec.Optional {
			t.Errorf("help parameter %q: got optional=false, want true", spec.Name)
		}
	}

	if _, ok := ParamSpecs("definitely_not_a_builtin"); ok {
		t.Errorf("ParamSpecs returned specs for an unknown builtin")
	}
}

// TestAcceptsGuardsUncheckedParameters pins the two ways a parameter opts out
// of type checking: undeclared kinds, and an explicit ParamAny.
func TestAcceptsGuardsUncheckedParameters(t *testing.T) {
	undeclared := BuiltinParamDoc{Name: "value"}
	if !undeclared.AcceptsAnyKind() || !undeclared.Accepts(ParamInt) {
		t.Errorf("a parameter with no declared kinds must accept everything")
	}

	anyKind := BuiltinParamDoc{Name: "value", Kinds: []ParamKind{ParamAny}}
	if !anyKind.AcceptsAnyKind() || !anyKind.Accepts(ParamHash) {
		t.Errorf("a ParamAny parameter must accept everything")
	}

	union := BuiltinParamDoc{Name: "value", Kinds: []ParamKind{ParamString, ParamArray}}
	if union.AcceptsAnyKind() {
		t.Errorf("a parameter with concrete kinds must not be treated as unchecked")
	}
	if !union.Accepts(ParamString) || !union.Accepts(ParamArray) {
		t.Errorf("a union parameter must accept every kind it declares")
	}
	if union.Accepts(ParamInt) {
		t.Errorf("a union parameter must reject a kind it does not declare")
	}
}

// TestTypedSignature checks the one rendering that both the editor's signature
// help and the generated capability reference read, across every parameter
// shape the metadata can produce: plain, union, optional, variadic, and one
// verified to accept anything.
func TestTypedSignature(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"gets", "gets() -> STRING"},
		{"len", "len(value: STRING|ARRAY|HASH) -> INTEGER"},
		{"bytes_slice", "bytes_slice(data: STRING, start: INTEGER, length: INTEGER) -> (STRING, ERROR)"},
		{"help", "help(topic?: STRING, mode?: STRING) -> STRING"},
		{"min", "min(value: INTEGER|FLOAT, ...values: INTEGER|FLOAT) -> INTEGER|FLOAT"},
		{"putf", "putf(format, ...values) -> NULL"},
		{"text_replace", "text_replace(text: STRING, old: STRING, new: STRING, count?: INTEGER) -> STRING"},
		// The return is what tells a reader which binding of `let a, b = f()`
		// receives the error, so both shapes are pinned here.
		{"fs_read", "fs_read(path: STRING) -> (STRING, ERROR)"},
		{"str_upper", "str_upper(s: STRING) -> STRING"},
		{"text_split", "text_split(text: STRING, sep: STRING) -> []STRING"},
		{"process_list", "process_list() -> ([]HASH, ERROR)"},
	}

	for _, test := range tests {
		got, spans, ok := TypedSignature(test.name)
		if !ok {
			t.Errorf("TypedSignature(%q) reported no doc", test.name)
			continue
		}
		if got != test.want {
			t.Errorf("TypedSignature(%q) = %q, want %q", test.name, got, test.want)
			continue
		}
		// Every span must select whole, valid text out of the label it belongs
		// to — that is what lets the language server address parameters by
		// offset instead of by an ambiguous substring.
		for i, span := range spans {
			if span.Start < 0 || span.Start > span.End || span.End > len(got) {
				t.Errorf("TypedSignature(%q) parameter %d span %+v is out of range for %q", test.name, i, span, got)
			}
		}
	}

	if _, _, ok := TypedSignature("definitely_not_a_builtin"); ok {
		t.Error("TypedSignature returned a rendering for an unknown builtin")
	}
}

// TestTypedSignatureSpansMatchDeclaredParams asserts, for every builtin that
// documents parameters, that the rendering produces one span per parameter and
// that each span contains that parameter's name. This is the file-wide version
// of the check above: it cannot be satisfied by a renderer that drops, reorders,
// or mislabels a parameter anywhere in the metadata.
func TestTypedSignatureSpansMatchDeclaredParams(t *testing.T) {
	for name, doc := range builtinDocs {
		if len(doc.params) == 0 {
			continue
		}
		label, spans, ok := TypedSignature(name)
		if !ok {
			t.Errorf("builtin %q: TypedSignature reported no doc", name)
			continue
		}
		if len(spans) != len(doc.params) {
			t.Errorf("builtin %q: %d spans for %d parameters", name, len(spans), len(doc.params))
			continue
		}
		for i, param := range doc.params {
			span := spans[i]
			if span.Start < 0 || span.Start > span.End || span.End > len(label) {
				t.Errorf("builtin %q parameter %d: span %+v is out of range for %q", name, i, span, label)
				continue
			}
			text := label[span.Start:span.End]
			if !strings.HasPrefix(text, param.name) {
				t.Errorf("builtin %q parameter %d: span covers %q, want it to start with %q", name, i, text, param.name)
			}
		}
	}
}

// TestParamKindCoverage reports how far the hand-verified kind population has
// got. It asserts nothing about the number — coverage grows a category at a
// time and an unpopulated builtin is simply never type-checked — but printing
// it keeps the remaining work visible instead of invisible.
func TestParamKindCoverage(t *testing.T) {
	var withParams, withKinds, params, kindedParams int

	for _, doc := range builtinDocs {
		if len(doc.params) == 0 {
			continue
		}
		withParams++
		kinded := false
		for _, p := range doc.params {
			params++
			if len(p.kinds) > 0 {
				kindedParams++
				kinded = true
			}
		}
		if kinded {
			withKinds++
		}
	}

	t.Logf("kinds declared for %d/%d builtins that document parameters (%d/%d parameters); %d builtins total",
		withKinds, withParams, kindedParams, params, len(builtinDocs))
}

func TestSignatureArity(t *testing.T) {
	tests := []struct {
		signature string
		minArgs   int
		maxArgs   int
	}{
		{"gets()", 0, 0},
		{"len(value)", 1, 1},
		{"push(array, value)", 2, 2},
		{"help(topic?, mode?)", 0, 2},
		{"range(start, end, step?)", 2, 3},
		{"putf(format, ...values)", 1, -1},
		{"min(...values)", 0, -1},
	}

	for _, test := range tests {
		_, params, ok := ParseSignature(test.signature)
		if !ok {
			t.Errorf("ParseSignature(%q) failed", test.signature)
			continue
		}
		minArgs, maxArgs := SignatureArity(params)
		if minArgs != test.minArgs || maxArgs != test.maxArgs {
			t.Errorf("SignatureArity(%q) = (%d, %d), want (%d, %d)",
				test.signature, minArgs, maxArgs, test.minArgs, test.maxArgs)
		}
	}
}

func TestParseSignatureRejectsMalformed(t *testing.T) {
	malformed := []string{
		"",
		"len",
		"len(value",
		"(value)",
		"len(value))",
		"len(nested(x))",
		"len(a b)",
		"len(a, , b)",
		"len(...)",
	}

	for _, signature := range malformed {
		if _, _, ok := ParseSignature(signature); ok {
			t.Errorf("ParseSignature(%q) succeeded, want failure", signature)
		}
	}
}

// signatureParamText re-renders a parsed parameter in its signature spelling,
// for readable failure messages.
func signatureParamText(p SignatureParam) string {
	text := p.Name
	if p.Variadic {
		text = "..." + text
	}
	if p.Optional {
		text += "?"
	}
	return text
}
