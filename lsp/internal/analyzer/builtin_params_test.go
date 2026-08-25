package analyzer

import (
	"strings"
	"testing"

	"mutant/builtin"
)

// TestBuiltinSignatureLabelSpansCoverTheirParameters is the assertion that
// makes the offset-based parameter labels safe: every span the label carries
// must select exactly the parameter it belongs to, out of the label string the
// client will display.
func TestBuiltinSignatureLabelSpansCoverTheirParameters(t *testing.T) {
	label, spans, ok := builtinSignatureLabel("bytes_slice")
	if !ok {
		t.Fatal("builtin bytes_slice has no signature label")
	}

	// The return rides on the end of the label. Spans are prefix offsets, so
	// appending it leaves every one of them valid — which is the property that
	// lets one renderer serve both hover and signature help.
	wantLabel := "bytes_slice(data: STRING, start: INTEGER, length: INTEGER) -> (STRING, ERROR)"
	if label != wantLabel {
		t.Fatalf("signature label = %q, want %q", label, wantLabel)
	}

	want := []string{"data: STRING", "start: INTEGER", "length: INTEGER"}
	if len(spans) != len(want) {
		t.Fatalf("label carried %d spans, want %d", len(spans), len(want))
	}
	for i, span := range spans {
		if int(span[0]) > int(span[1]) || int(span[1]) > len(label) {
			t.Fatalf("parameter %d span %v is out of range for a %d-character label", i, span, len(label))
		}
		if got := label[span[0]:span[1]]; got != want[i] {
			t.Errorf("parameter %d span covers %q, want %q", i, got, want[i])
		}
	}
}

func TestBuiltinSignatureLabelFallsBackToThePlainSignature(t *testing.T) {
	label, spans, ok := builtinSignatureLabel("gets")
	if !ok {
		t.Fatal("builtin gets has no signature label")
	}
	if label != "gets() -> STRING" {
		t.Errorf("label for a builtin with no parameters = %q, want the plain signature plus its return", label)
	}
	if spans != nil {
		t.Errorf("label for a builtin with no parameters carried %d spans, want none", len(spans))
	}

	if _, _, ok := builtinSignatureLabel("definitely_not_a_builtin"); ok {
		t.Error("builtinSignatureLabel returned a label for an unknown name")
	}
}

func TestParamDocumentationCombinesKindsAndProse(t *testing.T) {
	both := builtin.BuiltinParamDoc{Name: "s", Doc: "Text to digest.", Kinds: []builtin.ParamKind{builtin.ParamString}}
	if got, want := paramDocumentation(both), "**STRING** — Text to digest."; got != want {
		t.Errorf("paramDocumentation = %q, want %q", got, want)
	}

	proseOnly := builtin.BuiltinParamDoc{Name: "s", Doc: "Text to digest."}
	if got, want := paramDocumentation(proseOnly), "Text to digest."; got != want {
		t.Errorf("paramDocumentation for an unchecked parameter = %q, want %q", got, want)
	}

	anyKind := builtin.BuiltinParamDoc{Name: "v", Doc: "Any value.", Kinds: []builtin.ParamKind{builtin.ParamAny}}
	if got, want := paramDocumentation(anyKind), "Any value."; got != want {
		t.Errorf("paramDocumentation for a ParamAny parameter = %q, want %q", got, want)
	}

	kindsOnly := builtin.BuiltinParamDoc{Name: "s", Kinds: []builtin.ParamKind{builtin.ParamInt}}
	if got, want := paramDocumentation(kindsOnly), "**INTEGER**"; got != want {
		t.Errorf("paramDocumentation for a documented-only-by-kind parameter = %q, want %q", got, want)
	}
}

// TestBuiltinCompletionDetailKeepsItsSortingPrefix pins the coupling between
// the detail string and completionCategory, which sorts builtins ahead of local
// bindings by looking for a "builtin" prefix.
func TestBuiltinCompletionDetailKeepsItsSortingPrefix(t *testing.T) {
	detail := builtinCompletionDetail("len")
	if detail == nil {
		t.Fatal("builtinCompletionDetail returned nil")
	}
	if !strings.HasPrefix(*detail, "builtin") {
		t.Errorf("completion detail = %q, want it to start with \"builtin\"", *detail)
	}
	if !strings.Contains(*detail, "len(value: STRING|ARRAY|HASH)") {
		t.Errorf("completion detail = %q, want it to carry the typed signature", *detail)
	}

	unknown := builtinCompletionDetail("definitely_not_a_builtin")
	if unknown == nil || !strings.HasPrefix(*unknown, "builtin") {
		t.Errorf("completion detail for an unknown name = %v, want it to start with \"builtin\"", unknown)
	}
}

// TestParamKindForTypeDeclinesWhatItCannotName pins the translation's safety
// property: a type the kind vocabulary cannot express yields no opinion, so the
// argument goes unchecked rather than being judged wrongly.
func TestParamKindForTypeDeclinesWhatItCannotName(t *testing.T) {
	expressible := map[TypeKind]builtin.ParamKind{
		TypeInt:      builtin.ParamInt,
		TypeFloat:    builtin.ParamFloat,
		TypeBool:     builtin.ParamBool,
		TypeString:   builtin.ParamString,
		TypeArray:    builtin.ParamArray,
		TypeHash:     builtin.ParamHash,
		TypeFunction: builtin.ParamFn,
		TypeNull:     builtin.ParamNull,
		// Structs and enums moved from the declined list to this one when the
		// kind vocabulary gained them. That is what closed the last fifteen
		// undeclared parameter positions, all of which take a struct or an enum.
		TypeStruct: builtin.ParamStruct,
		TypeEnum:   builtin.ParamEnum,
	}
	for kind, want := range expressible {
		got, ok := paramKindForType(Type{Kind: kind})
		if !ok || got != want {
			t.Errorf("paramKindForType(%v) = (%q, %t), want (%q, true)", kind, got, ok, want)
		}
	}

	// What is left cannot be named at all: Any carries no information, an error
	// is not a value a parameter accepts, and a (value, err) pair is two values.
	// Declining them is what keeps the argument-type diagnostic from judging an
	// argument against a kind it was never compared to.
	for _, kind := range []TypeKind{TypeAny, TypeError, TypeMulti} {
		if _, ok := paramKindForType(Type{Kind: kind}); ok {
			t.Errorf("paramKindForType(%v) claimed a kind; it must decline what it cannot name", kind)
		}
	}
}

func TestKindListTextReadsAsEnglish(t *testing.T) {
	tests := []struct {
		kinds []builtin.ParamKind
		want  string
	}{
		{nil, "a supported type"},
		{[]builtin.ParamKind{builtin.ParamString}, "STRING"},
		{[]builtin.ParamKind{builtin.ParamInt, builtin.ParamFloat}, "INTEGER or FLOAT"},
		{[]builtin.ParamKind{builtin.ParamString, builtin.ParamArray, builtin.ParamHash}, "STRING, ARRAY, or HASH"},
	}
	for _, test := range tests {
		if got := kindListText(test.kinds); got != test.want {
			t.Errorf("kindListText(%v) = %q, want %q", test.kinds, got, test.want)
		}
	}
}

// TestArgumentCountFitsParams covers the gate that keeps positional mapping
// honest: a call whose argument count the signature cannot absorb is left to
// the arity rule instead of being type-checked against the wrong parameters.
func TestArgumentCountFitsParams(t *testing.T) {
	required := []builtin.BuiltinParamDoc{{Name: "a"}, {Name: "b"}}
	optional := []builtin.BuiltinParamDoc{{Name: "a"}, {Name: "b?", Optional: true}}
	variadic := []builtin.BuiltinParamDoc{{Name: "a"}, {Name: "...rest", Variadic: true}}

	tests := []struct {
		name   string
		params []builtin.BuiltinParamDoc
		count  int
		want   bool
	}{
		{"exact", required, 2, true},
		{"too few", required, 1, false},
		{"too many", required, 3, false},
		{"optional omitted", optional, 1, true},
		{"optional supplied", optional, 2, true},
		{"variadic empty tail", variadic, 1, true},
		{"variadic long tail", variadic, 9, true},
		{"variadic missing the required head", variadic, 0, false},
	}
	for _, test := range tests {
		if got := argumentCountFitsParams(test.params, test.count); got != test.want {
			t.Errorf("%s: argumentCountFitsParams(_, %d) = %t, want %t", test.name, test.count, got, test.want)
		}
	}
}
