package analyzer

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// namespace_call.go unified the builtin-aware lint rules behind one resolver,
// so `fs.read(p)` and `fs_read(p)` are one call to every diagnostic. Four call
// sites were missed, and all four were in the layer that decides what a value
// IS rather than whether it is wrong: type inference.
//
// The effect was not a wrong answer, which is the reason it survived. It was
// silence -- `let d = hash_blake2(x)` got a type and `let d = hash.blake2(x)`
// got any, so the inlay hint and the hover card went blank for the spelling the
// module system encourages.
//
// These tests assert the two spellings agree AND that the agreed answer is the
// real one. Two spellings that both infer `any` agree perfectly.

// inferredTypeOfLastLet returns the inferred type of the binding declared by the
// first `let` in src, as its display string.
func inferredTypeOfLastLet(t *testing.T, src string, line, col int) (string, bool) {
	t.Helper()
	snapshot := New().Analyze(src)
	node, _, ok := snapshot.NodeAt(lsp.Position{Line: lsp.UInteger(line), Character: lsp.UInteger(col)})
	if !ok {
		t.Fatalf("no node at %d:%d in %q", line, col, src)
	}
	ty, ok := snapshot.TypeOf(node)
	if !ok {
		return "", false
	}
	return ty.String(), true
}

// TestASingleBindingIsTypedInBothSpellings covers infer.go's CallExpression arm.
// A (value, err) builtin bound to one name is the whole pair, and that is what
// both spellings must say.
func TestASingleBindingIsTypedInBothSpellings(t *testing.T) {
	cases := []struct{ name, flat, dotted string }{
		{"hash_blake2", "let d = hash_blake2(\"x\");\nd;\n", "let d = hash.blake2(\"x\");\nd;\n"},
		{"str_upper", "let d = str_upper(\"x\");\nd;\n", "let d = str.upper(\"x\");\nd;\n"},
		{"fs_read", "let d = fs_read(\"p\");\nd;\n", "let d = fs.read(\"p\");\nd;\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flatType, flatOK := inferredTypeOfLastLet(t, tc.flat, 0, 4)
			if !flatOK {
				t.Fatalf("the flat spelling stopped being typed at all")
			}

			dottedType, dottedOK := inferredTypeOfLastLet(t, tc.dotted, 0, 4)
			if !dottedOK {
				t.Fatalf("the dotted spelling infers nothing; the flat one infers %s", flatType)
			}
			if dottedType != flatType {
				t.Fatalf("the two spellings infer differently: dotted %s, flat %s", dottedType, flatType)
			}
		})
	}
}

// TestAMultiBindingIsTypedInBothSpellings covers infer.go's multiBindTypes. The
// error half of a (value, err) call is what the uncheckedError rule and the
// error-field completion both hang off, so a binding typed `any` there is a
// binding the editor cannot help with.
func TestAMultiBindingIsTypedInBothSpellings(t *testing.T) {
	flatValue, flatValueOK := inferredTypeOfLastLet(t, "let d, e = fs_read(\"p\");\nd;\n", 0, 4)
	flatErr, flatErrOK := inferredTypeOfLastLet(t, "let d, e = fs_read(\"p\");\ne;\n", 0, 7)
	if !flatValueOK || !flatErrOK {
		t.Fatalf("the flat spelling stopped being typed: value %v, err %v", flatValueOK, flatErrOK)
	}

	dottedValue, dottedValueOK := inferredTypeOfLastLet(t, "let d, e = fs.read(\"p\");\nd;\n", 0, 4)
	dottedErr, dottedErrOK := inferredTypeOfLastLet(t, "let d, e = fs.read(\"p\");\ne;\n", 0, 7)
	if !dottedValueOK {
		t.Errorf("the dotted spelling infers nothing for the value; the flat one infers %s", flatValue)
	} else if dottedValue != flatValue {
		t.Errorf("value binding differs: dotted %s, flat %s", dottedValue, flatValue)
	}
	if !dottedErrOK {
		t.Errorf("the dotted spelling infers nothing for the error; the flat one infers %s", flatErr)
	} else if dottedErr != flatErr {
		t.Errorf("error binding differs: dotted %s, flat %s", dottedErr, flatErr)
	}
}

// TestABindingStillBeatsTheFamilyInInference is the control that keeps the fix
// honest. Inference must not start folding a name the author bound.
func TestABindingStillBeatsTheFamilyInInference(t *testing.T) {
	src := "struct Holder { read }\nlet fs = Holder{read: 1};\nlet d = fs.read;\nd;\n"
	ty, ok := inferredTypeOfLastLet(t, src, 2, 4)
	if ok && strings.Contains(ty, "error") {
		t.Fatalf("a struct field was typed as the builtin's return: %s", ty)
	}
}

// TestADottedCallConstrainsAParameter covers fn_solver.go's constrainCall. A
// parameter used only through a dotted builtin call contributed no evidence at
// all, so it stayed unconstrained -- and an unconstrained parameter is what the
// hover card shows as `any`.
func TestADottedCallConstrainsAParameter(t *testing.T) {
	flat := parameterTypeOf(t, "let f = fn(p) { return str_upper(p); };\nf(\"x\");\n")
	dotted := parameterTypeOf(t, "let f = fn(p) { return str.upper(p); };\nf(\"x\");\n")

	if flat == "" {
		t.Fatalf("the flat spelling stopped constraining the parameter")
	}
	if dotted != flat {
		t.Fatalf("the dotted spelling constrains the parameter differently: dotted %q, flat %q", dotted, flat)
	}
}

// parameterTypeOf returns the display type of the single parameter `p` of the
// function declared on line 0.
func parameterTypeOf(t *testing.T, src string) string {
	t.Helper()
	snapshot := New().Analyze(src)
	col := strings.Index(src, "fn(p)") + 3
	node, _, ok := snapshot.NodeAt(lsp.Position{Character: lsp.UInteger(col)})
	if !ok {
		t.Fatalf("no node at the parameter in %q", src)
	}
	ty, ok := snapshot.TypeOf(node)
	if !ok {
		return ""
	}
	return ty.String()
}

// TestAMistypedMemberIsReportedInBothSpellings is the diagnostic half. The
// undefined-declaration rule checked only a field expression's left, so
// `hash_blake3(x)` -- a typo -- was flagged and `hash.blake3(x)` was not: the
// member name was never looked at, and `hash` names no variable to complain
// about either.
//
// The report is gated on the family existing. A receiver with no family at all
// is someone's struct and stays silent, which is the same gate builtinCallee's
// isLiveBuiltin check applies.
func TestAMistypedMemberIsReportedInBothSpellings(t *testing.T) {
	flat := lintMessages(t, "let x = hash_blake3(\"a\");\nx;\n")
	if !mentions(flat, "hash_blake3") {
		t.Fatalf("the flat spelling stopped reporting an unknown builtin: %v", flat)
	}

	dotted := lintMessages(t, "let x = hash.blake3(\"a\");\nx;\n")
	if !mentions(dotted, "blake3") {
		t.Fatalf("hash.blake3 is not reported as unknown; the flat spelling says %v, this says %v", flat, dotted)
	}
}

// TestAnUnknownReceiverStaysSilent is the false positive the gate exists to
// prevent. A receiver that names no builtin family is a value, and its fields
// are nobody's business here.
func TestAnUnknownReceiverStaysSilent(t *testing.T) {
	for _, src := range []string{
		"let f = fn(thing) { return thing.whatever; };\nf(1);\n",
		"struct Holder { whatever }\nlet h = Holder{whatever: 1};\nh.whatever;\n",
	} {
		for _, message := range lintMessages(t, src) {
			if strings.Contains(message, "whatever") {
				t.Errorf("field access on a plain value was reported: %q (in %q)", message, src)
			}
		}
	}
}
