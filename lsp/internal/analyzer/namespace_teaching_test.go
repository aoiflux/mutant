package analyzer

import (
	"strings"
	"testing"

	lsp "github.com/tliron/glsp/protocol_3_16"

	mast "mutant/ast"
	"mutant/builtin"
)

// `hash.blake2(s)` and `hash_blake2(s)` are the same call. The lint rules learned
// that when builtinCallee landed; the things that *teach* — hover, signature
// help, the inlay hints built on it, and the colour the callee is painted — did
// not, and each found its callee with a bare `call.Function.(*mast.Identifier)`
// that a dotted call fails.
//
// The result was worse than nothing being shown. Hovering `blake2` fell through
// to the generic identifier arm and answered "identifier `blake2`", and
// signature help offered the one-parameter shape of a user function it had
// guessed at. An editor that is confidently wrong about the standard library is
// worse than one that stays quiet, and this is the rule the project already
// holds itself to: a feature is not done when the compiler accepts it, it is
// done when the editor teaches it.

// dottedAndFlat is the pair every case below is built from: a builtin whose name
// has a family prefix, spelled both ways, with the column of the callee in each.
type dottedAndFlat struct {
	name        string // the flat builtin name
	dottedSrc   string // `hash.blake2("x");`
	dottedCol   int    // a column inside `blake2`
	flatSrc     string // `hash_blake2("x");`
	flatCol     int    // a column inside `hash_blake2`
	insideArgs  int    // a column inside the argument list, for signature help
	dottedInArg int
}

func namespacePairs() []dottedAndFlat {
	return []dottedAndFlat{
		{
			name:        "hash_blake2",
			dottedSrc:   "hash.blake2(\"x\");\n",
			dottedCol:   7,
			flatSrc:     "hash_blake2(\"x\");\n",
			flatCol:     3,
			insideArgs:  13,
			dottedInArg: 13,
		},
		{
			name:        "str_upper",
			dottedSrc:   "str.upper(\"x\");\n",
			dottedCol:   5,
			flatSrc:     "str_upper(\"x\");\n",
			flatCol:     3,
			insideArgs:  11,
			dottedInArg: 11,
		},
		{
			name:        "fs_read",
			dottedSrc:   "fs.read(\"p\");\n",
			dottedCol:   4,
			flatSrc:     "fs_read(\"p\");\n",
			flatCol:     3,
			insideArgs:  9,
			dottedInArg: 9,
		},
	}
}

// TestHoverTeachesADottedBuiltin. Hovering the member of a namespaced call has
// to reach the same card as hovering the flat name, because they are the same
// function: same contract, same parameters, same return.
func TestHoverTeachesADottedBuiltin(t *testing.T) {
	for _, pair := range namespacePairs() {
		flat, _, ok := New().Analyze(pair.flatSrc).
			HoverText(lsp.Position{Line: 0, Character: lsp.UInteger(pair.flatCol)})
		if !ok {
			t.Fatalf("%s: hovering the flat spelling produced nothing", pair.name)
		}

		dotted, _, ok := New().Analyze(pair.dottedSrc).
			HoverText(lsp.Position{Line: 0, Character: lsp.UInteger(pair.dottedCol)})
		if !ok {
			t.Errorf("%s: hovering the dotted spelling produced nothing", pair.name)
			continue
		}
		if strings.HasPrefix(dotted, "identifier `") {
			t.Errorf("%s: the dotted spelling hovers as a bare identifier, not a builtin:\n%s",
				pair.name, dotted)
			continue
		}
		if dotted != flat {
			t.Errorf("%s: the two spellings hover differently.\n--- dotted ---\n%s\n--- flat ---\n%s",
				pair.name, dotted, flat)
		}
	}
}

// TestSignatureHelpTeachesADottedBuiltin. Signature help had a switch over the
// callee with no arm for a field expression, so a dotted call fell to the
// default and returned nothing -- and the inlay hints that are built on it went
// with it.
func TestSignatureHelpTeachesADottedBuiltin(t *testing.T) {
	for _, pair := range namespacePairs() {
		flatSnap := New().Analyze(pair.flatSrc)
		flat, ok := flatSnap.SignatureHelp(lsp.Position{Line: 0, Character: lsp.UInteger(pair.insideArgs)})
		if !ok || flat == nil || len(flat.Signatures) == 0 {
			t.Fatalf("%s: the flat spelling offered no signature help", pair.name)
		}

		dottedSnap := New().Analyze(pair.dottedSrc)
		dotted, ok := dottedSnap.SignatureHelp(lsp.Position{Line: 0, Character: lsp.UInteger(pair.dottedInArg)})
		if !ok || dotted == nil || len(dotted.Signatures) == 0 {
			t.Errorf("%s: the dotted spelling offered no signature help", pair.name)
			continue
		}

		wantLabel := flat.Signatures[0].Label
		gotLabel := dotted.Signatures[0].Label
		if gotLabel != wantLabel {
			t.Errorf("%s: signature label differs.\n  dotted: %q\n  flat:   %q",
				pair.name, gotLabel, wantLabel)
		}
		if got, want := len(dotted.Signatures[0].Parameters), len(flat.Signatures[0].Parameters); got != want {
			t.Errorf("%s: the dotted spelling shows %d parameters, the flat one %d",
				pair.name, got, want)
		}
	}
}

// TestADottedBuiltinIsPaintedAsABuiltin. The callee of a dotted call was painted
// `property`, the colour of a struct field, because the semantic-token pass only
// recognised a builtin behind a bare identifier. Reading `fs.read` in one colour
// and `fs_read` in another says they are different things.
func TestADottedBuiltinIsPaintedAsABuiltin(t *testing.T) {
	function := semanticTokenTypeIndex["function"]
	library := semanticTokenModifierBit("defaultLibrary")

	for _, pair := range namespacePairs() {
		snapshot := New().Analyze(pair.dottedSrc)
		call := firstCall(t, snapshot)
		field, ok := call.Function.(*mast.FieldExpression)
		if !ok {
			t.Fatalf("%s: the dotted call's callee is %T, not a field expression", pair.name, call.Function)
		}

		overrides := map[mast.Node]semanticTokenOverride{}
		collectExpressionTokenOverrides(call, overrides)

		got, painted := overrides[mast.Node(field.Field)]
		if !painted {
			t.Errorf("%s: the dotted callee got no semantic token override at all", pair.name)
			continue
		}
		if got.typeID != function || got.modifier != library {
			t.Errorf("%s: the dotted callee is painted type=%d modifier=%d, want function=%d defaultLibrary=%d",
				pair.name, got.typeID, got.modifier, function, library)
		}
	}
}

// TestAShadowedNamespaceStillWins. The whole feature rests on a real binding
// beating the derived name -- that is what lets it be added without changing the
// meaning of any program written before it. If the editor teaches the builtin
// where the compiler would call the variable, it is teaching a lie.
func TestAShadowedNamespaceStillWins(t *testing.T) {
	const src = "let hash = {\"blake2\": 1};\nhash.blake2;\n"

	text, _, ok := New().Analyze(src).HoverText(lsp.Position{Line: 1, Character: 7})
	if !ok {
		return // nothing taught is an acceptable answer here; a wrong card is not
	}
	if strings.Contains(text, "BLAKE2") || strings.Contains(text, "builtin `hash_blake2") {
		t.Fatalf("a shadowed namespace still hovered as the builtin:\n%s", text)
	}
}

// TestEveryFamilyIsReachableBothWays walks the registry rather than a sample, so
// a family added later cannot quietly teach only one of its two spellings.
func TestEveryFamilyIsReachableBothWays(t *testing.T) {
	var checked int
	var unparsed []string

	for _, def := range builtin.Builtins {
		name := def.Name
		if name == "" {
			continue
		}
		family, member, found := strings.Cut(name, "_")
		if !found || family == "" || member == "" {
			continue
		}
		// A second underscore is fine: fs_read_bytes is fs.read_bytes, because
		// the fold is at the first one only.
		src := family + "." + member + "();\n"
		call, found := topLevelCall(New().Analyze(src))
		if !found {
			// A family or member that is also a keyword does not parse as a
			// call. That is a parser fact rather than a resolution failure, and
			// it is reported rather than skipped in silence.
			unparsed = append(unparsed, name)
			continue
		}

		resolved, _, ok := builtinCallee(call.Function, nil)
		if !ok || resolved != name {
			t.Errorf("%s: the dotted spelling %s.%s resolved to %q (ok=%t)",
				name, family, member, resolved, ok)
		}
		checked++
	}

	if checked == 0 {
		t.Fatal("no builtin had a family prefix; the walk is not exercising anything")
	}
	t.Logf("checked %d builtins reachable in both spellings; %d did not parse as a dotted call (%s)",
		checked, len(unparsed), strings.Join(unparsed, ", "))
}

// topLevelCall is firstCall without the t.Fatal: a walk over the whole registry
// has to be able to say which names did not parse, rather than stopping at the
// first one that did not.
func topLevelCall(snapshot *Snapshot) (*mast.CallExpression, bool) {
	if snapshot == nil || snapshot.Program == nil {
		return nil, false
	}
	for _, stmt := range snapshot.Program.Statements {
		expr, ok := stmt.(*mast.ExpressionStatement)
		if !ok || expr == nil {
			continue
		}
		if call, ok := expr.Expression.(*mast.CallExpression); ok && call != nil {
			return call, true
		}
	}
	return nil, false
}
