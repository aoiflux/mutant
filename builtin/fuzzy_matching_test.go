package builtin

import (
	"math"
	"strings"
	"testing"

	"mutant/object"
)

func TestTextLevenshtein(t *testing.T) {
	result := TextLevenshtein(stringObj("kitten"), stringObj("sitting"))
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	value, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("payload is not INTEGER. got=%T", payload)
	}
	if value.Value != 3 {
		t.Fatalf("unexpected distance. got=%d, want=3", value.Value)
	}
}

func TestTextSimilarity(t *testing.T) {
	result := TextSimilarity(stringObj("abc"), stringObj("abc"))
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	value, ok := payload.(*object.Float)
	if !ok {
		t.Fatalf("payload is not FLOAT. got=%T", payload)
	}
	if math.Abs(value.Value-1.0) > 1e-9 {
		t.Fatalf("unexpected similarity. got=%f, want=1.0", value.Value)
	}
}

func TestTextFuzzyFind(t *testing.T) {
	candidates := &object.Array{Elements: []object.Object{
		stringObj("powershell"),
		stringObj("rundll32"),
		stringObj("cmd"),
	}}

	result := TextFuzzyFind(stringObj("powrshell"), candidates)
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hashPayload, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH. got=%T", payload)
	}

	foundObj := mustHashValueByStringKey(t, hashPayload, "found")
	found, ok := foundObj.(*object.Boolean)
	if !ok || !found.Value {
		t.Fatalf("expected found=true, got=%T (%v)", foundObj, foundObj.Inspect())
	}

	matchObj := mustHashValueByStringKey(t, hashPayload, "match")
	match, ok := matchObj.(*object.String)
	if !ok {
		t.Fatalf("match is not STRING. got=%T", matchObj)
	}
	if match.Value != "powershell" {
		t.Fatalf("unexpected best match. got=%q, want=%q", match.Value, "powershell")
	}
}

func TestTextFuzzyFindNoMatchWithinThreshold(t *testing.T) {
	candidates := &object.Array{Elements: []object.Object{
		stringObj("abc"),
		stringObj("def"),
	}}

	result := TextFuzzyFind(stringObj("zzzz"), candidates, intObj(1))
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hashPayload, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH. got=%T", payload)
	}

	foundObj := mustHashValueByStringKey(t, hashPayload, "found")
	found, ok := foundObj.(*object.Boolean)
	if !ok {
		t.Fatalf("found is not BOOLEAN. got=%T", foundObj)
	}
	if found.Value {
		t.Fatalf("expected found=false")
	}
}

func TestTextJaroWinkler(t *testing.T) {
	result := TextJaroWinkler(stringObj("martha"), stringObj("marhta"))
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	value, ok := payload.(*object.Float)
	if !ok {
		t.Fatalf("payload is not FLOAT. got=%T", payload)
	}
	if value.Value < 0.95 || value.Value > 0.97 {
		t.Fatalf("unexpected Jaro-Winkler score. got=%f, want around 0.961", value.Value)
	}
}

func TestFuzzyBuiltinsTypeErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{
			name: "levenshtein wrong type",
			call: func() object.Object { return TextLevenshtein(intObj(1), stringObj("x")) },
		},
		{
			name: "fuzzy find candidate wrong type",
			call: func() object.Object {
				return TextFuzzyFind(stringObj("abc"), &object.Array{Elements: []object.Object{intObj(1)}})
			},
		},
		{
			name: "jaro winkler wrong arity",
			call: func() object.Object { return TextJaroWinkler(stringObj("a")) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.call()
			_, errObj := unwrapSingleOrPair(t, result)
			if errObj == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(errObj.Message, "text_") && !strings.Contains(errObj.Message, "wrong number of arguments") {
				t.Fatalf("unexpected error message: %s", errObj.Message)
			}
		})
	}
}

func mustHashValueByStringKey(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()

	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing hash key %q", key)
	}
	return pair.Value
}
