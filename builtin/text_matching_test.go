package builtin

import (
	"reflect"
	"strings"
	"testing"

	"mutant/object"
)

func TestTextContains(t *testing.T) {
	result := TextContains(stringObj("incident-response"), stringObj("response"))
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	boolPayload, ok := payload.(*object.Boolean)
	if !ok {
		t.Fatalf("payload is not BOOLEAN. got=%T", payload)
	}
	if !boolPayload.Value {
		t.Fatalf("expected true, got false")
	}
}

func TestTextIndex(t *testing.T) {
	result := TextIndex(stringObj("abcabc"), stringObj("cab"))
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	intPayload, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("payload is not INTEGER. got=%T", payload)
	}
	if intPayload.Value != 2 {
		t.Fatalf("unexpected index. got=%d, want=2", intPayload.Value)
	}
}

func TestTextCount(t *testing.T) {
	result := TextCount(stringObj("aaaa"), stringObj("aa"))
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	intPayload, ok := payload.(*object.Integer)
	if !ok {
		t.Fatalf("payload is not INTEGER. got=%T", payload)
	}
	if intPayload.Value != 2 {
		t.Fatalf("unexpected count. got=%d, want=2", intPayload.Value)
	}
}

func TestTextSplit(t *testing.T) {
	result := TextSplit(stringObj("a,b,c"), stringObj(","))
	payload, errObj := unwrapSingleOrPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	arr, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("payload is not ARRAY. got=%T", payload)
	}

	actual := make([]string, len(arr.Elements))
	for i, el := range arr.Elements {
		strObj, ok := el.(*object.String)
		if !ok {
			t.Fatalf("array element %d is not STRING. got=%T", i, el)
		}
		actual[i] = strObj.Value
	}

	expected := []string{"a", "b", "c"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("unexpected split result. got=%v, want=%v", actual, expected)
	}
}

func TestTextReplace(t *testing.T) {
	tests := []struct {
		name     string
		args     []object.Object
		expected string
	}{
		{
			name:     "replace all",
			args:     []object.Object{stringObj("ioc ioc ioc"), stringObj("ioc"), stringObj("indicator")},
			expected: "indicator indicator indicator",
		},
		{
			name:     "replace first two",
			args:     []object.Object{stringObj("a-a-a"), stringObj("a"), stringObj("x"), intObj(2)},
			expected: "x-x-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TextReplace(tt.args...)
			payload, errObj := unwrapSingleOrPair(t, result)
			if errObj != nil {
				t.Fatalf("unexpected error: %s", errObj.Inspect())
			}

			strPayload, ok := payload.(*object.String)
			if !ok {
				t.Fatalf("payload is not STRING. got=%T", payload)
			}
			if strPayload.Value != tt.expected {
				t.Fatalf("unexpected replace result. got=%q, want=%q", strPayload.Value, tt.expected)
			}
		})
	}
}

func TestTextBuiltinsTypeErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{
			name: "contains wrong type",
			call: func() object.Object { return TextContains(intObj(1), stringObj("x")) },
		},
		{
			name: "replace bad count type",
			call: func() object.Object {
				return TextReplace(stringObj("a"), stringObj("a"), stringObj("b"), stringObj("1"))
			},
		},
		{
			name: "split wrong arity",
			call: func() object.Object { return TextSplit(stringObj("a,b,c")) },
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
