package builtin

import (
	"reflect"
	"strings"
	"testing"

	"mutant/object"
)

func TestRegexMatch(t *testing.T) {
	result := RegexMatch(stringObj("^adm.*"), stringObj("admin"))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	boolPayload, ok := payload.(*object.Boolean)
	if !ok {
		t.Fatalf("payload is not BOOLEAN. got=%T", payload)
	}
	if !boolPayload.Value {
		t.Fatalf("expected regex to match")
	}
}

func TestRegexFind(t *testing.T) {
	result := RegexFind(stringObj("[0-9]+"), stringObj("pid=4242 user=svc"))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	strPayload, ok := payload.(*object.String)
	if !ok {
		t.Fatalf("payload is not STRING. got=%T", payload)
	}
	if strPayload.Value != "4242" {
		t.Fatalf("unexpected match. got=%q, want=%q", strPayload.Value, "4242")
	}
}

func TestRegexFindNoMatchReturnsNull(t *testing.T) {
	result := RegexFind(stringObj("[0-9]+"), stringObj("no-digits"))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}
	if payload.Type() != object.NULL_OBJ {
		t.Fatalf("payload is not NULL. got=%s", payload.Type())
	}
}

func TestRegexFindAll(t *testing.T) {
	result := RegexFindAll(stringObj("ioc-[0-9]+"), stringObj("ioc-1 x ioc-22 y ioc-333"))
	payload, errObj := unwrapPair(t, result)
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
			t.Fatalf("element %d is not STRING. got=%T", i, el)
		}
		actual[i] = strObj.Value
	}

	expected := []string{"ioc-1", "ioc-22", "ioc-333"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("unexpected matches. got=%v, want=%v", actual, expected)
	}
}

func TestRegexFindAllWithLimit(t *testing.T) {
	result := RegexFindAll(stringObj("ioc-[0-9]+"), stringObj("ioc-1 ioc-2 ioc-3"), intObj(2))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	arr, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("payload is not ARRAY. got=%T", payload)
	}
	if len(arr.Elements) != 2 {
		t.Fatalf("unexpected number of matches. got=%d, want=2", len(arr.Elements))
	}
}

func TestRegexReplace(t *testing.T) {
	result := RegexReplace(stringObj("[0-9]+"), stringObj("pid=4242"), stringObj("XXXX"))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	strPayload, ok := payload.(*object.String)
	if !ok {
		t.Fatalf("payload is not STRING. got=%T", payload)
	}
	if strPayload.Value != "pid=XXXX" {
		t.Fatalf("unexpected replaced value. got=%q, want=%q", strPayload.Value, "pid=XXXX")
	}
}

func TestRegexCaptureGroups(t *testing.T) {
	result := RegexCaptureGroups(stringObj("user=([a-z]+):([0-9]+)"), stringObj("user=admin:9001"))
	payload, errObj := unwrapPair(t, result)
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
			t.Fatalf("element %d is not STRING. got=%T", i, el)
		}
		actual[i] = strObj.Value
	}

	expected := []string{"user=admin:9001", "admin", "9001"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("unexpected capture groups. got=%v, want=%v", actual, expected)
	}
}

func TestRegexBuiltinsTypeAndPatternErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{
			name: "match wrong arg type",
			call: func() object.Object { return RegexMatch(intObj(1), stringObj("abc")) },
		},
		{
			name: "find all wrong limit type",
			call: func() object.Object { return RegexFindAll(stringObj("a"), stringObj("a"), stringObj("2")) },
		},
		{
			name: "replace invalid regex",
			call: func() object.Object { return RegexReplace(stringObj("["), stringObj("abc"), stringObj("x")) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.call()
			_, errObj := unwrapPair(t, result)
			if errObj == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(errObj.Message, "regex_") && !strings.Contains(errObj.Message, "wrong number of arguments") {
				t.Fatalf("unexpected error message: %s", errObj.Message)
			}
		})
	}
}
