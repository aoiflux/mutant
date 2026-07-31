package builtin

import (
	"bufio"
	"strings"
	"testing"

	"mutant/object"
)

func TestReadStdinLineReadsFullLine(t *testing.T) {
	// gets() must return a whole line (with spaces), not a single token.
	r := bufio.NewReader(strings.NewReader("hello brave world\nsecond line\n"))
	line, err := readStdinLine(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != "hello brave world" {
		t.Fatalf("expected full line, got %q", line)
	}
	// A trailing line without a newline (EOF) is still returned.
	r2 := bufio.NewReader(strings.NewReader("no newline"))
	if line, err := readStdinLine(r2); err != nil || line != "no newline" {
		t.Fatalf("EOF line: got %q err %v", line, err)
	}
	// CRLF is trimmed.
	r3 := bufio.NewReader(strings.NewReader("windows\r\n"))
	if line, _ := readStdinLine(r3); line != "windows" {
		t.Fatalf("CRLF not trimmed: %q", line)
	}
}

func TestPopEmptyArrayDoesNotPanic(t *testing.T) {
	// Previously make([]object.Object, length-1) with length==0 panicked.
	res := Pop(&object.Array{Elements: []object.Object{}})
	if _, isErr := res.(*object.Error); isErr {
		t.Fatalf("pop([]) should not error, got %s", res.Inspect())
	}
	if res != nil {
		t.Fatalf("pop([]) should return nil (NULL), got %T", res)
	}
}

func TestPopSingleElementReturnsEmptyArray(t *testing.T) {
	res := Pop(&object.Array{Elements: []object.Object{intObj(1)}})
	arr, ok := res.(*object.Array)
	if !ok {
		t.Fatalf("pop([x]) should return an ARRAY, got %T", res)
	}
	if len(arr.Elements) != 0 {
		t.Fatalf("pop([x]) should return empty array, got %d elements", len(arr.Elements))
	}
}

func TestRestSingleElementReturnsEmptyArray(t *testing.T) {
	res := Rest(&object.Array{Elements: []object.Object{intObj(1)}})
	arr, ok := res.(*object.Array)
	if !ok {
		t.Fatalf("rest([x]) should return an ARRAY, got %T", res)
	}
	if len(arr.Elements) != 0 {
		t.Fatalf("rest([x]) should return empty array, got %d elements", len(arr.Elements))
	}
}

func TestLenSupportsHash(t *testing.T) {
	h := makeHashObject(map[string]object.Object{"a": intObj(1), "b": intObj(2)})
	res := Len(h)
	i, ok := res.(*object.Integer)
	if !ok {
		t.Fatalf("len(hash) should return INTEGER, got %T (%s)", res, res.Inspect())
	}
	if i.Value != 2 {
		t.Fatalf("len(hash) expected 2, got %d", i.Value)
	}
}

func TestRegexFindDistinguishesEmptyMatch(t *testing.T) {
	// Pattern "a*" matches the empty string at the start of "b": a real (empty)
	// match, which must NOT be reported as "no match" (NULL).
	payload, errObj := unwrapPair(t, RegexFind(stringObj("a*"), stringObj("b")))
	if errObj != nil {
		t.Fatalf("regex_find error: %s", errObj.Inspect())
	}
	if _, isNull := payload.(*object.Null); isNull {
		t.Fatalf("regex_find should report the empty match, not NULL")
	}
	s, ok := payload.(*object.String)
	if !ok || s.Value != "" {
		t.Fatalf("expected empty-string match, got %T %q", payload, payload.Inspect())
	}

	// A genuine non-match still returns NULL.
	payload2, errObj := unwrapPair(t, RegexFind(stringObj("xyz"), stringObj("b")))
	if errObj != nil {
		t.Fatalf("regex_find error: %s", errObj.Inspect())
	}
	if _, isNull := payload2.(*object.Null); !isNull {
		t.Fatalf("expected NULL for a real non-match, got %T", payload2)
	}
}
