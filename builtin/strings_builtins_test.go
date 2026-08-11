package builtin

import (
	"testing"

	"mutant/object"
)

func strResult(t *testing.T, res object.Object) string {
	t.Helper()
	if e, ok := res.(*object.Error); ok {
		t.Fatalf("unexpected error: %s", e.Message)
	}
	s, ok := res.(*object.String)
	if !ok {
		t.Fatalf("expected STRING, got %T (%s)", res, res.Inspect())
	}
	return s.Value
}

func strBool(t *testing.T, res object.Object) bool {
	t.Helper()
	b, ok := res.(*object.Boolean)
	if !ok {
		t.Fatalf("expected BOOLEAN, got %T (%s)", res, res.Inspect())
	}
	return b.Value
}

func TestStringBuiltins(t *testing.T) {
	cases := []struct {
		name string
		got  object.Object
		want string
	}{
		{"upper", StrUpper(stringObj("Mutant")), "MUTANT"},
		{"lower", StrLower(stringObj("Mutant")), "mutant"},
		{"trim", StrTrim(stringObj("  hi \t")), "hi"},
		{"trim_left", StrTrimLeft(stringObj("xxhi"), stringObj("x")), "hi"},
		{"trim_right", StrTrimRight(stringObj("hixx"), stringObj("x")), "hi"},
		{"trim_prefix", StrTrimPrefix(stringObj("hxxp://x"), stringObj("hxxp")), "://x"},
		{"trim_suffix", StrTrimSuffix(stringObj("file.exe"), stringObj(".exe")), "file"},
		{"join", StrJoin(&object.Array{Elements: []object.Object{stringObj("a"), stringObj("b"), stringObj("c")}}, stringObj("-")), "a-b-c"},
		{"repeat", StrRepeat(stringObj("ab"), intObj(3)), "ababab"},
		{"pad_left", StrPadLeft(stringObj("7"), intObj(3), stringObj("0")), "007"},
		{"pad_right", StrPadRight(stringObj("7"), intObj(3), stringObj("0")), "700"},
		{"pad_left_nochange", StrPadLeft(stringObj("abcd"), intObj(3), stringObj("0")), "abcd"},
		{"reverse", StrReverse(stringObj("straße")), "eßarts"},
		{"substr", StrSubstr(stringObj("mutant"), intObj(1), intObj(3)), "uta"},
		{"substr_clamp", StrSubstr(stringObj("mut"), intObj(1), intObj(99)), "ut"},
		{"char_at", StrCharAt(stringObj("mutant"), intObj(0)), "m"},
		{"format", StrFormat(stringObj("%s=%d"), stringObj("x"), intObj(42)), "x=42"},
		{"title", StrTitle(stringObj("hello brave world")), "Hello Brave World"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := strResult(t, c.got); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}

	if !strBool(t, StrStartsWith(stringObj("hxxp://x"), stringObj("hxxp"))) {
		t.Fatal("str_starts_with should be true")
	}
	if strBool(t, StrStartsWith(stringObj("http://x"), stringObj("hxxp"))) {
		t.Fatal("str_starts_with should be false")
	}
	if !strBool(t, StrEndsWith(stringObj("a.exe"), stringObj(".exe"))) {
		t.Fatal("str_ends_with should be true")
	}
}

func TestStringBuiltinArgErrors(t *testing.T) {
	calls := map[string]object.Object{
		"upper wrong count":  StrUpper(),
		"upper wrong type":   StrUpper(intObj(1)),
		"join not array":     StrJoin(stringObj("x"), stringObj("-")),
		"repeat negative":    StrRepeat(stringObj("a"), intObj(-1)),
		"char_at oob":        StrCharAt(stringObj("ab"), intObj(9)),
		"substr negative":    StrSubstr(stringObj("ab"), intObj(-1), intObj(1)),
		"pad empty padding":  StrPadLeft(stringObj("a"), intObj(4), stringObj("")),
	}
	for name, res := range calls {
		t.Run(name, func(t *testing.T) {
			if _, ok := res.(*object.Error); !ok {
				t.Fatalf("expected ERROR, got %T (%s)", res, res.Inspect())
			}
		})
	}
}
