package builtin

import "testing"

func linearLookup(name string) *BuiltIn {
	for _, entry := range Builtins {
		if entry.Name == name {
			return entry.Builtin
		}
	}
	return nil
}

func TestGetBuiltinByNameMatchesLinearLookupForRegistry(t *testing.T) {
	for _, entry := range Builtins {
		got := GetBuiltinByName(entry.Name)
		want := linearLookup(entry.Name)
		if got != want {
			t.Fatalf("lookup mismatch for %q", entry.Name)
		}
	}
}

func TestGetBuiltinByNameUnknownReturnsNil(t *testing.T) {
	if got := GetBuiltinByName("__definitely_not_a_builtin__"); got != nil {
		t.Fatalf("expected nil for unknown builtin, got=%T", got)
	}
}

func TestGetBuiltinByNameFindsLateAddedEntries(t *testing.T) {
	original := Builtins
	defer func() { Builtins = original }()

	first := &BuiltIn{}
	second := &BuiltIn{}
	Builtins = append(Builtins,
		BuiltinDefinition{Name: "__late_lookup_test__", Builtin: first},
		BuiltinDefinition{Name: "__late_lookup_test__", Builtin: second},
	)

	got := GetBuiltinByName("__late_lookup_test__")
	if got != first {
		t.Fatalf("expected first late-added builtin to win; got=%p want=%p", got, first)
	}
}
