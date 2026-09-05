package builtin

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// legacyOrdinalsDigest pins the frozen table byte for byte.
//
// Failing here IS a defect, and this is the one allowlist-style test in the
// repository that does not end "update the constant and say why in the commit".
// The table maps the OpGetBuiltin operands of every .mu compiled before v2.5 to
// names; changing an entry rebinds calls in artifacts that already exist and
// cannot be recompiled. If a builtin has been renamed or retired, add an entry
// to Aliases -- that is what it is for.
const legacyOrdinalsDigest = "f489245dc33c4ff172a02a93186e04b96adff36e58a1389566808959a5dedc3b"

func TestLegacyBuiltinOrdinalsAreFrozen(t *testing.T) {
	h := sha256.New()
	for _, name := range legacyBuiltinOrdinals {
		h.Write([]byte(name))
		h.Write([]byte{0})
	}
	got := hex.EncodeToString(h.Sum(nil))

	if legacyOrdinalsDigest == "" {
		t.Fatalf("legacyOrdinalsDigest is unset; pin it to %q", got)
	}
	if got != legacyOrdinalsDigest {
		t.Fatalf("the frozen ordinal table changed.\n got  %s\n want %s\n\n"+
			"This table is the only thing that keeps pre-v2.5 .mu files loadable: its indices are "+
			"OpGetBuiltin operands baked into artifacts that cannot be recompiled. Do not update the "+
			"digest. Revert the change to builtin/legacy_ordinals.go; to rename or retire a builtin, "+
			"add an entry to Aliases instead.", got, legacyOrdinalsDigest)
	}
}

func TestEveryLegacyOrdinalStillResolves(t *testing.T) {
	for ordinal, name := range legacyBuiltinOrdinals {
		if _, ok := ResolveName(name); !ok {
			t.Errorf("legacy ordinal %d (%q) no longer resolves: every .mu compiled before v2.5 that "+
				"calls it will fail to load. Add Aliases[%q] naming its replacement.", ordinal, name, name)
		}
	}
}

func TestResolveLegacyOrdinalsCoversTheWholeFrozenTable(t *testing.T) {
	resolved, err := ResolveLegacyOrdinals()
	if err != nil {
		t.Fatalf("ResolveLegacyOrdinals: %v", err)
	}
	if len(resolved) != LegacyOrdinalCount() {
		t.Fatalf("resolved %d entries, want %d", len(resolved), LegacyOrdinalCount())
	}
	for i, fn := range resolved {
		if fn == nil {
			name, _ := LegacyOrdinalName(i)
			t.Fatalf("ordinal %d (%q) resolved to nil", i, name)
		}
	}
}

func TestLegacyOrdinalNameRejectsAnOutOfRangeOrdinal(t *testing.T) {
	for _, ordinal := range []int{-1, LegacyOrdinalCount(), LegacyOrdinalCount() + 1} {
		if name, ok := LegacyOrdinalName(ordinal); ok {
			t.Fatalf("LegacyOrdinalName(%d) returned %q; that ordinal was never valid", ordinal, name)
		}
	}
}

// TestAliasesDoNotShadowLiveBuiltins keeps Aliases from quietly becoming a
// synonym table. An alias exists to keep old bytecode loading after a rename; an
// alias for a name that is still registered means the rename never happened, and
// resolution would silently prefer the registry entry anyway.
func TestAliasesDoNotShadowLiveBuiltins(t *testing.T) {
	for retired, replacement := range Aliases {
		if GetBuiltinByName(retired) != nil {
			t.Errorf("Aliases[%q] aliases a name that is still in the registry; remove the alias or "+
				"remove the registry entry", retired)
		}
		if GetBuiltinByName(replacement) == nil {
			t.Errorf("Aliases[%q] points at %q, which is not registered", retired, replacement)
		}
		if retired == replacement {
			t.Errorf("Aliases[%q] points at itself", retired)
		}
	}
}

func TestResolveNamesNamesTheMissingBuiltin(t *testing.T) {
	_, err := ResolveNames([]string{"len", "csv_parse", "putln"})
	if err == nil {
		t.Fatal("resolving an unknown builtin succeeded")
	}
	if !strings.Contains(err.Error(), "csv_parse") {
		t.Fatalf("the error must name the builtin it could not find; got: %v", err)
	}
}

func TestResolveNamesReturnsTheFunctionsInOrder(t *testing.T) {
	resolved, err := ResolveNames([]string{"push", "len"})
	if err != nil {
		t.Fatalf("ResolveNames: %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("resolved %d, want 2", len(resolved))
	}
	if resolved[0] != GetBuiltinByName("push") || resolved[1] != GetBuiltinByName("len") {
		t.Fatal("ResolveNames must preserve the order of the names it was given")
	}
}

// TestARenamedBuiltinResolvesThroughItsAlias is the renaming contract: a
// builtin can be given a new name and bytecode that calls it by the old one
// still loads.
func TestARenamedBuiltinResolvesThroughItsAlias(t *testing.T) {
	const retired = "text_contains_deprecated_spelling"

	if _, ok := ResolveName(retired); ok {
		t.Fatalf("%q is registered; pick a name for this test that is not", retired)
	}

	Aliases[retired] = "text_contains"
	defer delete(Aliases, retired)

	fn, ok := ResolveName(retired)
	if !ok {
		t.Fatal("a retired name with an alias must still resolve")
	}
	if fn != GetBuiltinByName("text_contains") {
		t.Fatal("the alias resolved to something other than its replacement")
	}

	resolved, err := ResolveNames([]string{retired})
	if err != nil {
		t.Fatalf("ResolveNames on an aliased name: %v", err)
	}
	if len(resolved) != 1 || resolved[0] != GetBuiltinByName("text_contains") {
		t.Fatal("ResolveNames did not follow the alias")
	}
}

func TestAliasesDoNotChainIndefinitely(t *testing.T) {
	// One hop only: a chain would let a rename history accumulate into an
	// unbounded lookup, and a cycle would hang.
	Aliases["mutant_test_alias_a"] = "mutant_test_alias_b"
	Aliases["mutant_test_alias_b"] = "len"
	defer func() {
		delete(Aliases, "mutant_test_alias_a")
		delete(Aliases, "mutant_test_alias_b")
	}()

	if _, ok := ResolveName("mutant_test_alias_a"); ok {
		t.Fatal("ResolveName followed a chain of aliases; it must follow exactly one hop")
	}
}
