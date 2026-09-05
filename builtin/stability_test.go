package builtin

import "testing"

func TestStabilityTiersAreOneOfTheThree(t *testing.T) {
	for name, doc := range builtinDocs {
		switch doc.stability {
		case "", StabilityStable, StabilityExperimental, StabilityDeprecated:
		default:
			t.Errorf("%s declares stability %q, which is not a tier", name, doc.stability)
		}
	}
}

// TestDeprecatedBuiltinsNameTheirReplacement is what makes the tier actionable.
// "Deprecated" on its own tells a reader to stop and gives them nowhere to go;
// the editor surfaces the replacement, so there has to be one.
func TestDeprecatedBuiltinsNameTheirReplacement(t *testing.T) {
	for name, doc := range builtinDocs {
		if doc.stability != StabilityDeprecated {
			continue
		}
		if doc.replacement == "" {
			t.Errorf("%s is deprecated but names no replacement", name)
			continue
		}
		if doc.replacement == name {
			t.Errorf("%s names itself as its replacement", name)
		}
		if GetBuiltinByName(doc.replacement) == nil {
			t.Errorf("%s names %q as its replacement, which is not a registered builtin",
				name, doc.replacement)
		}
	}
}

// TestReplacementIsOnlyMeaningfulForDeprecated keeps the two fields from drifting
// apart: a replacement on a stable builtin would be dead data that no consumer
// reads, and would read as a deprecation that was never declared.
func TestReplacementIsOnlyMeaningfulForDeprecated(t *testing.T) {
	for name, doc := range builtinDocs {
		if doc.replacement != "" && doc.stability != StabilityDeprecated {
			t.Errorf("%s names a replacement but is not deprecated (stability %q)",
				name, doc.stability)
		}
	}
}

func TestStabilityOfDefaultsToStable(t *testing.T) {
	if tier, ok := StabilityOf("len"); !ok || tier != StabilityStable {
		t.Fatalf("StabilityOf(len) = %q, %v; want stable, true", tier, ok)
	}
	// An undocumented name reports stable and false: absent any declaration,
	// there is no promise to report as withdrawn.
	if tier, ok := StabilityOf("no_such_builtin"); ok || tier != StabilityStable {
		t.Fatalf("StabilityOf(unknown) = %q, %v; want stable, false", tier, ok)
	}
}

func TestDeprecatedByIsFalseForLiveBuiltins(t *testing.T) {
	for _, name := range []string{"len", "putln", "net_connect_scan", "no_such_builtin"} {
		if replacement, deprecated := DeprecatedBy(name); deprecated {
			t.Errorf("DeprecatedBy(%q) reported a deprecation, replacement %q", name, replacement)
		}
	}
}

// TestTheDeprecatedAliasIsDeclared pins the one builtin L-1 names: net_syn_scan
// was kept in the registry purely to hold an ordinal, since an ordinal in the
// bytecode could never be vacated. Now that operands carry names, the tier says
// so out loud.
func TestTheDeprecatedAliasIsDeclared(t *testing.T) {
	replacement, deprecated := DeprecatedBy(BuiltinNameNetSynScan)
	if !deprecated {
		t.Fatalf("%s is documented as a deprecated alias but does not declare the tier",
			BuiltinNameNetSynScan)
	}
	if replacement != BuiltinNameNetConnectScan {
		t.Fatalf("replacement = %q, want %q", replacement, BuiltinNameNetConnectScan)
	}
}
