package builtin

import (
	"slices"
	"strings"
	"testing"
)

// These are the tests that keep the macro-expansion boundary from decaying. The
// boundary itself is data, and data goes stale silently: a builtin added next
// year is neither allowed nor refused unless somebody is made to decide, and a
// refusal rule that stops matching anything stops protecting anything.

// TestEveryBuiltinIsClassifiedForMacroExpansion is the drift guard. It is the
// sibling of TestResourceFamiliesCoverEveryCloser, which already requires every
// *_close in this registry to be a declared family or an entry carrying a
// reason: default-deny, a test red until somebody classifies, and a reason that
// cannot be left blank.
func TestEveryBuiltinIsClassifiedForMacroExpansion(t *testing.T) {
	unclassified := MacroUnclassified()
	if len(unclassified) == 0 {
		return
	}
	t.Fatalf(`%d builtin(s) have no macro-expansion classification: %s

A macro body runs while the compiler is running, so every builtin has to be
either safe to run there or refused with a reason. Decide for each name above:

  - safe: add it to macroSafeBuiltins in builtin/macro_safety.go, and only if
    all six clauses of the membership test in that file's header hold for it;
  - not safe: make sure a rule in macroRefusals answers for it, either by name
    or by a family prefix, and that the reason says what it would actually do.

There is no third answer, and no default. MacroSafe already refuses these names
at expansion time -- this test is about saying why.`,
		len(unclassified), strings.Join(unclassified, ", "))
}

// TestEveryMacroSafeNameIsRegistered catches a typo and a stale entry. A name in
// macroSafeBuiltins that no longer exists is not harmless: it reads as a
// decision somebody made, and it hides the fact that the real builtin is now
// unclassified.
func TestEveryMacroSafeNameIsRegistered(t *testing.T) {
	registered := make(map[string]struct{}, len(Builtins))
	for _, def := range Builtins {
		registered[def.Name] = struct{}{}
	}
	for _, name := range macroSafeBuiltins {
		if _, ok := registered[name]; !ok {
			t.Errorf("macroSafeBuiltins holds %q, which is not a registered builtin", name)
		}
	}
	if n := len(slices.Compact(slices.Clone(sortedCopy(macroSafeBuiltins)))); n != len(macroSafeBuiltins) {
		t.Errorf("macroSafeBuiltins holds a name twice: %d entries, %d distinct", len(macroSafeBuiltins), n)
	}
}

// TestEveryMacroRefusalRuleIsLoadBearing is what stops one line retiring the
// drift guard. macroRefusals is a first-match-wins prefix table, and
// strings.HasPrefix(anything, "") is true -- so a single entry with an empty
// prefix would make MacroUnclassified empty for ever, leaving MacroSafe still
// correct but the review gate silently dead. The same is true, more slowly, of
// any prefix broad enough to swallow a family somebody should have looked at.
//
// So: every rule must say something, must answer for a real builtin, and must be
// the only rule that answers for at least one of them.
func TestEveryMacroRefusalRuleIsLoadBearing(t *testing.T) {
	for i, rule := range macroRefusals {
		switch {
		case rule.name == "" && rule.prefix == "":
			t.Errorf("macroRefusals[%d] matches every name, which would retire the drift guard", i)
		case rule.name != "" && rule.prefix != "":
			t.Errorf("macroRefusals[%d] sets both a name and a prefix; pick one", i)
		case strings.TrimSpace(rule.why) == "":
			t.Errorf("macroRefusals[%d] (%s%s) gives no reason", i, rule.name, rule.prefix)
		}
	}

	answersFor := make(map[int][]string)
	for _, def := range Builtins {
		if def.Name == "" || MacroSafe(def.Name) {
			continue
		}
		if idx := macroRefusalRule(def.Name); idx >= 0 {
			answersFor[idx] = append(answersFor[idx], def.Name)
		}
	}
	for i, rule := range macroRefusals {
		if len(answersFor[i]) == 0 {
			t.Errorf("macroRefusals[%d] (%s%s) answers for no registered builtin: "+
				"remove it rather than leaving a rule that protects nothing. A builtin added later "+
				"is caught by TestEveryBuiltinIsClassifiedForMacroExpansion, which is the right "+
				"place for it -- a speculative prefix here only hides the decision.",
				i, rule.name, rule.prefix)
		}
	}
}

// TestNoMacroSafeBuiltinDeclaresAPath is a derived check this repository already
// owns: webrepl.takesHostPath reads the declared parameter names, and it is what
// keeps plist_parse and imphash out of the browser REPL. Reading the same
// declaration here means a path-taking builtin added to macroSafeBuiltins is red
// straight away, without waiting on the purity walk.
func TestNoMacroSafeBuiltinDeclaresAPath(t *testing.T) {
	for _, name := range macroSafeBuiltins {
		specs, ok := ParamSpecs(name)
		if !ok {
			continue
		}
		for _, param := range specs {
			n := strings.TrimSuffix(strings.ToLower(param.Name), "?")
			if n == "path" || n == "paths" || n == "dir" || n == "file" ||
				strings.HasSuffix(n, "path") || strings.Contains(n, "_path") ||
				strings.Contains(n, "file") {
				t.Errorf("%s is macro-safe but declares %q, which names something on disk", name, param.Name)
			}
		}
	}
}

// TestMacroRefusalAnswersForEveryRefusedBuiltin holds the other half of the
// contract MacroRefusal promises: "" exactly when the builtin is safe, and a
// sentence every other time. The expander prints that sentence, so an empty one
// would ship a refusal with no reason in it.
func TestMacroRefusalAnswersForEveryRefusedBuiltin(t *testing.T) {
	for _, def := range Builtins {
		if def.Name == "" {
			continue
		}
		why := MacroRefusal(def.Name)
		if MacroSafe(def.Name) {
			if why != "" {
				t.Errorf("%s is macro-safe but MacroRefusal gives a reason: %q", def.Name, why)
			}
			continue
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s is refused during macro expansion with no reason given", def.Name)
		}
	}
	if why := MacroRefusal("not_a_builtin_at_all"); why == "" {
		t.Error("MacroRefusal answers \"\" for a name that is not a builtin, which reads as allowed")
	}
	if MacroSafe("") {
		t.Error("MacroSafe allows the empty name")
	}
}

// TestTheOnlyMacroSafeExecutorNativesAreTheOnesThatJustCallBack pins clause 5.
// An executor-native builtin is run by the engine rather than through its
// registered Fn, so allowing one is allowing whatever the engine does for it.
// Five of them only call a user function, which this engine then evaluates under
// the same restriction; two answer a constant empty pair. Anything else arriving
// on this list is a decision that needs making by hand, not by category.
func TestTheOnlyMacroSafeExecutorNativesAreTheOnesThatJustCallBack(t *testing.T) {
	want := []string{
		BuiltinNameMap, BuiltinNameFilter, BuiltinNameReduce, BuiltinNameEach, BuiltinNameSortBy,
		BuiltinNameServeConn, BuiltinNameServeArg,
	}
	var got []string
	for _, def := range Builtins {
		if def.Builtin == nil || !MacroSafe(def.Name) {
			continue
		}
		if ExecutorNativeKind(def.Builtin) != "" {
			got = append(got, def.Name)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the macro-safe executor-natives changed\n got: %v\nwant: %v\n"+
			"Allowing an executor-native allows what the engine does for it, not what its Fn does. "+
			"If a new one belongs here, say in macro_safety.go's header why its only effect is "+
			"calling a function this engine evaluates.", got, want)
	}
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}
