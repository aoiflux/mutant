package sema

import (
	"slices"
	"testing"
)

// The precedence in ResolveField is the language's, not an implementation
// detail, so it is pinned here rather than left to the compiler tests that
// happen to exercise it. Each case names the rule it stands for.

// ctx builds a ScopeCtx from plain data, so a test reads as the situation it
// describes rather than as four closures.
type fixture struct {
	module     string
	enums      []string
	namespaces map[string]string // alias -> module key
	bound      []string
	exports    map[string][]string // module key -> declared top-level names
	unknown    []string            // module keys whose declarations are NOT loaded
	displays   map[string]string
}

func (f fixture) ctx() ScopeCtx {
	has := slices.Contains[[]string, string]

	c := ScopeCtx{
		Module: f.module,
		Enums:  func(name string) bool { return has(f.enums, name) },
		Bound:  func(name string) bool { return has(f.bound, name) },
		Namespace: func(alias string) (string, bool) {
			key, bound := f.namespaces[alias]
			return key, bound
		},
		Exports: func(key, name string) (ExportFact, bool) {
			if !has(f.exports[key], name) {
				return ExportFact{}, false
			}
			return ExportFact{Name: name, Private: IsModulePrivate(name)}, true
		},
		ModuleName: func(key string) string { return f.displays[key] },
	}

	if len(f.unknown) > 0 {
		c.ModuleKnown = func(key string) bool { return !has(f.unknown, key) }
	}
	return c
}

func TestAnEnumBeatsEverythingElse(t *testing.T) {
	// Colour.Red predates modules, so it is asked about first. Here `str` is
	// simultaneously an enum, an import namespace and a builtin family, and the
	// enum still wins.
	f := fixture{
		enums:      []string{"str"},
		namespaces: map[string]string{"str": "lib"},
		exports:    map[string][]string{"lib": {"upper"}},
	}
	got := NewResolver().ResolveField(f.ctx(), "str", "upper")
	if got.Kind != FieldEnumValue {
		t.Fatalf("ResolveField(str.upper) = %v, want FieldEnumValue", got.Kind)
	}
}

func TestAnImportNamespaceBeatsABuiltinFamily(t *testing.T) {
	// A module imported as `str` means that file's functions, not the standard
	// library's. Offering str_upper there would be offering the wrong module.
	f := fixture{
		namespaces: map[string]string{"str": "lib"},
		exports:    map[string][]string{"lib": {"upper"}},
	}
	got := NewResolver().ResolveField(f.ctx(), "str", "upper")
	if got.Kind != FieldModuleMember {
		t.Fatalf("ResolveField(str.upper) = %v, want FieldModuleMember", got.Kind)
	}
	if got.ModuleKey != "lib" || got.Member != "upper" {
		t.Fatalf("resolved to %s.%s, want lib.upper", got.ModuleKey, got.Member)
	}
}

func TestAnImportNamespaceBeatsAnOrdinaryBindingOfTheSameName(t *testing.T) {
	// The import is a declaration in this very file, so it is tried before a
	// variable that happens to share its name -- matching the compiler.
	f := fixture{
		namespaces: map[string]string{"util": "lib"},
		bound:      []string{"util"},
		exports:    map[string][]string{"lib": {"help"}},
	}
	if got := NewResolver().ResolveField(f.ctx(), "util", "help"); got.Kind != FieldModuleMember {
		t.Fatalf("ResolveField(util.help) = %v, want FieldModuleMember", got.Kind)
	}
}

func TestABoundNameBeatsTheBuiltinFold(t *testing.T) {
	// A variable, parameter or struct called `fs` wins, so no existing program
	// changes meaning when a builtin family gains a member.
	f := fixture{bound: []string{"fs"}}
	if got := NewResolver().ResolveField(f.ctx(), "fs", "read"); got.Kind != FieldValueAccess {
		t.Fatalf("ResolveField(fs.read) with a bound fs = %v, want FieldValueAccess", got.Kind)
	}
}

func TestTheFoldHappensWhenNothingIsBound(t *testing.T) {
	got := NewResolver().ResolveField(fixture{}.ctx(), "fs", "read")
	if got.Kind != FieldBuiltinFold {
		t.Fatalf("ResolveField(fs.read) = %v, want FieldBuiltinFold", got.Kind)
	}
	if got.Builtin != "fs_read" {
		t.Fatalf("folded to %q, want fs_read", got.Builtin)
	}
}

// TestAFamilyWhoseNameIsItselfABuiltinStillFolds is a901ce4, pinned at the
// level the decision is now made. A caller that reports a bare builtin as a
// binding breaks exactly these nine members; the parity suite proves the rest.
func TestAFamilyWhoseNameIsItselfABuiltinStillFolds(t *testing.T) {
	for _, c := range []struct{ left, field, want string }{
		{"rand", "int", "rand_int"},
		{"rand", "bytes", "rand_bytes"},
		{"sort", "by", "sort_by"},
		{"assert", "eq", "assert_eq"},
		{"gunzip", "bytes", "gunzip_bytes"},
	} {
		// Nothing is bound: Bound is the caller's job and must exclude
		// builtins, which is the whole point.
		got := NewResolver().ResolveField(fixture{}.ctx(), c.left, c.field)
		if got.Kind != FieldBuiltinFold || got.Builtin != c.want {
			t.Fatalf("ResolveField(%s.%s) = %v/%q, want FieldBuiltinFold/%s",
				c.left, c.field, got.Kind, got.Builtin, c.want)
		}
	}
}

func TestAPrivateMemberIsRefused(t *testing.T) {
	f := fixture{
		namespaces: map[string]string{"stats": "lib"},
		exports:    map[string][]string{"lib": {"_total", "mean"}},
		displays:   map[string]string{"lib": "lib/stats.mut"},
	}
	got := NewResolver().ResolveField(f.ctx(), "stats", "_total")
	if got.Kind != FieldRefused || got.Refusal == nil {
		t.Fatalf("ResolveField(stats._total) = %v, want FieldRefused with a refusal", got.Kind)
	}
	if got.Refusal.Code != RefusePrivateMember {
		t.Fatalf("refusal code = %v, want RefusePrivateMember", got.Refusal.Code)
	}
	want := "stats._total is private to lib/stats.mut: a top-level name beginning with _ is visible only inside the module that declares it"
	if got.Refusal.Error() != want {
		t.Fatalf("refusal text:\n got %q\nwant %q", got.Refusal.Error(), want)
	}
}

func TestAMemberTheModuleDoesNotDeclareIsRefused(t *testing.T) {
	f := fixture{
		namespaces: map[string]string{"stats": "lib"},
		exports:    map[string][]string{"lib": {"mean"}},
		displays:   map[string]string{"lib": "lib/stats.mut"},
	}
	got := NewResolver().ResolveField(f.ctx(), "stats", "median")
	if got.Kind != FieldRefused || got.Refusal == nil {
		t.Fatalf("ResolveField(stats.median) = %v, want FieldRefused", got.Kind)
	}
	if got.Refusal.Code != RefuseNoSuchMember {
		t.Fatalf("refusal code = %v, want RefuseNoSuchMember", got.Refusal.Code)
	}
	want := "lib/stats.mut declares no median, so stats.median has nothing to refer to"
	if got.Refusal.Error() != want {
		t.Fatalf("refusal text:\n got %q\nwant %q", got.Refusal.Error(), want)
	}
}

// TestAnUnloadedModuleHedgesRatherThanRefusing is the editor's case, and the
// reason Confidence exists. A file the language server has not indexed yet must
// produce silence, never "declares no such name" -- a refusal invented out of
// ignorance is worse than no answer.
func TestAnUnloadedModuleHedgesRatherThanRefusing(t *testing.T) {
	f := fixture{
		namespaces: map[string]string{"stats": "lib"},
		unknown:    []string{"lib"},
	}
	got := NewResolver().ResolveField(f.ctx(), "stats", "median")
	if got.Kind != FieldModuleMember {
		t.Fatalf("ResolveField(stats.median) against an unloaded module = %v, want FieldModuleMember", got.Kind)
	}
	if got.Confidence != Provisional {
		t.Fatal("an unloaded module produced a Certain answer")
	}
	if got.Refusal != nil {
		t.Fatalf("an unloaded module produced a refusal: %v", got.Refusal)
	}
}

// TestAPrivateMemberIsRefusedEvenWhenTheModuleIsUnloaded is why the private
// check runs first. The underscore is a rule about the name, not about the
// file, so the editor can say so the moment it is typed.
func TestAPrivateMemberIsRefusedEvenWhenTheModuleIsUnloaded(t *testing.T) {
	f := fixture{
		namespaces: map[string]string{"stats": "lib"},
		unknown:    []string{"lib"},
	}
	got := NewResolver().ResolveField(f.ctx(), "stats", "_total")
	if got.Kind != FieldRefused {
		t.Fatalf("ResolveField(stats._total) = %v, want FieldRefused", got.Kind)
	}
	if got.Confidence != Certain {
		t.Fatal("a private-name refusal hedged")
	}
}

func TestAnUnrecognisedReceiverIsFieldAccess(t *testing.T) {
	// point.x, and equally anything half-typed. This arm is what keeps a buffer
	// mid-edit from producing refusals.
	for _, c := range [][2]string{{"point", "x"}, {"nosuch", "member"}, {"", "x"}, {"x", ""}} {
		if got := NewResolver().ResolveField(fixture{}.ctx(), c[0], c[1]); got.Kind != FieldValueAccess {
			t.Fatalf("ResolveField(%q.%q) = %v, want FieldValueAccess", c[0], c[1], got.Kind)
		}
	}
}

func TestAZeroScopeCtxDecidesWithoutPanicking(t *testing.T) {
	// The REPL, the playground and a single-file compile all supply nothing but
	// a nil-valued context. A fold still has to work there.
	got := NewResolver().ResolveField(ScopeCtx{}, "str", "upper")
	if got.Kind != FieldBuiltinFold || got.Builtin != "str_upper" {
		t.Fatalf("ResolveField(str.upper) with an empty context = %v/%q", got.Kind, got.Builtin)
	}
}
