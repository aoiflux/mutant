package compiler

import (
	"testing"

	"mutant/sema"
)

// The symbol table files a module's top-level name under qualify(module, name),
// and sema identifies that same declaration with a DeclID. These are two
// independently-written notions of identity for one thing, so the graph can
// only be compared against the compiler if they produce the same bytes.
//
// Nothing enforces that at compile time -- DeclID.String assembles the key
// itself -- so it is pinned here, in the package that owns qualify. If this
// goes red, a parity test elsewhere has quietly stopped comparing anything.
func TestADeclIDIsTheKeyTheSymbolTableAlreadyUses(t *testing.T) {
	for _, c := range []struct{ module, name string }{
		{"o:/project/mutant/examples/modules/lib/stats.mut", "mean"},
		{"o:/project/mutant/examples/modules/lib/stats.mut", "_total"},
		{"", "mean"}, // the REPL, the playground, a single-file test compile
	} {
		want := qualify(c.module, c.name)
		got := sema.TopLevelID(c.module, c.name).String()
		if got != want {
			t.Fatalf("identity for %q in %q:\n sema %q\n compiler %q", c.name, c.module, got, want)
		}
	}
}

// The separator has to be a byte that can appear in neither a path nor an
// identifier, or a qualified key could be spelled by an unqualified one. Both
// packages now name one constant, so this checks the constant itself rather
// than that two copies agree.
func TestTheModuleSeparatorIsNUL(t *testing.T) {
	if moduleSeparator != "\x00" {
		t.Fatalf("moduleSeparator = %q, want NUL", moduleSeparator)
	}
}

// IsModulePrivate is the export rule, and the compiler refuses on it while the
// editor greys out on it. One function, reached two ways.
func TestTheCompilerAndSemaAgreeOnWhatIsPrivate(t *testing.T) {
	for _, name := range []string{"_total", "mean", "_", "x_y", ""} {
		if IsModulePrivate(name) != sema.IsModulePrivate(name) {
			t.Fatalf("IsModulePrivate(%q) disagrees between compiler and sema", name)
		}
	}
}
