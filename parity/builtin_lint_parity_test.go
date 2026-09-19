package parity

import (
	"strings"
	"testing"

	"mutant/lsp/api"
	"mutant/sema"
)

// The lint's half of the fold.
//
// field_resolution_parity_test.go settles what `F.m` MEANS, across the compiler,
// the evaluator, the VM and sema. This file asks the question one step further
// out: given that it means the builtin, does the editor then hold it to the
// builtin's contract -- and given that it does not, does the editor keep quiet?
//
// The two are not the same question, and the gap between them is where a defect
// sat. The builtin rules -- arity, argument kinds, deprecation, the (value, err)
// binding rule -- decided shadowing from a scope chain of their own, threaded
// through the whole of diagnostics.go and filled in by a case per AST node that
// binds a name. It wrote struct and enum names into the same table as lets and
// parameters, so `struct fs { path; }` made every one of those rules go silent
// for `fs.read(...)` in that file, while the build folded it to fs_read and ran
// it. `struct rand { x; }; rand.int(1, 5);` returns 3 from the builtin today.
//
// Silence is the expensive direction here. A rule that fires wrongly is
// reported; a rule that stops firing is not noticed until the thing it was
// watching for ships.
//
// It runs through mutant/lsp/api.Lint, which is what `mutant lint` runs and
// what the language server configures itself the same way to produce, rather
// than through the collector directly: a rule that is right and unreachable is
// not a rule the user has.

// tooManyArguments is more arguments than any builtin in the table takes, so
// the arity rule has something to say about every call that reaches it.
const tooManyArguments = "(1, 2, 3, 4, 5, 6, 7)"

// arityComplaint reports whether the lint held a call to name against the arity
// table, and what it said.
//
// Keyed on the flat registry name, which is how the message names a builtin
// whichever way the call was spelled -- an author who wrote `fs.read` reads
// `fs_read` in the message, and it is the same function.
func arityComplaint(src, name string) (string, bool) {
	for _, d := range api.Lint(src) {
		if d.Source == "mutant-lint" && strings.Contains(d.Message, "builtin `"+name+"` takes") {
			return d.Message, true
		}
	}
	return "", false
}

// TestEveryFamilyMemberHasAnArityTheLintCanCheck is the precondition the matrix
// below rests on.
//
// A member with no curated arity produces no complaint however the call is
// written, so its rows would pass by never firing -- the matrix would assert
// nothing for that family and say nothing about it. Checked separately so that
// a missing contract reads as a missing contract rather than as a fold that
// stopped working.
func TestEveryFamilyMemberHasAnArityTheLintCanCheck(t *testing.T) {
	for _, f := range foldFamilies {
		if _, complained := arityComplaint(f.flat()+tooManyArguments+";\n", f.flat()); !complained {
			t.Errorf("%s accepts seven arguments without complaint, so no row about "+
				"%s can fail by going silent", f.flat(), f.dotted())
		}
	}
}

// TestTheLintChecksACallExactlyWhenTheBuildCompilesOne is the matrix.
//
// `want` is not this file's opinion. It is the decision the compiler, the
// evaluator and the VM were each observed making in
// field_resolution_parity_test.go, which asserts it on the value the program
// produces. So a row here cannot drift into agreeing with the lint about
// something the build does differently: both read the same table.
func TestTheLintChecksACallExactlyWhenTheBuildCompilesOne(t *testing.T) {
	for _, form := range shadowForms {
		for _, f := range foldFamilies {
			t.Run(form.name+"/"+f.dotted(), func(t *testing.T) {
				src := form.source(f, f.dotted()+tooManyArguments)
				message, complained := arityComplaint(src, f.flat())

				switch {
				case form.want == sema.FieldBuiltinFold && !complained:
					t.Fatalf("the build compiles %s as the builtin %s here, and the editor "+
						"says nothing about seven arguments:\n\n%s\n"+
						"Going quiet is how this rule fails: the author sees a clean file "+
						"and the error at run time.", f.dotted(), f.flat(), src)

				case form.want != sema.FieldBuiltinFold && complained:
					t.Fatalf("the editor holds %s to the builtin %s's contract -- %q -- and "+
						"the build resolves it as %s here:\n\n%s\n"+
						"The complaint is about a function this program does not call.",
						f.dotted(), f.flat(), message, form.want, src)
				}
			})
		}
	}
}

// TestTheFlatSpellingIsCheckedWhateverShadowsTheFamily is the other half, and
// the one that stops the matrix above being satisfiable by a rule that simply
// gave up on files declaring anything.
//
// `rand_int` names the builtin and nothing else. No shadow in the table binds
// that name -- they bind `rand` -- so every row must still be checked, whatever
// the family name was made to mean.
func TestTheFlatSpellingIsCheckedWhateverShadowsTheFamily(t *testing.T) {
	for _, form := range shadowForms {
		for _, f := range foldFamilies {
			t.Run(form.name+"/"+f.flat(), func(t *testing.T) {
				src := form.source(f, f.flat()+tooManyArguments)
				if _, complained := arityComplaint(src, f.flat()); !complained {
					t.Fatalf("%s is not held to its own contract in a file where %s is "+
						"shadowed:\n\n%s\n"+
						"Nothing here binds %s, so nothing here can shadow it.",
						f.flat(), f.prefix, src, f.flat())
				}
			})
		}
	}
}
