package parity

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/generator"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/security"
	"mutant/sema"
	"mutant/vm"
)

// What `F.m` means, for every way of writing F and every family F can be.
//
// namespace_fold_parity_test.go tells the story this generalises. `ns.member`
// is `ns_member`, derived rather than tabulated; the fold was implemented three
// times; and each implementation asked "is this name already taken?" of a
// different thing. Four family names are themselves registered builtins --
// rand, sort, assert, gunzip -- so nine builtins compiled to a run-time error
// while the evaluator ran them and the editor recommended them.
//
// That test lists those nine by hand. This one asks the question they were a
// symptom of: for every way a program can put a name in front of a dot, do all
// four deciders agree? The deciders are the compiler, the tree-walking
// evaluator that expands macros, the VM that runs the result, and sema, which
// is what the editor asks -- and the only one of the four whose being wrong a
// user sees before they hit build.
//
// The property that makes the matrix worth running is that no cell depends on
// which family it is. A family whose name is also a builtin must behave exactly
// like one whose name is not: the collision was never supposed to mean
// anything. Every row below is asserted identically for `rand` and for `str`.
//
// It found one. `struct rand { int }` made sema call `rand.int` a field read on
// a value while all three engines folded it to rand_int, because the editor
// counted a type name as a binding and the compiler never has -- a type name
// does not enter the symbol table. It was not confined to the four: `struct fs`
// cost a file every builtin hover, completion and signature card for `fs.read`.
// sema.Graph.LocalScopeAt is the fix, and these are the rows that keep it.

// foldFamily is a builtin family and one member of it.
type foldFamily struct {
	prefix string
	member string

	// collides says prefix is itself a registered builtin, which is the
	// condition that made the old compiler skip the fold. It is stated rather
	// than computed so that a new builtin named after an existing family has to
	// be acknowledged here; TestTheCollidingFamiliesAreStillTheCollidingOnes
	// checks the claim against the registry.
	collides bool
}

func (f foldFamily) dotted() string { return f.prefix + "." + f.member }
func (f foldFamily) flat() string   { return f.prefix + "_" + f.member }

// The four that collide, and four that do not. The controls are not padding:
// without them a change that broke the fold outright would pass every row.
var foldFamilies = []foldFamily{
	{prefix: "rand", member: "int", collides: true},
	{prefix: "sort", member: "by", collides: true},
	{prefix: "assert", member: "eq", collides: true},
	{prefix: "gunzip", member: "bytes", collides: true},

	{prefix: "str", member: "upper"},
	{prefix: "hash", member: "blake2"},
	{prefix: "fs", member: "read"},
	{prefix: "base64", member: "encode"},
}

const (
	// What normalize renders a builtin as. It does not say which builtin, which
	// is why every fold row also compares the two spellings as objects.
	wantBuiltin = "BUILTIN(builtin function)"

	// The value every shadowing struct holds, so a row that resolves to a field
	// has one number to expect.
	heldNumber = "INTEGER(7)"
)

// shadowForm is one way of writing a program in which F.m appears, and what
// F.m must then mean.
type shadowForm struct {
	name string

	// source renders the program. use is the spelling under test -- `rand.int`
	// or `rand_int` -- and is always the last thing written, so its position
	// can be found by searching backwards.
	source func(f foldFamily, use string) string

	// want is the decision sema must reach about the dotted spelling, and value
	// is what all three engines must produce for it.
	want  sema.FieldKind
	value func(f foldFamily) string
}

func builtinValue(foldFamily) string { return wantBuiltin }
func heldValue(foldFamily) string    { return heldNumber }
func enumValue(f foldFamily) string {
	return fmt.Sprintf("ENUM_VALUE(%s.%s(0))", f.prefix, f.member)
}

var shadowForms = []shadowForm{
	{
		name:   "nothing shadows the family name",
		source: func(f foldFamily, use string) string { return use + ";\n" },
		want:   sema.FieldBuiltinFold,
		value:  builtinValue,
	},
	{
		// The original shadow test's case, kept because it is the reason the
		// fold is last in the precedence rather than first.
		name: "a top-level let holds a struct",
		source: func(f foldFamily, use string) string {
			return "struct Holder { " + f.member + " };\n" +
				"let " + f.prefix + " = Holder{" + f.member + ": 7};\n" +
				use + ";\n"
		},
		want:  sema.FieldValueAccess,
		value: heldValue,
	},
	{
		// A parameter is a different scope class from a global -- Local rather
		// than Global -- and the compiler's symbol table returns it by an
		// earlier path, so a fix that handled one would not necessarily handle
		// the other.
		name: "a parameter holds a struct",
		source: func(f foldFamily, use string) string {
			return "struct Holder { " + f.member + " };\n" +
				"let take = fn(" + f.prefix + ") { return " + use + "; };\n" +
				"take(Holder{" + f.member + ": 7});\n"
		},
		want:  sema.FieldValueAccess,
		value: heldValue,
	},
	{
		// The row that failed. A type name is visible -- a bare `Holder` has to
		// resolve to it -- without being a value binding, and only the second
		// of those shadows the fold.
		name: "a struct type carries the family name",
		source: func(f foldFamily, use string) string {
			return "struct " + f.prefix + " { " + f.member + " };\n" + use + ";\n"
		},
		want:  sema.FieldBuiltinFold,
		value: builtinValue,
	},
	{
		// A binding shadows from where it is written, not from everywhere in
		// the file. This row is the only one whose shadow is below the use, and
		// without it a resolver that ignored the position entirely would agree
		// with every other row in the matrix.
		//
		// It is not a contrived shape: it is what a file looks like halfway
		// through being written, which is when the editor is asked the most
		// questions.
		name: "the shadowing let is written below the use",
		source: func(f foldFamily, use string) string {
			return "let seen = " + use + ";\n" +
				"struct Holder { " + f.member + " };\n" +
				"let " + f.prefix + " = Holder{" + f.member + ": 7};\n" +
				"seen;\n"
		},
		want:  sema.FieldBuiltinFold,
		value: builtinValue,
	},
	{
		// An enum is the one type that does shadow, because an enum value is
		// written exactly like a fold and predates both modules and builtin
		// families. It is decided before Bound is ever consulted.
		name: "an enum carries the family name",
		source: func(f foldFamily, use string) string {
			return "enum " + f.prefix + " { " + f.member + " };\n" + use + ";\n"
		},
		want:  sema.FieldEnumValue,
		value: enumValue,
	},
}

// TestTheCollidingFamiliesAreStillTheCollidingOnes keeps the table's own claim
// honest. A builtin added under the name of an existing family would silently
// turn a control row into a colliding one, and the matrix would go on asserting
// that nothing had changed.
func TestTheCollidingFamiliesAreStillTheCollidingOnes(t *testing.T) {
	for _, f := range foldFamilies {
		registered := builtin.GetBuiltinByName(f.prefix) != nil
		if registered != f.collides {
			t.Errorf("%s is listed as collides=%v but the registry says %v: a family "+
				"whose own name is a builtin is the condition this file is about",
				f.prefix, f.collides, registered)
		}
		if builtin.GetBuiltinByName(f.flat()) == nil {
			t.Errorf("%s is not a registered builtin, so %s has nothing to fold to",
				f.flat(), f.dotted())
		}
	}
}

// TestEveryShadowingFormMeansTheSameForEveryFamily is the matrix.
func TestEveryShadowingFormMeansTheSameForEveryFamily(t *testing.T) {
	for _, form := range shadowForms {
		for _, f := range foldFamilies {
			t.Run(form.name+"/"+f.dotted(), func(t *testing.T) {
				source := form.source(f, f.dotted())
				want := form.value(f)

				// The two engines, on the value rather than on agreeing. A fold
				// that resolved to the wrong builtin would still agree.
				evaluated := normalize(evalViaEvaluator(source))
				if evaluated != want {
					t.Fatalf("the evaluator answered %s for %s, want %s\n%s",
						evaluated, f.dotted(), want, source)
				}
				dotted, err := evalViaVM(t, source)
				if err != nil {
					t.Fatalf("the VM refused %s: %v (the evaluator gave %s)\n%s",
						f.dotted(), err, evaluated, source)
				}
				if compiled := normalize(dotted); compiled != want {
					t.Fatalf("the VM answered %s for %s, want %s\n%s",
						compiled, f.dotted(), want, source)
				}

				// And sema, which is what the editor asks. A disagreement here
				// is a user being told one thing and built another.
				resolved := editorDecision(t, source, f.prefix, f.member)
				if resolved.Kind != form.want {
					t.Fatalf("sema calls %s a %s; the engines make it a %s, worth %s\n%s",
						f.dotted(), resolved.Kind, form.want, want, source)
				}

				if form.want != sema.FieldBuiltinFold {
					return
				}

				// Where the fold applies, it has to reach the builtin the flat
				// name names -- not merely some builtin.
				if resolved.Builtin != f.flat() {
					t.Fatalf("sema folds %s to %q, want %q", f.dotted(), resolved.Builtin, f.flat())
				}
				flat, err := evalViaVM(t, form.source(f, f.flat()))
				if err != nil {
					t.Fatalf("the VM refused the flat spelling %s: %v", f.flat(), err)
				}
				if dotted != flat {
					t.Fatalf("%s and %s are different objects: the fold reached the "+
						"wrong builtin, which two agreeing engines cannot rule out",
						f.dotted(), f.flat())
				}
			})
		}
	}
}

// TestShadowingTheFamilyNameNeverChangesTheFlatSpelling is the other half of
// the fold's premise. `rand.int` and `rand_int` are one function, so whatever a
// program does to the name `rand`, it cannot reach `rand_int` -- there is no
// `rand` in that identifier to shadow.
//
// Written separately from the matrix because it is a different claim: the
// matrix says each cell resolves correctly, this says the cells cannot leak
// into a spelling that has no dot in it at all.
func TestShadowingTheFamilyNameNeverChangesTheFlatSpelling(t *testing.T) {
	for _, form := range shadowForms {
		for _, f := range foldFamilies {
			t.Run(form.name+"/"+f.flat(), func(t *testing.T) {
				source := form.source(f, f.flat())

				evaluated := normalize(evalViaEvaluator(source))
				if evaluated != wantBuiltin {
					t.Fatalf("the evaluator answered %s for %s in a file where %s is "+
						"shadowed, want %s\n%s",
						evaluated, f.flat(), f.prefix, wantBuiltin, source)
				}
				obj, err := evalViaVM(t, source)
				if err != nil {
					t.Fatalf("the VM refused %s: %v\n%s", f.flat(), err, source)
				}
				if compiled := normalize(obj); compiled != wantBuiltin {
					t.Fatalf("the VM answered %s for %s in a file where %s is "+
						"shadowed, want %s\n%s",
						compiled, f.flat(), f.prefix, wantBuiltin, source)
				}
			})
		}
	}
}

// TestAnImportAliasNamedAfterABuiltinFamilyIsTheModule is the sixth form, and
// it needs a file tree: an import only means anything once there is a file to
// import.
//
// It is the one shadowing form that arrives from outside the file, and it beats
// the fold for the reason the precedence says -- the import is a declaration in
// this very file, written by the author, and a builtin family is a spelling
// nobody declared.
func TestAnImportAliasNamedAfterABuiltinFamilyIsTheModule(t *testing.T) {
	for _, f := range foldFamilies {
		t.Run(f.dotted(), func(t *testing.T) {
			files := map[string]string{
				"main.mut": "import " + f.prefix + " \"lib.mut\";\n" + f.dotted() + ";\n",
				"lib.mut":  "let " + f.member + " = 7;\n",
			}
			root := writeTree(t, files)

			value, err := runViaModules(t, root)
			if err != nil {
				t.Fatalf("a program importing a module called %s did not run: %v", f.prefix, err)
			}
			if got := normalize(value); got != heldNumber {
				t.Fatalf("%s answered %s, want %s -- the author's own module loses to a "+
					"builtin family of the same name", f.dotted(), got, heldNumber)
			}

			// sema, asked the way the editor asks: the file's own graph for
			// what is bound here, the workspace for what the import names.
			w := workspaceOverTree(t, root)
			entry := filepath.Join(root, "main.mut")
			key := sema.CanonicalKey(entry)
			resolved := w.ResolveField(key, localScopeIn(t, key, files["main.mut"], f.dotted()),
				f.prefix, f.member)
			if resolved.Kind != sema.FieldModuleMember {
				t.Fatalf("sema calls %s a %s in a file that imports a module under that "+
					"name; the build makes it the module's %s",
					f.dotted(), resolved.Kind, f.member)
			}
			if want := sema.CanonicalKey(filepath.Join(root, "lib.mut")); resolved.ModuleKey != want {
				t.Fatalf("sema resolves %s into %q, want %q", f.dotted(), resolved.ModuleKey, want)
			}

			// The flat spelling is still the builtin, in the same program.
			flat := map[string]string{
				"main.mut": "import " + f.prefix + " \"lib.mut\";\n" + f.flat() + ";\n",
				"lib.mut":  files["lib.mut"],
			}
			value, err = runViaModules(t, writeTree(t, flat))
			if err != nil {
				t.Fatalf("%s did not run alongside an import called %s: %v", f.flat(), f.prefix, err)
			}
			if got := normalize(value); got != wantBuiltin {
				t.Fatalf("%s answered %s beside an import called %s, want %s",
					f.flat(), got, f.prefix, wantBuiltin)
			}
		})
	}
}

// TestAMemberAnImportedModuleDoesNotDeclareIsRefusedRatherThanFolded is the
// case that shows the namespace arm is a decision and not a lookup that falls
// through.
//
// If the alias only shadowed the fold when the member happened to exist, then
// `rand.itn` -- a typo in a file importing a module called rand -- would
// quietly become the builtin rand_itn if there were one, and a program would
// run somebody else's code. Both deciders have to refuse instead.
func TestAMemberAnImportedModuleDoesNotDeclareIsRefusedRatherThanFolded(t *testing.T) {
	for _, f := range foldFamilies {
		t.Run(f.dotted(), func(t *testing.T) {
			files := map[string]string{
				"main.mut": "import " + f.prefix + " \"lib.mut\";\n" + f.dotted() + ";\n",
				"lib.mut":  "let somethingElse = 7;\n",
			}
			root := writeTree(t, files)
			entry := filepath.Join(root, "main.mut")

			accepted, message := compilerAccepts(t, entry)
			if accepted {
				t.Fatalf("the compiler accepted %s, which the imported module does not "+
					"declare; the builtin family of the same name must not stand in for it",
					f.dotted())
			}

			w := workspaceOverTree(t, root)
			key := sema.CanonicalKey(entry)
			resolved := w.ResolveField(key, localScopeIn(t, key, files["main.mut"], f.dotted()),
				f.prefix, f.member)
			if resolved.Kind != sema.FieldRefused {
				t.Fatalf("sema calls %s a %s; the compiler refuses it: %s",
					f.dotted(), resolved.Kind, message)
			}
			if !strings.Contains(message, resolved.Refusal.Error()) {
				t.Fatalf("two phrasings of one rule:\n compiler: %s\n sema:     %s",
					message, resolved.Refusal.Error())
			}
		})
	}
}

// editorDecision is what sema decides about left.field in a single-file
// program, composed the way the language server composes it: this file's graph
// supplies the local scope, and there is nothing cross-module to supply.
func editorDecision(t *testing.T, source, left, field string) sema.FieldResolution {
	t.Helper()
	local := localScopeIn(t, "", source, left+"."+field)
	return sema.NewResolver().ResolveField(
		sema.ScopeCtx{Enums: local.Enums, Bound: local.Bound}, left, field)
}

// localScopeIn is the local scope at the use under test, which is always the
// last occurrence of `use` in the source.
//
// It goes through Graph.LocalScopeAt rather than reproducing the predicate,
// because reproducing it is what this file exists to stop. A test that wrote
// out its own idea of "bound here" would agree with itself and with nothing.
func localScopeIn(t *testing.T, key, source, use string) sema.LocalScope {
	t.Helper()
	program := parser.New(lexer.New(source)).ParseProgram()
	line, column := positionOf(t, source, use)
	return sema.BuildFile(key, program, nil, nil).LocalScopeAt(line, column)
}

// positionOf is where the last occurrence of needle starts, as a 1-based line
// and column. The spelling under test is always written last, so searching
// backwards finds the use rather than the declaration that shadows it.
func positionOf(t *testing.T, source, needle string) (line, column int) {
	t.Helper()
	at := strings.LastIndex(source, needle)
	if at < 0 {
		t.Fatalf("%q does not appear in:\n%s", needle, source)
	}
	before := source[:at]
	line = strings.Count(before, "\n") + 1
	column = at - (strings.LastIndex(before, "\n") + 1) + 1
	return line, column
}

// runViaModules compiles a tree the way the mutant CLI does -- load the import
// graph, link it, compile -- and runs the result, returning what the program's
// last expression left on the stack.
//
// searchPaths are the --module-path directories, variadic for the same reason
// workspaceOverTree's are: they matter to the handful of cases that are about
// where a module was found rather than about what it says.
func runViaModules(t *testing.T, root string, searchPaths ...string) (object.Object, error) {
	t.Helper()
	byteCode, err, _, _ := generator.CompileForTest(filepath.Join(root, "main.mut"), searchPaths)
	if err != nil {
		return nil, err
	}
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := vm.NewWithGlobalStoreAndPassword(byteCode,
		make([]object.Object, global.GlobalSize), password)
	if err := machine.Run(); err != nil {
		return nil, err
	}
	return machine.LastPoppedStackElement(), nil
}

// TestAnEnumWithoutTheMemberIsRefusedByBothEnginesInTheSameWords is the cell
// the matrix above cannot hold, because there is no value to compare: both
// engines must refuse, and they must refuse identically.
//
// `enum str { notTheMember }; str.upper("a");` is an enum access to a tag that
// does not exist. It is NOT the fold -- an enum is decided first, which is what
// "Colour.Red predates modules" means -- and the evaluator used to think
// otherwise. It asked whether the VARIANT was in its environment rather than
// whether the ENUM was, so a missing variant fell through to the fold: the
// program returned "A" under the engine that expands macros while the VM
// refused it as an unknown tag. One program, two answers, which is the shape of
// a901ce4 and the reason this package exists.
func TestAnEnumWithoutTheMemberIsRefusedByBothEnginesInTheSameWords(t *testing.T) {
	for _, f := range foldFamilies {
		t.Run(f.dotted(), func(t *testing.T) {
			source := "enum " + f.prefix + " { notTheMember };\n" + f.dotted() + "(\"a\");\n"
			want := "unknown enum tag " + f.dotted()

			evaluated := evalViaEvaluator(source)
			raised, isError := evaluated.(*object.Error)
			if !isError {
				t.Fatalf("the evaluator answered %s for %s under an enum of that "+
					"name with no such tag; the VM refuses it\n%s",
					normalize(evaluated), f.dotted(), source)
			}
			if !strings.Contains(raised.Message, want) {
				t.Fatalf("the evaluator said %q, want it to contain %q\n%s",
					raised.Message, want, source)
			}

			value, err := evalViaVM(t, source)
			if err == nil {
				t.Fatalf("the VM answered %s where the evaluator refused\n%s",
					normalize(value), source)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the VM said %q, want it to contain %q\n%s",
					err.Error(), want, source)
			}

			// And sema, which decided it for both: an enum in front of the dot
			// is an enum access whether or not the tag is there. Deciding it on
			// the tag is what let the fold back in.
			if resolved := editorDecision(t, source, f.prefix, f.member); resolved.Kind != sema.FieldEnumValue {
				t.Fatalf("sema calls %s a %s under an enum of that name, want an "+
					"enum value\n%s", f.dotted(), resolved.Kind, source)
			}
		})
	}
}
