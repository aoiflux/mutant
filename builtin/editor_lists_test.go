package builtin

import (
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"testing"

	"mutant/object"
)

// The editor's rules about the case builtins read lists this package exports:
// SecretOptionRefusers and RoleOptionBuiltins name the builtins, and the
// refusals are the run time's own sentences. These tests read the code and hold
// each list to the calls that refuse, as classified_lists_test.go does for the
// sinks and sources, so the editor cannot warn about a builtin that does not
// refuse or miss one that was added.

// helperCall is one call to a package helper and the builtin it is made for.
type helperCall struct {
	builtin string
	call    *ast.CallExpr
}

// helperCalls returns every call to the named helper with the builtin each is
// made for: the BuiltinName constant passed as its first argument -- directly,
// through a local assigned one (`op := BuiltinNameRecordOpen`), or through a
// parameter of the function making the call, followed back to every caller of
// that function (recordSealImpl's op comes from record_seal and
// record_seal_quantised). An op it cannot follow fails the test rather than
// leaving a builtin out.
func helperCalls(t *testing.T, files []*ast.File, constants map[string]string, helper string) []helperCall {
	t.Helper()
	var funcs []*ast.FuncDecl
	for _, file := range files {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs = append(funcs, fn)
			}
		}
	}

	var resolve func(fn *ast.FuncDecl, expr ast.Expr, depth int) []string
	resolve = func(fn *ast.FuncDecl, expr ast.Expr, depth int) []string {
		ident, ok := expr.(*ast.Ident)
		if !ok || depth > 4 {
			t.Errorf("%s passes %s an op this test cannot follow", fn.Name.Name, helper)
			return nil
		}
		if name, isConstant := constants[ident.Name]; isConstant {
			return []string{name}
		}
		index := 0
		for _, field := range fn.Type.Params.List {
			for _, param := range field.Names {
				if param.Name != ident.Name {
					index++
					continue
				}
				var names []string
				for _, caller := range funcs {
					ast.Inspect(caller.Body, func(n ast.Node) bool {
						call, ok := n.(*ast.CallExpr)
						if !ok {
							return true
						}
						if callee, ok := call.Fun.(*ast.Ident); ok && callee.Name == fn.Name.Name && index < len(call.Args) {
							names = append(names, resolve(caller, call.Args[index], depth+1)...)
						}
						return true
					})
				}
				if len(names) == 0 {
					t.Errorf("%s takes its op as a parameter and nothing calls it", fn.Name.Name)
				}
				return names
			}
		}
		var assigned []string
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				if local, ok := lhs.(*ast.Ident); !ok || local.Name != ident.Name || i >= len(assign.Rhs) {
					continue
				}
				value, ok := assign.Rhs[i].(*ast.Ident)
				name, isConstant := "", false
				if ok {
					name, isConstant = constants[value.Name]
				}
				if !isConstant {
					t.Errorf("%s assigns %s something other than a BuiltinName constant", fn.Name.Name, ident.Name)
					continue
				}
				assigned = append(assigned, name)
			}
			return true
		})
		if len(assigned) != 1 {
			t.Errorf("%s assigns the op it passes %s %d times, want once", fn.Name.Name, helper, len(assigned))
		}
		return assigned
	}

	var out []helperCall
	for _, fn := range funcs {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if callee, ok := call.Fun.(*ast.Ident); !ok || callee.Name != helper || len(call.Args) == 0 {
				return true
			}
			for _, name := range resolve(fn, call.Args[0], 0) {
				out = append(out, helperCall{builtin: name, call: call})
			}
			return true
		})
	}
	return out
}

// The editor finds a builtin's options hash with OptionsPosition, under either
// spelling the metadata uses, and only where there is one.
func TestOptionsPositionFindsEitherSpelling(t *testing.T) {
	for name, want := range map[string]int{BuiltinNameRecordOpen: 2, BuiltinNameLedgerOpen: 3,
		BuiltinNameRecordSeal: 4, BuiltinNameReportWrite: 3, BuiltinNameDbOpenDisk: 2} {
		if got, ok := OptionsPosition(name); !ok || got != want {
			t.Errorf("OptionsPosition(%s) = %d, %v; want %d", name, got, ok, want)
		}
	}
	for _, name := range []string{BuiltinNamePutln, BuiltinNameCaseTransition, "no_such_builtin"} {
		if got, ok := OptionsPosition(name); ok {
			t.Errorf("OptionsPosition(%s) = %d, and it takes no options hash", name, got)
		}
	}
}

// Every builtin that reads its options with secretOptionsArg is in
// SecretOptionRefusers, and nothing else is. The editor looks for the options
// hash where the metadata puts it, so each call has to read it from there too.
func TestSecretOptionRefusersAreTheBuiltinsThatRefuse(t *testing.T) {
	files := builtinSources(t)
	constants := builtinNameConstants(files)

	var refusing []string
	for _, found := range helperCalls(t, files, constants, "secretOptionsArg") {
		refusing = append(refusing, found.builtin)
		want, hasOptions := OptionsPosition(found.builtin)
		position, literal := found.call.Args[2].(*ast.BasicLit)
		if !hasOptions || !literal || position.Kind != token.INT || position.Value != strconv.Itoa(want) {
			t.Errorf("%s reads its options hash at a position other than the %d its metadata gives", found.builtin, want)
		}
	}
	if len(refusing) < 27 {
		t.Fatalf("found %d calls to secretOptionsArg; the scan is not reaching them", len(refusing))
	}
	if got, want := sortedSet(refusing), sortedSet(SecretOptionRefusers()); !slices.Equal(got, want) {
		t.Errorf("the builtins that refuse an option named for a secret are\n  %v\nbut SecretOptionRefusers lists\n  %v", got, want)
	}
}

// Every builtin that reads a role out of its options hash with roleOption is in
// RoleOptionBuiltins, and nothing else is.
func TestRoleOptionBuiltinsAreTheBuiltinsThatReadARole(t *testing.T) {
	files := builtinSources(t)
	constants := builtinNameConstants(files)

	var reading []string
	for _, found := range helperCalls(t, files, constants, "roleOption") {
		reading = append(reading, found.builtin)
	}
	if got, want := sortedSet(reading), sortedSet(RoleOptionBuiltins()); !slices.Equal(got, want) {
		t.Errorf("the builtins that read a role from their options are\n  %v\nbut RoleOptionBuiltins lists\n  %v", got, want)
	}
}

// The editor's roleLiteral rule repeats ExaminerRoleRefusal at the line, so it
// has to be the sentence case_open and ledger_open refuse the role with, and
// empty for exactly the roles they take.
func TestTheRoleRefusalTheEditorRepeatsIsTheRuntimes(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Cleanup(resetCustodyForTesting)
	role := func(word string) object.Object {
		return makeHashObject(map[string]object.Object{"role": stringObj(word)})
	}
	for _, word := range []string{"legal", "external_partner", "Restricted_Viewer", "unasserted", " Unasserted ",
		"detective", ""} {
		refusal := ExaminerRoleRefusal(word)
		if refusal == "" {
			t.Errorf("ExaminerRoleRefusal(%q) refuses nothing", word)
			continue
		}
		resetCustodyForTesting()
		_, errObj := unwrapPairNoFatal(CaseOpen(stringObj("IR-1"), stringObj("examiner"), role(word)))
		if errObj == nil || errObj.Message != BuiltinNameCaseOpen+": "+refusal {
			t.Errorf("case_open with role %q: got %v, want the refusal %q", word, errObj, refusal)
		}
		_, errObj = unwrapPairNoFatal(LedgerOpen(stringObj("ledger"), stringObj("examiner"), role(word)))
		if errObj == nil || errObj.Message != BuiltinNameLedgerOpen+": "+refusal {
			t.Errorf("ledger_open with role %q: got %v, want the refusal %q", word, errObj, refusal)
		}
	}
	for _, word := range []string{"administrator", "case_owner", "lead_investigator", "investigator", "reviewer",
		"auditor", " Case_Owner "} {
		if refusal := ExaminerRoleRefusal(word); refusal != "" {
			t.Errorf("ExaminerRoleRefusal(%q) = %q, and an examiner asserts that role", word, refusal)
		}
	}
}
