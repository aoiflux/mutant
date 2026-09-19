package sema

import "testing"

func graphOf(t *testing.T, src string) *Graph {
	t.Helper()
	return BuildFile("", parse(t, src), nil, nil)
}

// find returns the declaration of name in the graph, failing if there is none.
func find(t *testing.T, g *Graph, name string) *Node {
	t.Helper()
	for _, node := range g.Declarations() {
		if node.Name == name {
			return node
		}
	}
	t.Fatalf("nothing named %q is declared; the file declares %v", name, declaredNames(g))
	return nil
}

func declaredNames(g *Graph) []string {
	names := make([]string, 0, len(g.Declarations()))
	for _, node := range g.Declarations() {
		names = append(names, node.Name+"("+node.Kind.String()+")")
	}
	return names
}

// The walk is a switch over node types, so a type it has no case for is a
// silent dead end -- the subtree is never entered and every name written inside
// it is invisible. That is not hypothetical. This graph replaces five separate
// walks, and *ast.ImportStatement was missing from all five, which is why an
// import alias had no definition, no completion and no references.
//
// ast/modify_coverage_test.go pins the same property for Modify, after a
// missing *CallExpression case made `putln(emit_literal())` fail to compile
// while `let x = emit_literal();` worked. This is that test for this walk:
// plant a use of a known declaration inside each node type and assert the graph
// recorded it.
func TestTheWalkReachesAUseInsideEveryNodeType(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"expression statement", `marker;`},
		{"let value", `let a = marker;`},
		{"multi-name let value", `let a, b = marker;`},
		{"return value", `let f = fn() { return marker; };`},
		{"if-arm block", `if (true) { marker; }`},
		{"empty if alternative", `if (marker) { }`},
		{"while condition", `while (marker) { }`},
		{"while body", `while (false) { marker; }`},
		{"for-in iterable", `for (v in marker) { }`},
		{"for-in body", `for (v in [1]) { marker; }`},
		{"for init", `for (let i = marker; false; i) { }`},
		{"for condition", `for (let i = 0; marker; i) { }`},
		{"for post", `for (let i = 0; false; marker) { }`},
		{"for body", `for (let i = 0; false; i) { marker; }`},
		{"function body", `let f = fn() { marker; };`},
		{"macro body", `let m = macro() { marker; };`},
		{"if alternative", `if (true) { } else { marker; }`},
		{"match subject", `let f = fn() { return match (marker) { _ => 1, }; };`},
		{"match arm body", `let f = fn() { return match (1) { _ => marker, }; };`},
		{"call callee", `marker();`},
		{"call argument", `putln(marker);`},
		{"prefix operand", `!marker;`},
		{"infix left", `marker + 1;`},
		{"infix right", `1 + marker;`},
		{"index left", `marker[0];`},
		{"index", `[1][marker];`},
		{"assign target", `marker = 2;`},
		{"assign value", `let a = 1; a = marker;`},
		{"field left", `marker.field;`},
		{"struct literal field value", `struct S { a; }; S { a: marker };`},
		{"array element", `[marker];`},
		{"template part", `"${marker}";`},
		{"hash key", `{marker: 1};`},
		{"hash value", `{"k": marker};`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graphOf(t, "let marker = 1;\n"+c.body+"\n")
			marker := find(t, g, "marker")
			if len(g.UsesOf(marker.ID)) == 0 {
				t.Fatalf("the walk never reached the use of marker in a %s.\n"+
					"A node type with no case in builder.statement or "+
					"builder.expression is a silent dead end: nothing inside it "+
					"is declared, resolved or findable.\n\nsource:\n%s",
					c.name, c.body)
			}
		})
	}
}

// The other half of the same property: every position a name can be declared
// in has to produce a declaration, or the name exists and nothing can see it.
func TestTheWalkDeclaresInEveryPositionANameCanBeDeclared(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want NodeKind
	}{
		{"top-level let", `let thing = 1;`, KindValue},
		{"top-level function", `let thing = fn() { return 1; };`, KindFunction},
		{"multi-name let", `let a, thing = split();`, KindValue},
		{"parameter", `let f = fn(thing) { return thing; };`, KindParam},
		{"macro parameter", `let m = macro(thing) { return thing; };`, KindParam},
		{"loop value binding", `for (thing in [1]) { }`, KindLoopBind},
		{"loop key binding", `for (thing, v in {"a": 1}) { }`, KindLoopBind},
		{"local let", `let f = fn() { let thing = 1; return thing; };`, KindValue},
		{"import alias", `import thing "lib/other.mut";`, KindNamespace},
		{"derived import alias", `import "lib/thing.mut";`, KindNamespace},
		{"struct name", `struct thing { a; };`, KindStruct},
		{"enum name", `enum thing { A, B };`, KindEnum},
		{"struct field", `struct S { thing; };`, KindField},
		{"enum variant", `enum E { thing };`, KindVariant},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graphOf(t, c.src+"\n")
			declared := find(t, g, "thing")
			if declared.Kind != c.want {
				t.Fatalf("declared as a %s, want a %s", declared.Kind, c.want)
			}
			if !declared.Anchor().IsValid() {
				t.Fatal("the declaration has no range, so nothing can jump to it")
			}
		})
	}
}

// The gap that motivated the whole step, stated as the thing a user notices.
func TestAnImportAliasIsAnOrdinaryBinding(t *testing.T) {
	g := graphOf(t, "import report \"lib/report.mut\";\nreport.label();\n")

	alias := find(t, g, "report")
	if alias.Kind != KindNamespace {
		t.Fatalf("the alias is a %s, want a namespace", alias.Kind)
	}

	uses := g.UsesOf(alias.ID)
	if len(uses) != 1 {
		t.Fatalf("the alias has %d uses, want the one in `report.label()`", len(uses))
	}

	visible := g.VisibleAt(2, 1)
	if !containsName(visible, "report") {
		t.Fatalf("the alias is not visible where it is used, so completion "+
			"cannot offer it; visible: %v", nameList(visible))
	}
}

// A derived alias is bound by a statement that never writes the name.
//
// That gives it somewhere to point and nothing to edit, and the two have to be
// kept apart. Rename replaces the text at every range it is handed, so handing
// it the path literal would turn `import "lib/report.mut";` into
// `import "newname";` -- a rename that breaks the import it was meant to tidy.
func TestADerivedImportAliasCanBeJumpedToButNotRenamed(t *testing.T) {
	g := graphOf(t, "import \"lib/report.mut\";\nreport.label();\n")

	alias := find(t, g, "report")
	if alias.Ident != nil {
		t.Fatal("the alias was not written, so it should have no identifier")
	}
	if alias.DeclRange.IsValid() {
		t.Fatalf("the alias has a name range covering %d:%d-%d:%d, and rename "+
			"would replace whatever text is there",
			alias.DeclRange.Start.Line, alias.DeclRange.Start.Column,
			alias.DeclRange.End.Line, alias.DeclRange.End.Column)
	}
	if !alias.Anchor().IsValid() || alias.Anchor().Start.Line != 1 {
		t.Fatalf("go-to-definition has nowhere to land; anchor is %+v", alias.Anchor())
	}
}

// The written form is the one that can be renamed, and it is the alias itself
// that gets edited rather than the statement around it.
func TestAWrittenImportAliasIsRenameable(t *testing.T) {
	g := graphOf(t, "import rep \"lib/report.mut\";\nrep.label();\n")

	alias := find(t, g, "rep")
	if !alias.DeclRange.IsValid() {
		t.Fatal("the alias was written, so it has a name to rename")
	}
	if alias.DeclRange.Start.Column != 8 {
		t.Fatalf("the name range starts at column %d, want 8 -- the `rep`, not "+
			"the `import` in front of it", alias.DeclRange.Start.Column)
	}
	if !alias.FullRange.IsValid() || alias.FullRange.Start.Column != 1 {
		t.Fatalf("the full range should cover the statement; got %+v", alias.FullRange)
	}
}

func TestTwoDeclarationsOfOneNameAreTwoDeclarations(t *testing.T) {
	g := graphOf(t, "let x = 1;\nx;\nlet x = 2;\nx;\n")

	first, second := (*Node)(nil), (*Node)(nil)
	for _, node := range g.Declarations() {
		if node.Name != "x" {
			continue
		}
		if first == nil {
			first = node
		} else {
			second = node
		}
	}
	if first == nil || second == nil {
		t.Fatalf("want two declarations of x, got %v", declaredNames(g))
	}
	if first.ID == second.ID {
		t.Fatal("both declarations of x share an identity, so renaming one renames the other")
	}

	firstUses, secondUses := g.UsesOf(first.ID), g.UsesOf(second.ID)
	if len(firstUses) != 1 || firstUses[0].Start.Line != 2 {
		t.Fatalf("the first x should be used once, on line 2; got %v", firstUses)
	}
	if len(secondUses) != 1 || secondUses[0].Start.Line != 4 {
		t.Fatalf("the second x should be used once, on line 4; got %v", secondUses)
	}
}

func TestAFunctionCanCallItselfButAMultiNameLetCannot(t *testing.T) {
	recursive := graphOf(t, "let f = fn() { return f(); };\n")
	if uses := recursive.UsesOf(find(t, recursive, "f").ID); len(uses) != 1 {
		t.Fatalf("a single-name let binds before its value is walked, so f sees "+
			"itself; got %d uses", len(uses))
	}

	pair := graphOf(t, "let a, b = b();\n")
	if uses := pair.UsesOf(find(t, pair, "b").ID); len(uses) != 0 {
		t.Fatalf("a multi-name let binds after its value is walked, so b does not "+
			"see itself; got %d uses", len(uses))
	}
}

// Mutant has fewer scopes than its syntax suggests, and the graph must not
// invent the missing ones.
func TestABlockOpensNoScopeAndAFunctionDoes(t *testing.T) {
	leaked := graphOf(t, "let f = fn() { if (true) { let inner = 1; } inner; };\n")
	if uses := leaked.UsesOf(find(t, leaked, "inner").ID); len(uses) != 1 {
		t.Fatalf("a block opens no scope, so inner is still bound after it; got %d uses", len(uses))
	}

	contained := graphOf(t, "let f = fn() { let inner = 1; };\ninner;\n")
	if uses := contained.UsesOf(find(t, contained, "inner").ID); len(uses) != 0 {
		t.Fatalf("a function body does open a scope, so inner does not escape it; got %d uses", len(uses))
	}
}

func TestALoopBindingOutlivesItsLoop(t *testing.T) {
	g := graphOf(t, "for (v in [1]) { }\nv;\n")
	if uses := g.UsesOf(find(t, g, "v").ID); len(uses) != 1 {
		t.Fatalf("a for-in binding is defined in the enclosing scope, which is "+
			"what the VM does; got %d uses", len(uses))
	}
}

// A struct or enum name never enters the compiler's symbol table, so it is not
// in the scope chain and does not shadow, or get shadowed by, a value.
func TestATypeNameAndAValueOfTheSameNameAreTwoBindings(t *testing.T) {
	g := graphOf(t, "struct Point { x; };\nlet Point = 1;\nPoint;\n")

	value, structure := (*Node)(nil), (*Node)(nil)
	for _, node := range g.Declarations() {
		switch node.Kind {
		case KindStruct:
			structure = node
		case KindValue:
			value = node
		}
	}
	if value == nil || structure == nil {
		t.Fatalf("want both a struct and a value called Point, got %v", declaredNames(g))
	}
	if value.ID == structure.ID {
		t.Fatal("the struct and the value share an identity")
	}
	if uses := g.UsesOf(value.ID); len(uses) != 1 {
		t.Fatalf("a bare Point in value position is the let; got %d uses of the let", len(uses))
	}
	if uses := g.UsesOf(structure.ID); len(uses) != 0 {
		t.Fatalf("the struct is not used here; got %d uses", len(uses))
	}
}

func TestAnEnumVariantResolvesThroughTheEnumName(t *testing.T) {
	g := graphOf(t, "enum Colour { Red, Green };\nColour.Red;\n")

	_, members, ok := g.TypeNamed("Colour")
	if !ok {
		t.Fatalf("Colour is not in the type table; declared: %v", declaredNames(g))
	}

	red := (*Node)(nil)
	for _, member := range members {
		if member.Name == "Red" {
			red = member
		}
	}
	if red == nil {
		t.Fatalf("Colour has no Red; members: %v", nameList(members))
	}
	if uses := g.UsesOf(red.ID); len(uses) != 1 {
		t.Fatalf("Colour.Red should be a use of the variant; got %d", len(uses))
	}
}

// The enum arm of Resolver.ResolveField comes before the bound-name arm, so an
// enum wins even where a value of the same name exists. The graph has to agree
// with the decision procedure it sits next to.
func TestAnEnumWinsOverAValueOfTheSameNameInFieldPosition(t *testing.T) {
	g := graphOf(t, "enum Colour { Red };\nlet Colour = 1;\nColour.Red;\n")

	value := (*Node)(nil)
	for _, node := range g.Declarations() {
		if node.Name == "Colour" && node.Kind == KindValue {
			value = node
		}
	}
	if value == nil {
		t.Fatalf("want a value called Colour; got %v", declaredNames(g))
	}
	if uses := g.UsesOf(value.ID); len(uses) != 0 {
		t.Fatalf("`Colour.Red` is the enum, not the let, so the let has no uses; got %d", len(uses))
	}
}

// A name declared below the cursor is not in scope at the cursor. Completion
// depends on this: a file's last function must not be offered at its top.
func TestADeclarationBelowThePositionIsNotVisibleAtIt(t *testing.T) {
	g := graphOf(t, "let above = 1;\nlet here = 2;\nlet below = 3;\n")

	visible := g.VisibleAt(2, 1)
	if !containsName(visible, "above") {
		t.Fatalf("a declaration above the position is visible; got %v", nameList(visible))
	}
	if containsName(visible, "below") {
		t.Fatalf("a declaration below the position is not; got %v", nameList(visible))
	}
}

func TestAParameterIsVisibleInsideItsFunctionAndNotOutside(t *testing.T) {
	g := graphOf(t, "let f = fn(arg) {\n  arg;\n};\nlet after = 1;\n")

	if inside := g.VisibleAt(2, 3); !containsName(inside, "arg") {
		t.Fatalf("the parameter is not visible in the body; got %v", nameList(inside))
	}
	if outside := g.VisibleAt(4, 1); containsName(outside, "arg") {
		t.Fatalf("the parameter escaped its function; got %v", nameList(outside))
	}
}

// The reserved scope roots carry a NUL precisely so a scope the author opened
// cannot be spelled the same way.
//
// `type` is not a Mutant keyword -- only `struct`, `enum` and `import` are --
// so `let type = fn() { let Point = fn() { ... }; };` opens a scope whose path
// would be `type/Point`, which is the very path a struct called `Point` gives
// its fields.
//
// What that costs is stated here as the stability contract, because that is
// where it is observable. Spell the root as the bare word `type` and the two
// scopes become one, the sequence counter that separates repeat declarations
// starts counting across both of them, and a struct field's identity then
// depends on whether some unrelated function happens to be written above it.
// Adding the function below changes nothing about `struct Point`. It must not
// change what its field is called.
func TestAFieldKeepsItsIdentityWhenAnUnrelatedFunctionIsAddedAboveIt(t *testing.T) {
	const declaration = "struct Point { x; };\n"
	const unrelated = "let type = fn() { let Point = fn() { let x = 1; return x; }; };\n"

	alone := fieldID(t, graphOf(t, declaration))
	preceded := fieldID(t, graphOf(t, unrelated+declaration))

	if alone != preceded {
		t.Fatalf("struct Point's field is %q on its own and %q with an unrelated\n"+
			"function above it. A DeclID is contracted to survive any edit that\n"+
			"does not touch its own enclosing scope, and this edit does not.",
			alone, preceded)
	}
}

func fieldID(t *testing.T, g *Graph) string {
	t.Helper()
	for _, node := range g.Declarations() {
		if node.Kind == KindField {
			return node.ID.String()
		}
	}
	t.Fatalf("no field was declared; the file declares %v", declaredNames(g))
	return ""
}

// Walk order is not source order. HashLiteral.Pairs is a Go map, so the uses
// inside one are reached in a different order on every run -- the same
// non-determinism that made two clone tests fail at random before
// HashLiteral.String started sorting. Find-references over a hash literal
// returned its locations shuffled for exactly this reason.
//
// Built repeatedly because one build could come out sorted by chance; eight
// entries make that a one-in-forty-thousand draw, and twenty independent draws
// make it nothing.
func TestUsesComeBackInSourceOrderWhateverOrderTheWalkReachedThem(t *testing.T) {
	const src = `let n = 1;
{"a": n, "b": n, "c": n, "d": n, "e": n, "f": n, "g": n, "h": n};
`

	for attempt := 0; attempt < 20; attempt++ {
		g := graphOf(t, src)
		uses := g.UsesOf(find(t, g, "n").ID)
		if len(uses) != 8 {
			t.Fatalf("want eight uses, got %d", len(uses))
		}
		for i := 1; i < len(uses); i++ {
			if !startsBefore(uses[i-1], uses[i]) {
				t.Fatalf("use %d starts at column %d and use %d at column %d, "+
					"so they are not in source order",
					i-1, uses[i-1].Start.Column, i, uses[i].Start.Column)
			}
		}
	}
}

func TestACallIsMarkedAsOne(t *testing.T) {
	g := graphOf(t, "let f = fn() { return 1; };\nf();\nlet g = f;\n")

	calls, plain := 0, 0
	for _, ref := range g.refList {
		if ref.InCallPosition {
			calls++
		} else {
			plain++
		}
	}
	if calls != 1 || plain != 1 {
		t.Fatalf("want one call and one plain reference, got %d and %d", calls, plain)
	}
}

func TestAnImportEdgeRecordsWhatWasWritten(t *testing.T) {
	g := graphOf(t, "import rep \"lib/report.mut\";\n")

	imports := g.Imports()
	if len(imports) != 1 {
		t.Fatalf("want one import edge, got %d", len(imports))
	}
	edge := imports[0]
	if edge.Alias != "rep" || edge.Spelling != "lib/report.mut" {
		t.Fatalf("edge records alias %q of %q", edge.Alias, edge.Spelling)
	}
	if edge.To != "" {
		t.Fatalf("no workspace was given, so nothing resolves; got target %q", edge.To)
	}
	if !edge.Range.IsValid() {
		t.Fatal("the edge has no range, so a documentLink has nothing to attach to")
	}
}

// An unbound name records no reference. Inventing one is how a jump into an
// unrelated file starts.
func TestAnUnboundNameRefersToNothing(t *testing.T) {
	// The file declares something, deliberately. A file with no declarations at
	// all cannot tell a graph that refuses to guess apart from one that would
	// have guessed and had nothing to guess from.
	g := graphOf(t, "let something = 1;\nnowhere;\n")

	if ref, found := g.ReferenceAt(2, 1); found {
		t.Fatalf("the undeclared name was resolved to %q. A name with no "+
			"declaration has no reference to record, and inventing one is how "+
			"a jump into an unrelated file starts.", ref.Target.String())
	}
	if uses := g.UsesOf(find(t, g, "something").ID); len(uses) != 0 {
		t.Fatalf("the one declaration in the file collected %d uses it has none of", len(uses))
	}
}

func TestAGraphOfNothingIsStillAGraph(t *testing.T) {
	g := BuildFile("", nil, nil, nil)
	if g == nil {
		t.Fatal("BuildFile returned nil")
	}
	if len(g.Declarations()) != 0 || len(g.Imports()) != 0 {
		t.Fatal("a nil program declared something")
	}
	if _, found := g.Resolve(1, 1); found {
		t.Fatal("a nil program resolved a position")
	}
}

func containsName(nodes []*Node, name string) bool {
	for _, node := range nodes {
		if node.Name == name {
			return true
		}
	}
	return false
}

func nameList(nodes []*Node) []string {
	names := make([]string, 0, len(nodes))
	for _, node := range nodes {
		names = append(names, node.Name)
	}
	return names
}

// Which declaration a use sits inside is a fact the walk has and nothing else
// does. Without it a consumer has to work it out again from positions -- the
// same "derive it a second time" that produced the five walks this package
// replaced -- and a call graph becomes a second traversal instead of a filter
// over the references already recorded.
func TestAUseKnowsWhichDeclarationItSitsInside(t *testing.T) {
	g := graphOf(t, "let helper = fn() { return 1; };\n"+
		"let caller = fn() { return helper(); };\n"+
		"helper();\n")

	helper := find(t, g, "helper")
	caller := find(t, g, "caller")

	inside, atTopLevel := 0, 0
	for _, ref := range g.References() {
		if ref.Target != helper.ID {
			continue
		}
		switch {
		case ref.From == nil:
			atTopLevel++
		case ref.From.ID == caller.ID:
			inside++
		default:
			t.Fatalf("a use of helper is attributed to %q, which declares neither "+
				"of the two places it is written", ref.From.Name)
		}
	}
	if inside != 1 {
		t.Fatalf("%d uses of helper are attributed to caller, want 1", inside)
	}
	if atTopLevel != 1 {
		t.Fatalf("%d uses of helper are at the file's top level, want 1 -- a use "+
			"outside every declaration belongs to no declaration, not to the "+
			"nearest one above it", atTopLevel)
	}
}

// An anonymous literal opens a scope and declares nothing, so it cannot own a
// use. The use belongs to the nearest declaration that does -- otherwise every
// callback in the file would be attributed to the top level, and a call graph
// would lose exactly the calls that are hardest to find by reading.
func TestAUseInsideAnAnonymousLiteralBelongsToTheDeclarationAroundIt(t *testing.T) {
	g := graphOf(t, "let helper = fn(x) { return x; };\n"+
		"let each = fn(xs, f) { return f(xs); };\n"+
		"let run = fn() { return each([1], fn(v) { return helper(v); }); };\n")

	helper := find(t, g, "helper")
	run := find(t, g, "run")

	for _, ref := range g.References() {
		if ref.Target != helper.ID {
			continue
		}
		if ref.From == nil {
			t.Fatal("the use of helper inside the callback belongs to no declaration")
		}
		if ref.From.ID != run.ID {
			t.Fatalf("the use of helper inside the callback is attributed to %q, "+
				"want run -- the anonymous fn declares nothing to own it", ref.From.Name)
		}
		return
	}
	t.Fatal("the use of helper inside the callback was not recorded at all")
}

// Owner is exact where enclosing is not: an anonymous literal's scope is owned
// by nobody, and saying it was owned by the declaration around it would be a
// small lie that an outline would render as a function nested inside another.
func TestAScopeKnowsWhichDeclarationOpenedItAndAnAnonymousOneOpensNothing(t *testing.T) {
	g := graphOf(t, "struct Point { x; y; };\n"+
		"let named = fn(a) { return a; };\n"+
		"let holder = fn() { return fn(b) { return b; }; };\n")

	if g.Root.Owner != nil {
		t.Fatalf("the file's own scope is owned by %q; it is owned by the file",
			g.Root.Owner.Name)
	}

	named := find(t, g, "named")
	if named.Scope != g.Root {
		t.Fatal("a top-level declaration does not live in the file's scope")
	}

	owners := map[string]string{}
	var walk func(*Scope)
	walk = func(scope *Scope) {
		for _, child := range scope.Children {
			owner := "(none)"
			if child.Owner != nil {
				owner = child.Owner.Name
			}
			owners[string(child.Path)] = owner
			walk(child)
		}
	}
	walk(g.Root)
	walk(g.Types)

	if got := owners["named"]; got != "named" {
		t.Fatalf("the scope of `named` is owned by %s, want named", got)
	}
	if got := owners["holder/fn#0"]; got != "(none)" {
		t.Fatalf("an anonymous literal's scope claims to be owned by %s; it "+
			"declares nothing, so nothing owns it", got)
	}
	if got := owners[string(ScopeType.Child("Point"))]; got != "Point" {
		t.Fatalf("the scope holding Point's fields is owned by %s, want Point", got)
	}
}
