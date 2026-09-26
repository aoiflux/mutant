package sema

import "testing"

// refsTo is every reference to a declaration called name, in source order.
func refsTo(g *Graph, owner *Graph, name string) []Ref {
	var out []Ref
	for _, ref := range g.References() {
		target, found := owner.NodeFor(ref.Target)
		if found && target.Name == name {
			out = append(out, ref)
		}
	}
	return out
}

// A question about a type is usually "where is it built" or "where is it told
// apart", and a list of every mention answers neither. So a reference says
// which of the three it is, and the export labels its edge accordingly.
func TestAUseSaysWhetherItBuildsComparesOrNames(t *testing.T) {
	g := graphOf(t, `struct Point { x; };
enum Status { Ok, Failed };
let make = fn() { return Point{x: 1}; };
let p = make();
let f = fn(s) { return match (s) { Status.Ok => p.x, _ => 0, }; };
Status.Failed;
`)

	point := refsTo(g, g, "Point")
	if len(point) != 1 || point[0].Role != RoleConstruct {
		t.Fatalf("the struct literal's type name is %+v, want one construction", point)
	}
	if from := point[0].From; from == nil || from.Name != "make" {
		t.Fatalf("the construction is attributed to %v, want the function that makes it", from)
	}
	if x := refsTo(g, g, "x"); len(x) != 1 || x[0].Role != RoleUse {
		t.Fatalf("the field named inside the literal is %+v; it is a use of the field, and "+
			"only the type is constructed", x)
	}

	status := refsTo(g, g, "Status")
	if len(status) != 2 {
		t.Fatalf("Status is referenced %d times, want 2", len(status))
	}
	if status[0].Role != RolePattern || status[1].Role != RoleUse {
		t.Fatalf("Status in the arm is %s and at the top level is %s; want pattern, then use",
			status[0].Role, status[1].Role)
	}
	if ok := refsTo(g, g, "Ok"); len(ok) != 1 || ok[0].Role != RolePattern {
		t.Fatalf("the variant in the pattern is %+v, want one pattern use", ok)
	}
	// The arm's body is not a pattern: what it reads is used, not matched.
	for _, ref := range refsTo(g, g, "p") {
		if ref.Role != RoleUse {
			t.Fatalf("p read in an arm body is a %s", ref.Role)
		}
	}
}

// A miss is what a Ref would have been, so it carries the same two facts: the
// declaration it was written in, and what it did.
func TestAMissSaysWhereItWasAndWhatItDid(t *testing.T) {
	g := graphOf(t, `let f = fn() { return Nope{x: 1}; };
let g = fn(v) { return match (v) { Gone.Away => 1, _ => 2, }; };
`)
	misses := map[string]Unbound{}
	for _, miss := range g.UnboundUses() {
		misses[miss.Name] = miss
	}

	nope, found := misses["Nope"]
	if !found || nope.Kind != UnboundType || nope.Role != RoleConstruct {
		t.Fatalf("Nope{...} is %+v, want a type miss that constructs", nope)
	}
	if nope.From == nil || nope.From.Name != "f" {
		t.Fatalf("Nope{...} is attributed to %v, want f", nope.From)
	}

	gone, found := misses["Gone"]
	if !found || gone.Kind != UnboundReceiver || gone.Role != RolePattern {
		t.Fatalf("Gone.Away in a pattern is %+v, want a receiver miss in a pattern", gone)
	}
	if gone.From == nil || gone.From.Name != "g" {
		t.Fatalf("Gone.Away is attributed to %v, want g", gone.From)
	}
}

// Within a program, a type another module declares is a reference into that
// module -- its fields and variants too -- provided the module compiles first.
// A file on its own has no "first", and still records the miss: that is the
// language server's graph, and it must not start resolving names it cannot
// check against the compiler's order.
func TestATypeFromAnEarlierModuleIsAReferenceIntoIt(t *testing.T) {
	program, key := programOf(t,
		[]string{"lib/geo.mut", "main.mut"},
		map[string]string{
			"lib/geo.mut": "struct Loc { a; b; };\nenum Dir { N, S };\n",
			"main.mut": "import \"lib/geo.mut\";\nlet l = fn() { return Loc{a: 1, b: 2}; };\n" +
				"let d = fn(x) { return match (x) { Dir.S => 1, _ => 0, }; };\n",
		})
	geo, _ := program.ModuleFor(key("lib/geo.mut"))
	main, _ := program.ModuleFor(key("main.mut"))

	for _, want := range []struct {
		name string
		role RefRole
		from string
	}{
		{"Loc", RoleConstruct, "l"},
		{"a", RoleUse, "l"},
		{"b", RoleUse, "l"},
		{"Dir", RolePattern, "d"},
		{"S", RolePattern, "d"},
	} {
		refs := refsTo(main.Graph, geo.Graph, want.name)
		if len(refs) != 1 {
			t.Fatalf("main.mut holds %d reference(s) to geo's %s, want 1", len(refs), want.name)
		}
		ref := refs[0]
		if ref.Target.Module != geo.Key {
			t.Fatalf("%s resolved into %q, want lib/geo.mut", want.name, ref.Target.Module)
		}
		if ref.Role != want.role || ref.From == nil || ref.From.Name != want.from {
			t.Fatalf("%s is a %s from %v, want a %s from %s", want.name, ref.Role, ref.From, want.role, want.from)
		}
	}
	if len(main.UnresolvedTypeUses) != 0 {
		t.Fatalf("main.mut counts %d unresolved type use(s), and every one resolved", len(main.UnresolvedTypeUses))
	}

	alone := BuildFile(main.Key, parse(t, "import \"lib/geo.mut\";\nlet l = Loc{a: 1, b: 2};\n"), nil, nil)
	if len(alone.UnboundUses()) != 1 || alone.UnboundUses()[0].Name != "Loc" {
		t.Fatalf("a file built on its own resolved another module's type: %+v", alone.UnboundUses())
	}
}

// A use nothing resolves is counted when it names a type, and only then. The
// test that matters is the one that does not count: `hash.sha256` is a
// builtin, and a later module that happens to declare `enum hash` does not make
// it a use of that enum.
func TestOnlyATypeUseThatDidNotResolveIsCounted(t *testing.T) {
	program, key := programOf(t,
		[]string{"lib/early.mut", "main.mut"},
		map[string]string{
			"lib/early.mut": "let a = Later{x: 1};\nlet b = Dir.S;\nlet c = hash.sha256(\"x\");\nlet d = Nowhere{y: 2};\n",
			"main.mut":      "import \"lib/early.mut\";\nstruct Later { x; };\nenum Dir { N, S };\nenum hash { one };\n",
		})
	early, _ := program.ModuleFor(key("lib/early.mut"))

	var names []string
	for _, miss := range early.UnresolvedTypeUses {
		names = append(names, miss.Name)
	}
	if len(names) != 3 || names[0] != "Later" || names[1] != "Dir" || names[2] != "Nowhere" {
		t.Fatalf("the unresolved type uses are %v, want Later, Dir and Nowhere -- and not hash, "+
			"whose sha256 is a builtin rather than a variant", names)
	}
}
