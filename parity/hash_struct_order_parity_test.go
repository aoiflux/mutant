package parity

import (
	"bytes"
	"strings"
	"testing"

	"mutant/compiler"
	"mutant/lexer"
	"mutant/parser"
)

// M26-CMP-010 and M26-LEX-004, which were one defect: a compound literal runs
// its parts where they are written, both engines agree about that, and one
// source compiles to one bytecode.
//
// ast.HashLiteral used to keep its pairs in a Go map, so the written order was
// gone by the time either engine saw the literal. The compiler rebuilt an order
// by sorting on key.String() and the evaluator used whatever the map handed
// over, so one program ran its own side effects in two different orders
// depending on which engine ran it -- and where two keys rendered alike the sort
// had nothing left to separate them, so the same source compiled to different
// bytes on different builds. compileStructLiteral had the same defect without a
// map to blame: it compiled the initialisers in the order the DECLARATION listed
// the fields, so `Header{magic: next(), size: next()}` against
// `struct Header { size, magic }` gave each field the other one's value.

// marker and counter are the two ways a program can report the order its own
// parts ran in: one appends to a string, one hands out ascending numbers.
const (
	marker = "let log = \"\";\n" +
		"let mark = fn(s) { log = log + s; return s; };\n"

	counter = "let n = 0;\n" +
		"let next = fn() { n = n + 1; return n; };\n"
)

func TestACompoundLiteralRunsItsPartsInSourceOrderInBothEngines(t *testing.T) {
	for _, c := range []struct{ name, input, want string }{
		{
			// Ordered by key.String() this is "a2b3c1": the keys render as
			// mark(c), mark(a) and mark(b), because ast.StringLiteral.String()
			// renders a string without its quotes.
			name:  "a hash literal runs each key then its value, pair by pair",
			input: marker + `let h = {mark("c"): mark("1"), mark("a"): mark("2"), mark("b"): mark("3")}; log`,
			want:  `STRING("c1a2b3")`,
		},
		{
			name: "a struct literal runs its initialisers where they are written",
			input: counter + "struct Header { size, magic }\n" +
				"let h = Header{magic: next(), size: next()};\n" +
				"h.magic",
			want: "INTEGER(1)",
		},
		{
			name: "and the field written second gets the second value",
			input: counter + "struct Header { size, magic }\n" +
				"let h = Header{magic: next(), size: next()};\n" +
				"h.size",
			want: "INTEGER(2)",
		},
		{
			// A literal written inside a LATER initialiser of another literal is
			// the case that needs the spill slots keyed by nesting depth: the
			// outer literal has already stashed its first value when the inner
			// one runs, so one shared slot would overwrite it. `o.y` is that
			// first value.
			name: "a struct literal nested in a later initialiser keeps its own slots",
			input: counter + "struct Inner { a, b }\n" +
				"struct Outer { x, y }\n" +
				"let o = Outer{y: next(), x: Inner{b: next(), a: next()}};\n" +
				"[o.y, o.x.b, o.x.a]",
			want: "ARRAY([1, 2, 3])",
		},
		{
			// Two keys that are one key only at run time, so the parser cannot
			// refuse them. The later pair wins, in both engines, because both
			// write the pairs into a map in the order the literal holds them.
			name:  "a key only the run time knows is a duplicate takes the later value",
			input: `let k = "k"; let h = {k: 1, "k": 2}; h["k"]`,
			want:  "INTEGER(2)",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			evalRes := normalize(evalViaEvaluator(c.input))
			vmObj, vmErr := evalViaVM(t, c.input)
			if vmErr != nil {
				t.Fatalf("the VM failed: %v", vmErr)
			}
			vmRes := normalize(vmObj)
			if vmRes != c.want {
				t.Errorf("the compiled engine answered %s, want %s", vmRes, c.want)
			}
			if evalRes != c.want {
				t.Errorf("the evaluator answered %s, want %s", evalRes, c.want)
			}
		})
	}
}

// compiledInstructions is the bytecode one compile of src produces, with no
// encryption and no password: the instruction bytes are the whole question.
func compiledInstructions(t *testing.T, src string) []byte {
	t.Helper()

	p := parser.New(lexer.New(src))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		t.Fatalf("source did not parse: %s", errs[0])
	}
	comp := compiler.New()
	if err := comp.Compile(program); err != nil {
		t.Fatalf("compiler error: %s", err)
	}
	return []byte(comp.ByteCode().Instructions)
}

// One source, one bytecode. The identifier `k` and the string "k" both render
// as `k`, so the sort that used to order the pairs had nothing left to separate
// them and fell through to Go map iteration. Measured before the fix, over
// twenty-four separate builds of `let h = {"k": 1, "k": 2}; h["k"]`: 2 on twenty
// of them and 1 on the other four. Go draws a fresh iteration order per range,
// so sixty-four compiles in one process is the same experiment run cheaply.
func TestOneSourceCompilesToOneBytecode(t *testing.T) {
	const src = `let k = "k"; let h = {k: 1, "k": 2}; h["k"]`

	first := compiledInstructions(t, src)
	for i := 0; i < 64; i++ {
		if got := compiledInstructions(t, src); !bytes.Equal(got, first) {
			t.Fatalf("compile %d emitted %d bytes, the first emitted %d, and they differ",
				i, len(got), len(first))
		}
	}
}

// A key the literal itself states twice is refused where it is written, because
// one of the two values is dropped and the syntax does not say which. It is the
// parser that refuses it, so one refusal covers both engines and the editor,
// which reads the same typed errors.
func TestAHashLiteralMayNotSetOneKeyTwice(t *testing.T) {
	for _, c := range []struct{ name, input, key string }{
		{"a string key", `let h = {"k": 1, "k": 2};`, `"k"`},
		{"an integer key", `let h = {7: 1, 7: 2};`, "7"},
		{"a float key", `let h = {1.5: 1, 1.5: 2};`, "1.5"},
		{"a boolean key", `let h = {true: 1, true: 2};`, "true"},
		{"not adjacent", `let h = {"a": 1, "b": 2, "a": 3};`, `"a"`},
		// The value and not the spelling: ParseInt reads 07 in base 0, so these
		// are two spellings of the integer 7 and one key.
		{"one integer written two ways", `let h = {07: 1, 7: 2};`, "7"},
		// Likewise 1.50 and 1.5.
		{"one float written two ways", `let h = {1.50: 1, 1.5: 2};`, "1.5"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := parser.New(lexer.New(c.input))
			p.ParseProgram()
			errs := p.Errors()
			if len(errs) == 0 {
				t.Fatalf("%s was accepted, and one of its two values is dropped", c.input)
			}
			if !strings.Contains(errs[0], c.key) || !strings.Contains(errs[0], "twice") {
				t.Errorf("the refusal does not name %s as a key set twice:\n  %s", c.key, errs[0])
			}
		})
	}
}

// And the keys that only look alike. Refusing one of these would refuse a
// working program, which is the one outcome worse than the defect: a kind is
// part of a hash key, and a key the literal does not state is not the parser's
// to judge.
func TestAHashLiteralKeepsTheKeysThatOnlyLookAlike(t *testing.T) {
	for _, c := range []struct{ name, input string }{
		{"an integer and a string that print the same", `let h = {1: 1, "1": 2};`},
		{"an integer and a float of the same value", `let h = {1: 1, 1.0: 2};`},
		{"a negated number, which is an expression and not a literal", `let h = {0.0: 1, -0.0: 2};`},
		{"a string and an identifier spelled the same way", `let k = "k"; let h = {k: 1, "k": 2};`},
		{"two names", `let a = 1; let b = 2; let h = {a: 1, b: 2};`},
		{"one key name in two nested literals", `let h = {"a": {"x": 1}, "b": {"x": 2}};`},
		{"one key name in two sibling literals", `let a = {"x": 1}; let b = {"x": 2};`},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := parser.New(lexer.New(c.input))
			p.ParseProgram()
			if errs := p.Errors(); len(errs) > 0 {
				t.Fatalf("%s was refused: %s", c.input, errs[0])
			}
		})
	}
}
