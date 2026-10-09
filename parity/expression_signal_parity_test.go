package parity

// A `return`, a `break` or a `continue` reached from inside an EXPRESSION, held
// against what each engine does with it.
//
// This is M26-EVL-025, and it is the sibling of loop_control_parity_test.go's
// M26-EVL-023. That row was the signal escaping a CALL; this one is the signal
// escaping an expression it was written inside, which the same fix did not
// reach. A block is a value in this language -- `let v = if (c) { break; } else
// { 1 };` is ordinary -- so eval of a block hands the signal back as the block's
// result, and expression evaluation then guarded only isError. Anything that was
// not an error was a value, so the signal was appended to an argument list,
// stored as a hash value, used as an array element or added to an integer, and
// the loop or function it was meant for never saw it.
//
// Measured at a923a5c over these shapes: the evaluator was wrong on twelve of
// thirteen loop-control shapes and on six of seven return shapes, three of each
// SILENTLY -- a wrong number with no diagnostic. One did not terminate at all.
//
// The engines do not yet agree everywhere, and that is recorded here rather
// than left out: vmAgrees marks each shape, and the test below fails if a
// shape marked as still-divergent starts agreeing. M26-CMP-003 is the compiler
// half, and when it lands it has to move those entries rather than discover
// them.

import (
	"strings"
	"testing"
	"time"

	"mutant/object"
	"mutant/sema"
)

// signalShape is one program, the answer a correct engine gives, and whether
// the VM already gives it.
//
// want is the answer, not a comparison between the engines. A parity test that
// asserted only "both engines agree" would have passed on this row at every
// point in its history where they were both wrong, and for the first array
// element they were -- the evaluator answered 3 and the VM answered 1 for a
// program whose answer is 1, so agreement and correctness were different
// questions and only one of them was being asked.
type signalShape struct {
	name     string
	src      string
	want     string
	vmAgrees bool
	silent   bool // the evaluator answered this one with a wrong number, no error
}

var expressionSignalShapes = []signalShape{
	// ---- break, reached from an operand position ----
	{
		name:     "infix right operand",
		src:      `let n = 0; for (v in [1,2,3]) { n = n + (if (v == 2) { break; } else { v }); } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "infix right operand, nested two deep",
		src:      `let n = 0; for (v in [1,2,3]) { n = n + (1 + (2 * (if (v == 2) { break; } else { v }))); } n;`,
		want:     "INTEGER(3)",
		vmAgrees: true,
	},
	{
		name:     "prefix operand",
		src:      `let n = 0; for (v in [1,2,3]) { n = n + (-(if (v == 2) { break; } else { v })); } n;`,
		want:     "INTEGER(-1)",
		vmAgrees: true,
	},
	{
		name:     "index of an index expression",
		src:      `let xs = [10,20,30]; let n = 0; for (v in [1,2,3]) { n = n + xs[if (v == 2) { break; } else { v }]; } n;`,
		want:     "INTEGER(20)",
		vmAgrees: true,
	},
	{
		name:     "the container of an index expression",
		src:      `let xs = [[1],[2],[3]]; let n = 0; for (v in [1,2,3]) { let q = (if (v == 2) { break; } else { xs })[0]; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "a hash value",
		src:      `let n = 0; for (v in [1,2,3]) { let h = {"k": if (v == 2) { break; } else { v }}; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "a call argument",
		src:      `let n = 0; for (v in [1,2,3]) { n = n + len([if (v == 2) { break; } else { v }]); } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "the FIRST array element",
		src:      `let n = 0; for (v in [1,2,3]) { let t = [if (v == 2) { break; } else { v }, 0]; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "a let initialiser",
		src:      `let n = 0; for (v in [1,2,3]) { let w = if (v == 2) { break; } else { v }; n = n + w; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "an if condition",
		src:      `let n = 0; for (v in [1,2,3]) { if (if (v == 2) { break; } else { false }) { n = n + 100; } n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "a match subject",
		src:      `let n = 0; for (v in [1,2,3]) { let q = match (if (v == 2) { break; } else { v }) { 1 => 1, _ => 0 }; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "a match ARM body",
		src:      `let n = 0; for (v in [1,2,3]) { let q = match (v) { 2 => { break; }, _ => 0 }; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "the right operand of a logical &&, which is not short-circuited away",
		src:      `let n = 0; for (v in [1,2,3]) { let q = true && (if (v == 2) { break; } else { true }); n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "a template literal hole",
		src:      `let n = 0; for (v in [1,2,3]) { let s = "x${if (v == 2) { break; } else { v }}"; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "a struct literal field value",
		src:      `struct P { a } let n = 0; for (v in [1,2,3]) { let p = P{a: if (v == 2) { break; } else { v }}; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "the target of a field access",
		src:      `struct P { a } let n = 0; for (v in [1,2,3]) { let q = (if (v == 2) { break; } else { P{a: 1} }).a; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "the right-hand side of an assignment",
		src:      `let q = 0; let n = 0; for (v in [1,2,3]) { q = if (v == 2) { break; } else { v }; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "the right-hand side of a compound index assignment",
		src:      `let xs = [0,0,0]; let n = 0; for (v in [1,2,3]) { xs[0] += if (v == 2) { break; } else { v }; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "the index of an index assignment",
		src:      `let xs = [0,0,0]; let n = 0; for (v in [1,2,3]) { xs[if (v == 2) { break; } else { 0 }] = v; n = n + 1; } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "a return operand",
		src:      `let f = fn() { for (v in [1,2,3]) { return (if (v == 2) { break; } else { v }); } return 0; }; f();`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "a while loop's body, from an operand",
		src:      `let i = 0; let n = 0; while (i < 3) { i = i + 1; n = n + (if (i == 2) { break; } else { i }); } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},

	// ---- continue, reached from an operand position ----
	{
		name:     "continue from a let initialiser",
		src:      `let n = 0; for (v in [1,2,3]) { let w = if (v == 2) { continue; } else { v }; n = n + w; } n;`,
		want:     "INTEGER(4)",
		vmAgrees: true,
	},
	{
		name:     "continue from a hash value",
		src:      `let n = 0; for (v in [1,2,3]) { let h = {"k": if (v == 2) { continue; } else { v }}; n = n + 1; } n;`,
		want:     "INTEGER(2)",
		vmAgrees: false,
		silent:   true,
	},
	{
		name:     "continue from a match arm, reached through an operand",
		src:      `let score = 0; for (k in ["a","skip","b"]) { score = score + match (k) { "skip" => { continue; }, "a" => 1, _ => 2 }; } score;`,
		want:     "INTEGER(3)",
		vmAgrees: false,
	},
	{
		name:     "continue binds to the innermost loop, from an operand",
		src:      `let n = 0; for (a in [1,2]) { for (b in [1,2,3]) { n = n + (if (b == 2) { continue; } else { b }); } } n;`,
		want:     "INTEGER(8)",
		vmAgrees: false,
	},

	// ---- return, reached from an operand position ----
	// The same defect, and the one with the wider reach: a `return` inside an
	// if-expression is something people write, where a `break` there is not.
	{
		name:     "return from a let initialiser",
		src:      `let f = fn(x) { let w = if (x == 2) { return 99; } else { x }; return w; }; f(2);`,
		want:     "INTEGER(99)",
		vmAgrees: true,
	},
	{
		name:     "return from the FIRST array element",
		src:      `let f = fn(x) { let t = [if (x == 2) { return 99; } else { x }, 0]; return 0; }; f(2);`,
		want:     "INTEGER(99)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "return from an infix right operand",
		src:      `let f = fn(x) { return 1 + (if (x == 2) { return 99; } else { x }); }; f(2);`,
		want:     "INTEGER(99)",
		vmAgrees: true,
	},
	{
		name:     "return from a call argument",
		src:      `let f = fn(x) { return len([if (x == 2) { return 99; } else { x }]); }; f(2);`,
		want:     "INTEGER(99)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "return from a hash value",
		src:      `let f = fn(x) { let h = {"k": if (x == 2) { return 99; } else { x }}; return 0; }; f(2);`,
		want:     "INTEGER(99)",
		vmAgrees: true,
		silent:   true,
	},
	{
		name:     "return from a prefix operand",
		src:      `let f = fn(x) { return -(if (x == 2) { return 99; } else { x }); }; f(2);`,
		want:     "INTEGER(99)",
		vmAgrees: true,
	},
	{
		name:     "return from an operand at the top level",
		src:      `let n = 1 + (if (true) { return 7; } else { 0 }); n;`,
		want:     "INTEGER(7)",
		vmAgrees: true,
	},

	// ---- the loop's own header ----
	// The compiler compiles a condition, an init section and a for-in's
	// iterable BEFORE pushing the loop's context, and the body and the post
	// section inside it. So a break in a header belongs to an ENCLOSING loop,
	// and a break in a post section belongs to this one. That asymmetry is the
	// compiler's; the evaluator matches it rather than inventing a second rule.
	{
		name:     "a break in an inner for-in's iterable belongs to the outer loop",
		src:      `let n = 0; for (a in [1,2,3]) { for (v in (if (a == 2) { break; } else { [1] })) { n = n + 1; } } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "a break in an inner while condition belongs to the outer loop",
		src:      `let n = 0; for (a in [1,2,3]) { let i = 0; while (if (a == 2) { break; } else { i < 1 }) { i = i + 1; n = n + 1; } } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "a break in an inner for init belongs to the outer loop",
		src:      `let n = 0; for (a in [1,2,3]) { for (let i = (if (a == 2) { break; } else { 0 }); i < 1; i = i + 1) { n = n + 1; } } n;`,
		want:     "INTEGER(1)",
		vmAgrees: true,
	},
	{
		name:     "a break in a for POST section belongs to that loop",
		src:      `let n = 0; for (let i = 0; i < 5; i = i + (if (i == 2) { break; } else { 1 })) { n = n + 1; } n;`,
		want:     "INTEGER(3)",
		vmAgrees: true,
	},

	// ---- controls ----
	// These passed before the fix and have to go on passing: the guard must
	// catch a signal used as a value without catching a signal used as a
	// statement, which is what loop control is for.
	{
		name:     "statement-level break, nothing pending (control)",
		src:      `let out = []; for (a in [1,2,3]) { for (b in [10,20]) { if (b == 20) { break; } } out = push(out, a); } out;`,
		want:     "ARRAY([1, 2, 3])",
		vmAgrees: true,
	},
	{
		name:     "statement-level return (control)",
		src:      `let f = fn(x) { if (x == 2) { return 99; } return 0; }; f(2);`,
		want:     "INTEGER(99)",
		vmAgrees: true,
	},
	{
		name:     "a short circuit that skips the break (control)",
		src:      `let n = 0; for (v in [1,2,3]) { let q = false && (if (v == 1) { break; } else { true }); n = n + 1; } n;`,
		want:     "INTEGER(3)",
		vmAgrees: true,
	},
	{
		name:     "an if-expression value with no signal in it (control)",
		src:      `let n = 0; for (v in [1,2,3]) { n = n + (if (v == 2) { 10 } else { v }); } n;`,
		want:     "INTEGER(14)",
		vmAgrees: true,
	},
	{
		name:     "an array holding an if-expression value (control)",
		src:      `let out = []; for (v in [1,2,3]) { out = push(out, [if (v == 2) { 10 } else { v }, 0]); } len(out);`,
		want:     "INTEGER(3)",
		vmAgrees: true,
	},

	// ---- the one shape where the evaluator was already right ----
	// Kept because it is M26-CMP-003's own case (a), and because it is the
	// proof that these two rows are one defect in two engines rather than one
	// engine's defect: here the VM is the wrong one.
	{
		name:     "an array element after the first, inner loop breaking",
		src:      `let out = []; for (a in [1,2,3]) { for (b in [10,20]) { let t = [0, if (b == 20) { break; } else { b }]; } out = push(out, a); } out;`,
		want:     "ARRAY([1, 2, 3])",
		vmAgrees: false,
	},
}

// TestTheEvaluatorLeavesAnExpressionWhenASignalReachesIt is the row's
// assertion, and it is about one engine on purpose.
//
// The usual parity shape -- run both, compare -- cannot be the whole test here,
// because for five of these shapes the VM is still wrong and the comparison
// would fail for the opposite reason. So this asserts the answer, and the test
// after it asserts the agreement, separately.
func TestTheEvaluatorLeavesAnExpressionWhenASignalReachesIt(t *testing.T) {
	for _, shape := range expressionSignalShapes {
		t.Run(shape.name, func(t *testing.T) {
			got := normalize(evalViaEvaluator(shape.src))
			if got != shape.want {
				t.Errorf("the evaluator answered %s, want %s\n  %s", got, shape.want, shape.src)
			}
		})
	}
}

// TestNoExpressionSignalShapeFailsSilently is the half that would have caught
// this row soonest, and the half an error-message test cannot.
//
// Nine of the shapes surfaced as spurious errors naming the control object as a
// type -- `type mismatch: INTEGER+BREAK`, `unknown operator: -BREAK`, `index
// operator not supported: ARRAY`. Those were at least visible. The ones marked
// silent answered an ordinary number: a Break stored in an array, a hash or an
// argument list, the loop running to completion, exit 0. Since `mutant gen`
// expands macros through this engine with no flag behind it, a macro body of
// that shape spliced the wrong value into the generated program and said
// nothing.
func TestNoExpressionSignalShapeFailsSilently(t *testing.T) {
	silent := 0
	for _, shape := range expressionSignalShapes {
		if !shape.silent {
			continue
		}
		silent++
		t.Run(shape.name, func(t *testing.T) {
			if got := normalize(evalViaEvaluator(shape.src)); got != shape.want {
				t.Errorf("answered %s, want %s -- and this shape answers with no error at all, "+
					"so a wrong answer here reaches the program silently\n  %s", got, shape.want, shape.src)
			}
		})
	}
	if silent == 0 {
		t.Fatal("no shape is marked silent, so this test asserts nothing; the silent class is the " +
			"reason the row is not S4")
	}
}

// TestTheEnginesAgreeExactlyWhereTheTableSaysTheyDo holds the remaining
// divergence open rather than leaving it out of the suite.
//
// Both directions are checked. A shape marked vmAgrees that stops agreeing is a
// regression. A shape marked as still-divergent that starts agreeing is not a
// failure of the code -- it means M26-CMP-003 has landed -- but it is a failure
// of this table, and saying so here is what stops a stale entry passing
// vacuously and taking the real assertion down with it.
func TestTheEnginesAgreeExactlyWhereTheTableSaysTheyDo(t *testing.T) {
	for _, shape := range expressionSignalShapes {
		t.Run(shape.name, func(t *testing.T) {
			tree := normalize(evalViaEvaluator(shape.src))

			compiled, compileErr := compilerComplaint(shape.src)
			if compileErr {
				if shape.vmAgrees {
					t.Fatalf("the compiler refuses a shape the table says the VM agrees on: %q\n  %s",
						compiled, shape.src)
				}
				return
			}

			machine, runErr := evalViaVM(t, shape.src)
			if runErr != nil {
				if shape.vmAgrees {
					t.Fatalf("the VM failed a shape the table says it agrees on: %v\n  %s", runErr, shape.src)
				}
				return
			}

			switch agrees := normalize(machine) == tree; {
			case shape.vmAgrees && !agrees:
				t.Errorf("engines disagree: evaluator %s, VM %s, want %s\n  %s",
					tree, normalize(machine), shape.want, shape.src)
			case !shape.vmAgrees && agrees:
				t.Errorf("the VM now agrees (%s) on a shape this table records as still wrong. "+
					"If M26-CMP-003 has landed, set vmAgrees on %q; an entry left stale here passes "+
					"without asserting anything.", normalize(machine), shape.name)
			}
		})
	}
}

// TestNoExpressionSignalShapeHangs exists because one of them did.
//
// `while (if (i == 2) { break; } else { true })` produced a Break object, and
// object.IsTruthy answers true for one, so the loop ran for ever -- on a program
// the compiler refuses outright. A wrong answer is a bug; a tree-walker that
// does not return is `mutant gen` wedged, holding whatever it had allocated,
// which on this project has needed a WMI kill to clear. The cap is generous
// because the assertion is termination, not speed.
func TestNoExpressionSignalShapeHangs(t *testing.T) {
	for _, shape := range append(expressionSignalShapes, signalShape{
		name: "break in a while condition, no enclosing loop",
		src:  `let i = 0; let n = 0; while (if (i == 2) { break; } else { true }) { i = i + 1; n = n + 1; } n;`,
		want: "ERROR",
	}) {
		t.Run(shape.name, func(t *testing.T) {
			done := make(chan string, 1)
			go func() { done <- normalize(evalViaEvaluator(shape.src)) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("the evaluator did not terminate\n  %s", shape.src)
			}
		})
	}
}

// TestASignalWithNoLoopLeftIsRefusedInTheCompilersWords covers the boundary the
// propagation creates: once a signal travels, something has to stop it.
//
// The compiler refuses every one of these at compile time, with
// sema.LoopControlRefusal's sentence. The evaluator has no compile step, so the
// same sentence has to be raised where the signal runs out of places to go --
// the end of the program, which is the boundary this row added, next to the end
// of a function body, which M26-EVL-023 added. Before it, `let n = 1; break;
// n;` answered 1.
func TestASignalWithNoLoopLeftIsRefusedInTheCompilersWords(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"break at the top level", `let n = 1; break; n;`},
		{"continue at the top level", `let n = 1; continue; n;`},
		{"break in a while condition with no enclosing loop",
			`let i = 0; let n = 0; while (if (i == 2) { break; } else { true }) { i = i + 1; n = n + 1; } n;`},
		{"break in a for condition with no enclosing loop",
			`let n = 0; for (let i = 0; if (i == 2) { break; } else { i < 5 }; i = i + 1) { n = n + 1; } n;`},
		{"break in a for-in iterable with no enclosing loop",
			`let n = 0; for (v in (if (n == 0) { break; } else { [1,2] })) { n = n + 1; } n;`},
		{"break in a for init with no enclosing loop",
			`let n = 0; for (let i = (if (n == 0) { break; } else { 0 }); i < 3; i = i + 1) { n = n + 1; } n;`},
	} {
		t.Run(c.name, func(t *testing.T) {
			compiled, refused := compilerComplaint(c.src)
			if !refused {
				t.Fatalf("the compiler accepted a signal with no loop to act on\n  %s", c.src)
			}

			evaluated := evalViaEvaluator(c.src)
			raised, isError := evaluated.(*object.Error)
			if !isError {
				t.Fatalf("the evaluator answered %s where the compiler refuses the same program\n  %s",
					normalize(evaluated), c.src)
			}
			if raised.Message != compiled {
				t.Errorf("the engines refuse it in different words:\n  compiler:  %s\n  evaluator: %s",
					compiled, raised.Message)
			}
			if !strings.Contains(raised.Message, "outside of for loop") {
				t.Errorf("refused for some other reason: %q", raised.Message)
			}
		})
	}
}

// TestContinueInALoopStepIsRefusedRatherThanGivenAMeaning records a decision,
// which is why it is a test rather than a comment.
//
// `for (let i = 0; i < 5; i = i + (if (i == 2) { continue; } else { 1 }))` has
// no terminating reading. Going on to the condition skips the advance; re-running
// the post section, which is where the compiler's continue jumps, reaches the
// same continue again. Both loop for ever. The evaluator was measured doing the
// first, as a hang, so the shape is refused and sema owns the sentence.
//
// The compiler still accepts it and answers a boolean for a program whose value
// is an integer -- its half of M26-CMP-003. When that lands this test gains the
// compiler assertion; until then it asserts the one engine that has an answer.
func TestContinueInALoopStepIsRefusedRatherThanGivenAMeaning(t *testing.T) {
	src := `let n = 0; for (let i = 0; i < 5; i = i + (if (i == 2) { continue; } else { 1 })) { n = n + 1; } n;`

	done := make(chan object.Object, 1)
	go func() { done <- evalViaEvaluator(src) }()

	var answered object.Object
	select {
	case answered = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the evaluator did not terminate on a continue in a for loop's post section; " +
			"the shape has to be refused, because no reading of it ends")
	}

	raised, isError := answered.(*object.Error)
	if !isError {
		t.Fatalf("answered %s, want a refusal", normalize(answered))
	}
	if want := sema.ContinueInLoopStepRefusal().Message; raised.Message != want {
		t.Errorf("refused in different words than sema owns:\n  got:  %s\n  want: %s", raised.Message, want)
	}

	// A break in the same position is NOT refused: it has exactly one meaning
	// and both engines agree on it. The refusal has to be this narrow, or it
	// would be a false flag on working code.
	sound := `let n = 0; for (let i = 0; i < 5; i = i + (if (i == 2) { break; } else { 1 })) { n = n + 1; } n;`
	if got := normalize(evalViaEvaluator(sound)); got != "INTEGER(3)" {
		t.Errorf("a break in a post section answered %s, want INTEGER(3)", got)
	}
}
