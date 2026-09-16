package parity

import (
	"testing"

	"mutant/compiler"
	"mutant/lexer"
	"mutant/parser"
)

// Assignment to a captured variable is the defect L-10 was opened for, and this
// file is the part of the fix that stops the next one of its class.
//
// The compiler used to branch on two of SymbolScope's five values at its three
// assignment sites, so a write to a free variable was emitted as OpSetLocal
// against the free index -- a position in the closure's capture list, not a
// frame slot. Writing free 0 landed on local 0, which is usually the first
// parameter. `fn(x) { let acc = 0; let inner = fn(p){ acc = 7; return p; };
// return inner(x); }` called with 42 answered 7: silent argument corruption,
// with no diagnostic from any stage.
//
// A captured local now lives in an object.Cell that the frame slot and every
// closure over it point at, so a write through any of them is a write all of
// them see -- which is what object.Environment.Update has always done in the
// tree-walking evaluator.
//
// Every case carries the answer it must give, not only the demand that the two
// engines agree. Agreement alone would have been satisfied by both engines being
// wrong in the same way, and the whole reason this defect was findable is that
// one engine was right.
func TestCapturedVariableAssignmentParity(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			// Row A. The natural accumulator over a callback, and the shape that
			// started this: the write reached local 0 of the callback's own
			// frame, so acc stayed 0 forever.
			"accumulating over a callback",
			`let probe = fn() {
  let acc = 0;
  each([1, 2, 3], fn(x) { acc = acc + x; });
  return acc;
};
probe()`,
			"INTEGER(6)",
		},
		{
			// Row B, the loudest one. The answer was 7 -- not a dropped write but
			// the argument itself, overwritten.
			"the write used to land on a parameter",
			`let probe = fn(x) {
  let acc = 0;
  let inner = fn(p) { acc = 7; return p; };
  return inner(x);
};
probe(42)`,
			"INTEGER(42)",
		},
		{
			// Row F. Two frees over two parameters: the free index is positional,
			// so both arguments went. This returned [777, 888].
			"two captures used to corrupt two parameters",
			`let probe = fn(a, b) {
  let one = 0;
  let two = 0;
  let inner = fn() { one = 777; two = 888; return 0; };
  inner();
  return [a, b];
};
probe(10, 20)`,
			"ARRAY([10, 20])",
		},
		{
			// Row G. Never an integer-only defect; the type of the value written
			// had nothing to do with it.
			"a captured string",
			`let probe = fn() {
  let s = "a";
  each([1], fn(x) { s = "b"; });
  return s;
};
probe()`,
			`STRING("b")`,
		},
		{
			// Row H. The capture is itself a free variable in the middle
			// function, which is the case a fix that only understood one level
			// would miss: the middle function has to pass the owner's cell along
			// rather than box a second one.
			"captured through two levels",
			`let probe = fn() {
  let acc = 0;
  let mid = fn() {
    let inner = fn() { acc = 5; return 0; };
    inner();
    return 0;
  };
  mid();
  return acc;
};
probe()`,
			"INTEGER(5)",
		},
		{
			// The reason a by-value Free array with an OpSetFree bolted on was
			// rejected rather than deferred: it would have fixed the corruption
			// and left this at 0, because the closure would accumulate into its
			// own private copy. A quiet wrong number is worse than a loud one.
			"the enclosing frame sees the write",
			`let probe = fn() {
  let n = 0;
  let bump = fn() { n = n + 1; };
  bump();
  bump();
  return n;
};
probe()`,
			"INTEGER(2)",
		},
		{
			// Two closures over one variable. The same by-value fix would have
			// left these two disagreeing about n.
			"two closures share one variable",
			`let probe = fn() {
  let n = 0;
  let inc = fn() { n = n + 1; };
  let get = fn() { return n; };
  inc();
  inc();
  return get();
};
probe()`,
			"INTEGER(2)",
		},
		{
			// A captured parameter, which the design gets for free: the frame's
			// slots are boxed after the arguments are already in them, so slot i
			// is wrapped around argument i with no special case.
			"a captured parameter is written through the same cell",
			`let probe = fn(x) {
  let double = fn() { x = x * 2; };
  double();
  return x;
};
probe(21)`,
			"INTEGER(42)",
		},
		{
			// The closure that outlives the frame that made it. This is the shape
			// every language's closure chapter opens with, and Mutant could not
			// express it.
			"a counter that survives its frame",
			`let counter = fn() {
  let n = 0;
  return fn() { n = n + 1; return n; };
};
let c = counter();
c();
c();
c()`,
			"INTEGER(3)",
		},
		{
			// One cell per frame, so two calls to the maker do not share. The
			// opposite mistake to the one being fixed, and just as findable here.
			"two counters do not share a cell",
			`let counter = fn() {
  let n = 0;
  return fn() { n = n + 1; return n; };
};
let a = counter();
let b = counter();
a();
a();
[a(), b()]`,
			"ARRAY([3, 1])",
		},
		{
			// Index write-back through a captured container. It resolves the
			// container the same way the plain identifier path does, so it had
			// the same defect and needed the same fix.
			"writing through an index into a captured array",
			`let probe = fn() {
  let arr = [1, 2, 3];
  each([1], fn(x) { arr[0] = 9; });
  return arr;
};
probe()`,
			"ARRAY([9, 2, 3])",
		},
		{
			// And the hash form of the same path.
			"writing through a key into a captured hash",
			`let probe = fn() {
  let h = {"a": 1};
  each([1], fn(x) { h["a"] = 2; });
  return h["a"];
};
probe()`,
			"INTEGER(2)",
		},
		{
			// Field write-back through a captured struct: the third of the three
			// assignment sites that shared the two-way branch.
			"writing through a field on a captured struct",
			`struct Point { x; y; };
let probe = fn() {
  let p = Point { x: 1, y: 2 };
  each([1], fn(n) { p.x = 9; });
  return p.x;
};
probe()`,
			"INTEGER(9)",
		},
		{
			// Compound assignment desugars to the same store, so it reaches the
			// same site. Worth its own row because the desugaring happens in the
			// parser and could have produced a shape the boxing pass missed.
			"compound assignment through a capture",
			`let probe = fn() {
  let acc = 1;
  let bump = fn() { acc += 5; };
  bump();
  return acc;
};
probe()`,
			"INTEGER(6)",
		},
		{
			// Including the bitwise compound forms, which are newer than the
			// defect and reach the store the same way.
			"bitwise compound assignment through a capture",
			`let probe = fn() {
  let flags = 1;
  let set = fn() { flags |= 4; };
  set();
  return flags;
};
probe()`,
			"INTEGER(5)",
		},
		{
			// Postfix increment is a third spelling of the same store.
			"increment through a capture",
			`let probe = fn() {
  let n = 0;
  let bump = fn() { n++; };
  bump();
  bump();
  return n;
};
probe()`,
			"INTEGER(2)",
		},
		{
			// A capture that is only ever read was never broken, and has to stay
			// that way: boxing a slot changes how every access to it is compiled,
			// not only the writes.
			"a captured variable that is only read",
			`let probe = fn() {
  let base = 10;
  let add = fn(x) { return x + base; };
  return add(1);
};
probe()`,
			"INTEGER(11)",
		},
		{
			// Boxed and unboxed locals in one frame. `acc` is captured and `step`
			// is not, so exactly one of the two slots may be boxed -- boxing both
			// would work and cost, boxing neither is the bug.
			"a boxed and an unboxed local in one frame",
			`let probe = fn() {
  let acc = 0;
  let step = 3;
  let bump = fn() { acc = acc + step; };
  bump();
  bump();
  return acc + step;
};
probe()`,
			"INTEGER(9)",
		},
		{
			// A for loop inside the capturing frame. Both engines scope the loop
			// once rather than once per iteration -- the evaluator makes a single
			// loopEnv, the VM a single cell -- so the closure sees the final
			// value. Pinned because it is the shape where languages disagree with
			// each other, and the two engines here must not.
			"a closure made inside a loop sees the final value",
			`let probe = fn() {
  let seen = 0;
  let f = fn() { return seen; };
  for (let i = 0; i < 3; i = i + 1) { seen = seen + i; }
  return f();
};
probe()`,
			"INTEGER(3)",
		},
		{
			// Recursion alongside a capture: the function's own name is a
			// separate scope from the captured local, and it is captured by
			// value because it is not storage.
			"a recursive closure that also captures",
			`let probe = fn() {
  let calls = 0;
  let down = fn(n) {
    calls = calls + 1;
    if (n <= 0) { return calls; }
    return down(n - 1);
  };
  return down(3);
};
probe()`,
			"INTEGER(4)",
		},
		{
			// A local that shadows a global of the same name. The capture must
			// take the local, and the global must be left alone.
			"a capture shadowing a global",
			`let acc = 100;
let probe = fn() {
  let acc = 0;
  let bump = fn() { acc = acc + 1; };
  bump();
  return acc;
};
[probe(), acc]`,
			"ARRAY([1, 100])",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evalRes := normalize(evalViaEvaluator(tc.src))

			vmObj, vmErr := evalViaVM(t, tc.src)
			vmRes := normalize(vmObj)
			if vmErr != nil {
				vmRes = "ERROR"
			}

			if evalRes != vmRes {
				t.Errorf("engine divergence: evaluator=%s vm=%s", evalRes, vmRes)
			}
			if vmRes != tc.want {
				t.Errorf("wrong answer: got %s, want %s", vmRes, tc.want)
			}
		})
	}
}

// The two things that are still refused by the compiler, and must stay refused:
// neither is storage, so neither is a meaningful assignment. Both used to
// compile -- the builtin's registry ordinal and the closure's own marker were
// written as though they were frame slots -- and boxing captures does not make
// either one writable.
//
// The two engines do not agree on either of them, and that is recorded here
// rather than asserted away. The compiler resolves both names to scopes that are
// not storage and refuses; the evaluator has neither concept, so `len = 5`
// creates a binding that shadows the builtin and `f = 1` rebinds the global f,
// and both calls return normally. Which engine is right is a language question
// -- may a name be assigned before it is bound, and may a function rebind its
// own name mid-call -- and not one this defect gets to settle. So both answers
// are pinned, and a change to either engine trips this test.
func TestAssigningToSomethingThatIsNotStorageStaysRefusedByTheCompiler(t *testing.T) {
	cases := []struct {
		name string
		src  string
		// evaluatorAnswer is what the tree-walking engine returns. It is a
		// value in every row below, which is exactly the divergence being
		// pinned; "ERROR" here would mean the two engines had converged.
		evaluatorAnswer string
	}{
		{
			// Row J. The VM returned the builtin's Inspect string rather than 5,
			// having written the registry ordinal into a frame slot. The
			// evaluator answers 5: Update finds no binding named len, so Set
			// creates one, and the new binding shadows the builtin for the rest
			// of the call.
			"a builtin",
			`let probe = fn() { len = 5; return len; }; probe()`,
			"INTEGER(5)",
		},
		{
			// Row I. probe(42) returned 1, because FunctionScope's index is 0 and
			// that is parameter 0's slot. The evaluator answers 42 and leaves f
			// bound to 1 -- an ordinary rebinding of a global, in an engine with
			// no notion of a function's own name.
			"the function's own name",
			`let f = fn(x) { f = 1; return x; }; f(42)`,
			"INTEGER(42)",
		},
		{
			// The same name reached through a capture. It is a free variable at
			// the point of assignment and so looks exactly like the writes that
			// now succeed -- but it is captured by value with OpCurrentClosure
			// and has no cell behind it, which is why the compiler singles it out
			// instead of letting it fail at run time as a type complaint about a
			// closure.
			"the enclosing function's own name, captured",
			`let f = fn(x) { let g = fn() { f = 1; return 0; }; g(); return x; }; f(42)`,
			"INTEGER(42)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := compiler.New().Compile(parser.New(lexer.New(tc.src)).ParseProgram()); err == nil {
				t.Error("the compiler accepted a write to something that is not storage")
			}
			if got := normalize(evalViaEvaluator(tc.src)); got != tc.evaluatorAnswer {
				t.Errorf("evaluator answered %s, want %s", got, tc.evaluatorAnswer)
			}
		})
	}
}
