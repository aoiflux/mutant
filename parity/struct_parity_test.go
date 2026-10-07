package parity

import (
	"sort"
	"testing"
)

// What a struct is, asked of both engines.
//
// Struct.Inspect used to range a Go map, so the two engines did not disagree in
// any fixed way: each one disagreed with itself, call to call. That is a shape
// one run compared with one run cannot see, so every input here is run
// repeatedly through each engine, and the whole set of answers has to be one
// answer before the two are compared with each other.
//
// It matters beyond printing, in both directions. Inspect was the identity `==`
// compared, so until it had an order these inputs were coin tosses in both
// engines. And the evaluator is what computes `unquote(...)` during macro
// expansion, so a struct compared inside a macro and the same comparison written
// inline were two different questions.

const structParityRepeats = 20

var structParityInputs = []string{
	// Rendering: the declaration decides the order, not the literal.
	"struct P { b; a; }; P { a: 1, b: 2 }",
	"struct P { b; a; }; P { b: 2, a: 1 }",
	"struct Q { a; b; c; d; e; f; }; Q { f: 6, e: 5, d: 4, c: 3, b: 2, a: 1 }",
	"struct Inner { z; y; }; struct Outer { i; n; }; Outer { n: 3, i: Inner { y: 1, z: 2 } }",
	"struct H { xs; m; }; H { xs: [1, 2, 3], m: {\"k\": 1} }",
	"struct P { b; a; }; [P { a: 1, b: 2 }]",

	// Equality.
	"struct P { b; a; }; P { a: 1, b: 2 } == P { a: 1, b: 2 }",
	"struct P { b; a; }; P { a: 1, b: 2 } != P { a: 1, b: 2 }",
	"struct P { b; a; }; P { a: 1, b: 2 } == P { a: 1, b: 9 }",
	"struct P { b; a; }; P { a: 1, b: 2 } != P { a: 1, b: 9 }",
	"struct P { b; a; }; let p = P { a: 1, b: 2 }; p == p",
	"struct Q { a; b; c; d; e; f; }; Q { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6 } == Q { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6 }",

	// A struct is never equal to a value of another type, whatever it renders
	// as. The first of these was true in both engines.
	"struct One { a; }; One { a: 1 } == \"One { a: 1 }\"",
	"struct A1 { a; }; struct B1 { a; }; A1 { a: 1 } == B1 { a: 1 }",
	"struct P { b; a; }; P { a: 1, b: 2 } == 1",
	"struct P { b; a; }; P { a: 1, b: 2 } != 1",

	// Through a container and through a field write.
	"struct Inner { v; }; struct Outer { i; }; Outer { i: Inner { v: 1 } } == Outer { i: Inner { v: 1 } }",
	"struct P { b; a; }; [P { a: 1, b: 2 }] == [P { a: 1, b: 2 }]",
	"struct P { b; a; }; let p = P { a: 1, b: 2 }; p.a = 9; p",
	"struct P { b; a; }; let p = P { a: 1, b: 2 }; let q = p; q == p",
}

func TestStructsMeanTheSameThingInBothEngines(t *testing.T) {
	for _, input := range structParityInputs {
		evalAnswers := map[string]struct{}{}
		vmAnswers := map[string]struct{}{}

		for i := 0; i < structParityRepeats; i++ {
			evalAnswers[normalize(evalViaEvaluator(input))] = struct{}{}

			vmObj, vmErr := evalViaVM(t, input)
			answer := normalize(vmObj)
			if vmErr != nil {
				answer = "ERROR"
			}
			vmAnswers[answer] = struct{}{}
		}

		if len(evalAnswers) != 1 {
			t.Errorf("the evaluator gave %d answers over %d runs of %q: %v",
				len(evalAnswers), structParityRepeats, input, answerSet(evalAnswers))
			continue
		}
		if len(vmAnswers) != 1 {
			t.Errorf("the VM gave %d answers over %d runs of %q: %v",
				len(vmAnswers), structParityRepeats, input, answerSet(vmAnswers))
			continue
		}

		evalRes, vmRes := answerSet(evalAnswers)[0], answerSet(vmAnswers)[0]
		if evalRes != vmRes {
			t.Errorf("the engines disagree for %q:\n evaluator: %s\n vm:        %s", input, evalRes, vmRes)
		}
	}
}

// answerSet reads a set of answers back in a definite order, so a failure
// message naming three of them names them the same way twice.
func answerSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for answer := range set {
		out = append(out, answer)
	}
	sort.Strings(out)
	return out
}
