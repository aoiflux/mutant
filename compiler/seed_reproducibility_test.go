package compiler

// `--seed` exists so a build can be reproduced. It was not enough to reproduce
// one: the seed reached the polymorphic engine and nothing else, while the
// optional OpChkDbg/OpChkSnd checks were placed from crypto/rand. Two `mutant
// gen` runs of the same source with the same seed produced instruction streams
// of different lengths -- at every mutation level, including 0, where the
// polymorphic engine does not run at all.
//
// The .mu *file* still differs every build and must: it is sealed with AES-GCM
// under a fresh salt and nonce, and repeating a GCM nonce under one key is a
// break. What the seed reproduces is the bytecode inside it.

import (
	"bytes"
	"testing"
)

const seededSource = `
let classify = fn(n) {
	if (n > 10) { return "big"; };
	if (n > 5) { return "medium"; };
	return "small";
};

let total = 0;
for (let i = 0; i < 20; i = i + 1) {
	if (i % 3 == 0) { total = total + i; };
};

let labels = [];
for (let i = 0; i < 12; i = i + 1) {
	labels = push(labels, classify(i));
};

putln(total, labels);
`

// compileSeeded mirrors what generator.compile does for a real `mutant gen`:
// security checks on, both the injection and the engine seeded from --seed.
func compileSeeded(t *testing.T, level int, seed int64, seedTheChecks bool) *ByteCode {
	t.Helper()

	comp := New()
	comp.EnableSecurityOpcodeInjection()
	if seedTheChecks {
		comp.SetSecurityCheckSeed(seed)
	}
	if level > 0 {
		comp.EnablePolymorphismWithSeed(level, seed)
	}
	if err := comp.Compile(parse(seededSource)); err != nil {
		t.Fatalf("compile at level %d: %s", level, err)
	}
	return comp.ByteCode()
}

func TestTheSameSeedProducesTheSameBytecodeAtEveryLevel(t *testing.T) {
	for level := 0; level <= 10; level++ {
		first := compileSeeded(t, level, 424242, true)
		again := compileSeeded(t, level, 424242, true)

		if !bytes.Equal(first.Instructions, again.Instructions) {
			t.Fatalf("level %d: two builds with the same seed differ (%d vs %d bytes)",
				level, len(first.Instructions), len(again.Instructions))
		}
		if len(first.Constants) != len(again.Constants) {
			t.Fatalf("level %d: constant pools differ in size: %d vs %d",
				level, len(first.Constants), len(again.Constants))
		}
	}
}

func TestADifferentSeedProducesDifferentBytecode(t *testing.T) {
	// Level 0 too: the security checks are placed at every level, so the seed has
	// to change the program even when no mutation stage runs.
	for _, level := range []int{0, 5, 10} {
		one := compileSeeded(t, level, 424242, true)
		two := compileSeeded(t, level, 999983, true)

		if bytes.Equal(one.Instructions, two.Instructions) {
			t.Fatalf("level %d: two different seeds produced identical bytecode, so the seed is not reaching it", level)
		}
	}
}

// The load-bearing half. Without the injection seeded, the same seed does not
// reproduce a build -- which is the defect, and it is invisible unless a test
// compiles twice and compares.
func TestUnseededSecurityCheckPlacementIsWhatBrokeReproducibility(t *testing.T) {
	// Repeat: the placement is a 1-in-3 chance per site, so two runs can agree by
	// luck. Over this many builds of a program with this many sites they will not.
	differed := false
	for i := 0; i < 8 && !differed; i++ {
		first := compileSeeded(t, 0, 424242, false)
		again := compileSeeded(t, 0, 424242, false)
		if !bytes.Equal(first.Instructions, again.Instructions) {
			differed = true
		}
	}

	if !differed {
		t.Fatal("unseeded check placement produced identical bytecode eight times running; " +
			"either the placement is no longer random or this test no longer exercises it")
	}
}

// A build with no --seed must still differ every time: that is the whole point of
// randomising where the checks land.
func TestNoSeedStillVariesBetweenBuilds(t *testing.T) {
	differed := false
	for i := 0; i < 8 && !differed; i++ {
		comp1, comp2 := New(), New()
		comp1.EnableSecurityOpcodeInjection()
		comp2.EnableSecurityOpcodeInjection()
		if err := comp1.Compile(parse(seededSource)); err != nil {
			t.Fatalf("compile: %s", err)
		}
		if err := comp2.Compile(parse(seededSource)); err != nil {
			t.Fatalf("compile: %s", err)
		}
		if !bytes.Equal(comp1.ByteCode().Instructions, comp2.ByteCode().Instructions) {
			differed = true
		}
	}

	if !differed {
		t.Fatal("builds with no seed came out identical eight times running; check placement is meant to vary")
	}
}
