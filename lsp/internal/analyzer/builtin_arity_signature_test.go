package analyzer

import (
	"testing"

	"mutant/builtin"
)

// TestCuratedAritiesMatchSignatures cross-checks the hand-verified
// builtinArities table against the argument shape implied by each builtin's
// signature string in builtin/metadata.go.
//
// The two are authored independently — the table by reading implementations,
// the signatures by documenting them — so agreement is real evidence and
// disagreement is a bug in one of them. This is the cheapest gate available on
// the arity table's accuracy, and it keeps the table honest as the metadata
// grows machine-readable parameter contracts.
func TestCuratedAritiesMatchSignatures(t *testing.T) {
	checked := 0

	for name, curated := range builtinArities {
		signature, _, _, ok := builtin.TeachingDoc(name)
		if !ok {
			t.Errorf("builtin %q is in builtinArities but has no teaching doc", name)
			continue
		}

		_, params, ok := builtin.ParseSignature(signature)
		if !ok {
			t.Errorf("builtin %q: signature %q does not parse", name, signature)
			continue
		}

		minArgs, maxArgs := builtin.SignatureArity(params)
		if curated.min != minArgs || curated.max != maxArgs {
			t.Errorf("builtin %q: curated arity {min:%d max:%d} disagrees with signature %q {min:%d max:%d}",
				name, curated.min, curated.max, signature, minArgs, maxArgs)
		}
		checked++
	}

	if checked == 0 {
		t.Fatal("no builtin arities were cross-checked; the table or the metadata lookup is broken")
	}
	t.Logf("cross-checked %d curated arities against their signatures", checked)
}
