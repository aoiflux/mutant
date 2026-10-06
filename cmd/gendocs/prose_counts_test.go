package main

import "testing"

// The generated documents cannot drift: gendocs writes CAPABILITY_REFERENCE.md,
// the editor grammar and the limits reference, and a test fails when any of the
// three is behind. The prose around them had no such check, and it drifted the
// same way the grammar did -- four documents still telling a reader the
// standard library held 459 builtins across 34 categories, a count three
// releases old, found 2026-09-16 while registering the sigma_* family.
//
// It is the same failure as ED-1 in a different file type: a hand-written claim
// about the registry, with nothing that fails when the registry moves. So it
// gets the same answer.
//
// The checks themselves are in consistency.go, because `gendocs -check` runs
// them too, and a tree the release gate calls consistent has to be the same
// tree the suite calls consistent. These tests are the other caller. What they
// add is a failure at the line of the claim for somebody running the suite
// rather than the generator.

func TestProseCountsMatchTheRegistry(t *testing.T) {
	check, err := checkProseCounts(repoRoot)
	if err != nil {
		t.Fatalf("checking prose counts: %v", err)
	}
	reportDocCheck(t, check)
}

func TestProseExampleCountsMatchTheTree(t *testing.T) {
	check, err := checkProseExampleCounts(repoRoot)
	if err != nil {
		t.Fatalf("checking example counts: %v", err)
	}
	reportDocCheck(t, check)
}

func TestCategoryIndexMatchesTheRegistry(t *testing.T) {
	check, err := checkCategoryIndex(repoRoot)
	if err != nil {
		t.Fatalf("checking the category index: %v", err)
	}
	reportDocCheck(t, check)
}

// reportDocCheck fails the test once per problem, at the place a reader would
// find it, and fatally when the check examined less than it must. The second
// half is not ceremony: a scanner that has stopped matching anything passes
// every document ever written, and reports a clean tree while doing it.
func reportDocCheck(t *testing.T, check docCheck) {
	t.Helper()
	if shortfall := check.shortfall(); shortfall != "" {
		t.Fatal(shortfall)
	}
	for _, problem := range check.problems {
		t.Error(problem)
	}
}
