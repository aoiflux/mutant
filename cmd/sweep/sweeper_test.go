package main

import (
	"strings"
	"testing"

	"mutant/sweep"
)

// scriptedRun is one run the sweeper is expected to ask for, and what that run
// prints.
type scriptedRun struct {
	level  int
	output string
}

// scripted answers the sweeper's runs in order and fails the test if it asks
// for a level out of turn or for more runs than the script holds.
func scripted(t *testing.T, runs ...scriptedRun) (func(string, sweep.Marker, int) (string, *result), func()) {
	t.Helper()
	next := 0
	run := func(file string, marker sweep.Marker, level int) (string, *result) {
		if next >= len(runs) {
			t.Fatalf("run %d at mutation %d was not expected", next+1, level)
		}
		want := runs[next]
		next++
		if level != want.level {
			t.Fatalf("run %d was at mutation %d, expected %d", next, level, want.level)
		}
		return want.output, nil
	}
	done := func() {
		t.Helper()
		if next != len(runs) {
			t.Fatalf("the sweeper made %d runs, expected %d", next, len(runs))
		}
	}
	return run, done
}

// A difference between two levels is only a mutation defect if it holds when
// both levels are run again. Output that carries the time agreed with itself
// on the back-to-back probe and then differed by the next level, which the sweep
// reported as the engine changing what a program prints: fs_example (a
// modification time crossing a second) and security_quickcheck (a microsecond
// timer), each on some runs and not others.
func TestADifferenceBetweenLevelsIsConfirmedBeforeItIsAFailure(t *testing.T) {
	cases := []struct {
		name     string
		runs     []scriptedRun
		fail     bool
		noteHas  string
		failNote string
	}{
		{
			name:    "identical output at every level passes",
			runs:    []scriptedRun{{0, "x"}, {0, "x"}, {5, "x"}, {10, "x"}},
			noteHas: "identical across 3 levels",
		},
		{
			name: "a clock that ticked between levels is output that varies",
			runs: []scriptedRun{
				{0, "modified: 11:46:02"}, {0, "modified: 11:46:02"}, {5, "modified: 11:46:03"},
				{0, "modified: 11:46:03"}, // the first level no longer agrees with itself
				{10, "modified: 11:46:04"},
			},
			noteHas: "output varies between runs so it was not compared",
		},
		{
			name: "a timer that repeats at the first level but not at the other varies",
			runs: []scriptedRun{
				{0, "loop_us=47"}, {0, "loop_us=47"}, {5, "loop_us=49"},
				{0, "loop_us=47"}, {5, "loop_us=48"},
				{10, "loop_us=51"},
			},
			noteHas: "output varies between runs so it was not compared",
		},
		{
			name: "a difference that repeats is a mutation defect",
			runs: []scriptedRun{
				{0, "ip=6"}, {0, "ip=6"}, {5, "ip=6"}, {10, "ip=12"},
				{0, "ip=6"}, {10, "ip=12"},
			},
			fail:     true,
			failNote: "mutation 10 differs from mutation 0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run, done := scripted(t, tc.runs...)
			s := &sweeper{opts: options{levels: []int{0, 5, 10}}, run: run}

			res := s.runAcrossLevels("examples/x.mut", sweep.Marker{Mode: sweep.ModeRun})
			done()

			if tc.fail {
				if res.status != statusFail || res.note != tc.failNote {
					t.Fatalf("got %v, want a failure noting %q", res, tc.failNote)
				}
				return
			}
			if res.status != statusOK {
				t.Fatalf("got a failure, want a pass: %v", res)
			}
			if !strings.Contains(res.note, tc.noteHas) {
				t.Fatalf("note %q does not say %q", res.note, tc.noteHas)
			}
		})
	}
}
