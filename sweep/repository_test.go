package sweep

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repositoryRoot is where this package sits relative to the tree it polices.
const repositoryRoot = ".."

// Every Mutant program in the repository has to agree with its own sweep marker.
//
// This is the test that makes the convention worth having. A marker is a claim
// about how a program behaves -- it serves forever, or it needs a connection
// handed to it -- and a claim nothing checks is one that quietly stops being
// true. Checking it against the program's own calls means a new server example
// cannot be added unmarked (a sweep would report it as a hang), and a marker
// left behind after a rewrite cannot keep a runnable example excluded.
func TestEveryProgramAgreesWithItsSweepMarker(t *testing.T) {
	programs := mutantPrograms(t)
	if len(programs) == 0 {
		t.Fatal("found no .mut files to check; the walk is looking in the wrong place")
	}

	for _, path := range programs {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %s", path, err)
		}
		if err := Check(string(source)); err != nil {
			t.Errorf("%s:\n%s", filepath.ToSlash(path), err)
		}
	}
}

// The counts are pinned so that marking a file, or removing a marker, is a
// visible decision rather than a side effect. Failing here is not a defect --
// it means update the number and say why in the commit.
func TestTheMarkedProgramsAreTheOnesWeExpect(t *testing.T) {
	counts := map[Mode]int{}

	for _, path := range mutantPrograms(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %s", path, err)
		}
		marker, err := ParseMarker(string(source))
		if err != nil {
			t.Fatalf("%s: %s", filepath.ToSlash(path), err)
		}
		if marker.Explicit {
			counts[marker.Mode]++
		}
	}

	want := map[Mode]int{
		ModeServer:       5,
		ModeServeHandler: 2,
		ModeRun:          1,
	}
	for _, mode := range Modes() {
		if counts[mode] != want[mode] {
			t.Errorf("%d programs marked %q, expected %d", counts[mode], mode, want[mode])
		}
	}
}

// Every reason has to say something. A marker whose reason restates its mode
// tells a reader nothing they did not already have.
func TestEveryReasonSaysSomething(t *testing.T) {
	for _, path := range mutantPrograms(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %s", path, err)
		}
		marker, err := ParseMarker(string(source))
		if err != nil || !marker.Explicit {
			continue
		}
		if len(strings.Fields(marker.Reason)) < 3 {
			t.Errorf("%s: the reason %q is too short to tell anyone anything",
				filepath.ToSlash(path), marker.Reason)
		}
	}
}

func mutantPrograms(t *testing.T) []string {
	t.Helper()

	programs := []string{}
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "node_modules" || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".mut") {
			programs = append(programs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %s", repositoryRoot, err)
	}
	return programs
}
