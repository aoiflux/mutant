package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The 2.6.0 review keeps one ledger of findings, one JSON object per line, so a
// finding is one line in a diff and every report is written from the same rows.
// These tests hold the ledger to its own rules; see the README beside it.
//
// The ledger is not in this repository, and must not be. It carries the
// unfixed findings of a security review, most of them with a reproduction,
// and this repository is public -- so it lives with the review's own tooling
// under plans/, which git ignores. These tests check it where it is present
// and skip on a clone that has not got it.

const (
	reviewDir    = "../../plans/review-2.6.0/ledger"
	reviewLedger = reviewDir + "/findings.jsonl"
)

type reviewFinding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Area           string   `json:"area"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	Priority       string   `json:"priority"`
	Status         string   `json:"status"`
	Verification   string   `json:"verification"`
	Embargoed      bool     `json:"embargoed"`
	AuditedCommit  string   `json:"audited_commit"`
	Location       string   `json:"location"`
	Claim          string   `json:"claim"`
	Evidence       string   `json:"evidence"`
	Repro          string   `json:"repro"`
	Impact         string   `json:"impact"`
	FixProposal    string   `json:"fix_proposal"`
	RegressionTest string   `json:"regression_test"`
	FixCommit      string   `json:"fix_commit"`
	DuplicateOf    string   `json:"duplicate_of"`
	Reporter       string   `json:"reporter"`
	Verifier       string   `json:"verifier"`
	Reports        []string `json:"reports"`
}

var (
	findingID    = regexp.MustCompile(`^M26-[A-Z0-9]+-\d{3}$`)
	findingCite  = regexp.MustCompile(`\bM26-[A-Z0-9]+-\d{3}\b`)
	commitHash   = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	findingEnums = map[string]map[string]bool{
		"category":     setOf("correctness", "reliability", "security", "docs", "debt", "perf", "test", "limit", "arch", "readability"),
		"severity":     setOf("S1", "S2", "S3", "S4", "S5"),
		"priority":     setOf("P0", "P1", "P2", "P3"),
		"status":       setOf("OPEN", "FIXED", "WONTFIX", "DUPLICATE"),
		"verification": setOf("CONFIRMED", "PLAUSIBLE", "REFUTED", "UNVERIFIED"),
	}
)

func setOf(values ...string) map[string]bool {
	m := map[string]bool{}
	for _, v := range values {
		m[v] = true
	}
	return m
}

func readReviewLedger(t *testing.T) []reviewFinding {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(reviewLedger))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("no ledger at %s: it is kept out of the repository, so this runs only where it is present", reviewLedger)
	}
	if err != nil {
		t.Fatalf("reading %s: %v", reviewLedger, err)
	}
	var out []reviewFinding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.DisallowUnknownFields()
		var f reviewFinding
		if err := decoder.Decode(&f); err != nil {
			t.Fatalf("%s:%d: %v", reviewLedger, n, err)
		}
		out = append(out, f)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestReviewLedgerIsWellFormed: ids are unique and well formed, every enum
// holds a value it can hold, and each status carries what that status claims.
func TestReviewLedgerIsWellFormed(t *testing.T) {
	findings := readReviewLedger(t)
	if len(findings) == 0 {
		t.Fatal("the review ledger is empty")
	}
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	seen := map[string]bool{}
	for _, f := range findings {
		where := f.ID
		if !findingID.MatchString(f.ID) {
			t.Errorf("%q is not an M26-<AREA>-<NNN> id", f.ID)
		}
		if seen[f.ID] {
			t.Errorf("%s appears twice", f.ID)
		}
		seen[f.ID] = true
		if area := strings.Split(f.ID, "-"); len(area) == 3 && area[1] != f.Area {
			t.Errorf("%s: area %q does not match the id", where, f.Area)
		}
		for field, value := range map[string]string{
			"category": f.Category, "severity": f.Severity, "priority": f.Priority,
			"status": f.Status, "verification": f.Verification,
		} {
			if !findingEnums[field][value] {
				t.Errorf("%s: %s %q is not one of the allowed values", where, field, value)
			}
		}
		if f.AuditedCommit != "" && !commitHash.MatchString(f.AuditedCommit) {
			t.Errorf("%s: audited_commit %q is not a commit hash", where, f.AuditedCommit)
		}
		if f.FixCommit != "" && !commitHash.MatchString(f.FixCommit) {
			t.Errorf("%s: fix_commit %q is not a commit hash", where, f.FixCommit)
		}

		// Embargo: an unfixed security finding says only that it exists.
		detail := f.Title + f.Location + f.Claim + f.Evidence + f.Repro + f.Impact + f.FixProposal
		if f.Category == "security" && f.Status != "FIXED" && f.Status != "WONTFIX" {
			if !f.Embargoed {
				t.Errorf("%s: an unfixed security finding must be embargoed", where)
			}
		}
		if f.Embargoed {
			if detail != "" {
				t.Errorf("%s is embargoed but carries detail; move it to the gitignored embargo file", where)
			}
			continue
		}
		if f.Title == "" || f.Claim == "" || f.Location == "" {
			t.Errorf("%s: title, claim and location are required", where)
		}
		if f.Verification == "CONFIRMED" && f.Repro == "" {
			t.Errorf("%s is CONFIRMED with no repro; say what failed as predicted", where)
		}
		switch f.Status {
		case "FIXED":
			if f.RegressionTest == "" {
				t.Errorf("%s is FIXED with no regression_test; name the test that failed before the fix", where)
			}
		case "DUPLICATE":
			if !ids[f.DuplicateOf] {
				t.Errorf("%s is a DUPLICATE of %q, which is not in the ledger", where, f.DuplicateOf)
			}
		}
	}
}

// TestReviewReportsCiteRealFindings: a report that cites an id the ledger does
// not hold is citing something nobody can look up.
func TestReviewReportsCiteRealFindings(t *testing.T) {
	ids := map[string]bool{}
	for _, f := range readReviewLedger(t) {
		ids[f.ID] = true
	}
	reports, err := filepath.Glob(filepath.Join(filepath.FromSlash(reviewDir), "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) == 0 {
		t.Fatalf("no reports under %s", reviewDir)
	}
	for _, report := range reports {
		data, err := os.ReadFile(report)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range findingCite.FindAllString(string(data), -1) {
			if !ids[id] {
				t.Errorf("%s cites %s, which is not in the ledger", filepath.Base(report), id)
			}
		}
	}
}
