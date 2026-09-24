// Command covreport turns Go coverage profiles into the per-package table the
// release review's test-coverage report is written from.
//
//	go run ./cmd/covreport -unit unit.out -cross cross.out [-o coverage.md]
//
// -unit is a profile from `go test ./... -coverprofile`, where each package is
// credited only for its own tests. -cross is one from `-coverpkg=./...`, where
// a package is credited for every test in the module that runs its code -- the
// number that matters for builtin/, which the parity suite and the examples
// exercise from outside. scripts/coverage.{ps1,sh} produce both and call this.
//
// It is a measurement, not a gate: nothing here fails on a low number.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// modulePrefix is stripped from profile paths so rows name repository
// directories.
const modulePrefix = "mutant/"

type counts struct{ covered, total int }

func main() {
	unit := flag.String("unit", "", "profile from go test -coverprofile")
	cross := flag.String("cross", "", "profile from go test -coverpkg=./... -coverprofile")
	out := flag.String("o", "", "also write the table to this file")
	root := flag.String("root", ".", "repository root, for line counts")
	flag.Parse()
	if *unit == "" || *cross == "" {
		fmt.Fprintln(os.Stderr, "covreport: -unit and -cross are both required")
		os.Exit(2)
	}

	unitCounts, err := readProfile(*unit)
	if err != nil {
		fail(err)
	}
	crossCounts, err := readProfile(*cross)
	if err != nil {
		fail(err)
	}
	loc, testLOC, err := lineCounts(*root)
	if err != nil {
		fail(err)
	}

	table := render(unitCounts, crossCounts, loc, testLOC)
	fmt.Print(table)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(table), 0o644); err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "covreport: %v\n", err)
	os.Exit(1)
}

// readProfile sums statements per package. A profile written for many
// packages repeats a block once per test binary that instrumented it, so
// blocks are keyed by position and a block counts as covered if any binary
// ran it.
func readProfile(path string) (map[string]counts, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type block struct {
		pkg   string
		stmts int
		hit   bool
	}
	blocks := map[string]*block{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		// file.go:startLine.startCol,endLine.endCol numStmts count
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s: malformed line %q", path, line)
		}
		stmts, err1 := strconv.Atoi(fields[1])
		hits, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%s: malformed line %q", path, line)
		}
		file, _, _ := strings.Cut(fields[0], ":")
		b := blocks[fields[0]]
		if b == nil {
			b = &block{pkg: strings.TrimPrefix(filepath.ToSlash(filepath.Dir(file)), modulePrefix), stmts: stmts}
			if b.pkg == strings.TrimSuffix(modulePrefix, "/") {
				b.pkg = "."
			}
			blocks[fields[0]] = b
		}
		b.hit = b.hit || hits > 0
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	out := map[string]counts{}
	for _, b := range blocks {
		c := out[b.pkg]
		c.total += b.stmts
		if b.hit {
			c.covered += b.stmts
		}
		out[b.pkg] = c
	}
	return out, nil
}

// lineCounts counts lines of non-test and test Go source per directory.
func lineCounts(root string) (map[string]int, map[string]int, error) {
	loc, testLOC := map[string]int{}, map[string]int{}
	skip := map[string]bool{".git": true, ".codegraph": true, "node_modules": true, "dist": true, "testdata": true}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		pkg := filepath.ToSlash(rel)
		lines := strings.Count(string(data), "\n")
		if strings.HasSuffix(d.Name(), "_test.go") {
			testLOC[pkg] += lines
		} else {
			loc[pkg] += lines
		}
		return nil
	})
	return loc, testLOC, err
}

func percent(c counts) string {
	if c.total == 0 {
		return "--"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(c.covered)/float64(c.total))
}

func render(unit, cross map[string]counts, loc, testLOC map[string]int) string {
	pkgs := map[string]bool{}
	for p := range cross {
		pkgs[p] = true
	}
	for p := range unit {
		pkgs[p] = true
	}
	names := make([]string, 0, len(pkgs))
	for p := range pkgs {
		names = append(names, p)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("| Package | Lines | Test lines | Unit coverage | Cross-package coverage |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: |\n")
	var unitTotal, crossTotal counts
	var linesTotal, testTotal int
	for _, p := range names {
		fmt.Fprintf(&b, "| `%s` | %d | %d | %s | %s |\n", p, loc[p], testLOC[p], percent(unit[p]), percent(cross[p]))
		unitTotal.covered += unit[p].covered
		unitTotal.total += unit[p].total
		crossTotal.covered += cross[p].covered
		crossTotal.total += cross[p].total
		linesTotal += loc[p]
		testTotal += testLOC[p]
	}
	fmt.Fprintf(&b, "| **all** | %d | %d | %s | %s |\n", linesTotal, testTotal, percent(unitTotal), percent(crossTotal))
	return b.String()
}
