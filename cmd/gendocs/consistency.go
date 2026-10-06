// Consistency checks for the documentation gendocs does not write.
//
// gendocs generates three artifacts, and -check compared exactly those three.
// The documents around them make the same claims by hand -- how many builtins
// the standard library holds, how many each category holds, where the
// reference's headings are -- and nothing in -check could see any of it.
//
// On 2026-10-06 that cost a broken HEAD twice. `gendocs -check` reported all
// three artifacts up to date, which they were, while seven sentences in six
// documents still gave the previous builtin count and the category index linked
// to an anchor that stopped existing the moment the heading it names was
// regenerated with a new count. A reader ran the check the documentation itself
// tells them to run, was told the documentation was current, and it was not.
//
// The checks already existed, in this package's tests. They live here now, so
// -check and `go test ./cmd/gendocs` are two callers of one implementation and
// a clean -check means the documentation agrees with the tree rather than
// meaning three files were rewritten recently. The owner's rule of 2026-10-03
// is the reason: a tool that reports success while what it names is wrong is a
// false flag, and a false flag is fixed or removed.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"mutant/builtin"
)

// docProblem is one thing a check found, at the place a reader would find it.
type docProblem struct {
	path string // repository-relative, slash-separated
	line int    // 1-based; zero when the problem is the document as a whole
	text string
}

func (p docProblem) String() string {
	if p.line == 0 {
		return fmt.Sprintf("%s: %s", p.path, p.text)
	}
	return fmt.Sprintf("%s:%d: %s", p.path, p.line, p.text)
}

// docCheck is one check's whole outcome: what it examined as well as what it
// found. The count is part of the answer because a check that examined nothing
// passes, and a pass for that reason tells a reader the opposite of the truth.
type docCheck struct {
	what     string // named in every line about this check
	noun     string // what examined counts, singular: claim, row, link
	verdict  string // what a pass means, for the summary line
	examined int
	floor    int // the least it must examine for a pass to mean anything
	problems []docProblem
}

// shortfall names the check's own failure: it looked at less than it must for a
// pass to be worth anything. An empty string means it looked at enough.
func (c docCheck) shortfall() string {
	if c.examined >= c.floor {
		return ""
	}
	return fmt.Sprintf("%s: examined %s and cannot pass on fewer than %d; the scanner is broken",
		c.what, plural(c.examined, c.noun), c.floor)
}

// The count is given its noun by plural, in limits.go: "1 problems" is the
// kind of detail that makes a reader doubt the rest of the output, and a link
// count worth four digits reads better grouped.

// checkDocumentConsistency runs every check that holds a hand-written document
// to the registry, or to where it points. It is what -check runs and what the
// tests in this package run.
//
// It deliberately does not run the rest of this package's checks. Those compile
// every fenced program, parse the CLI for the command lines the documents
// quote, and resolve every cited path: a different and far slower job that
// belongs in `go test ./cmd/gendocs`. What belongs here is every claim gendocs'
// own output can invalidate, because those are the ones a reader breaks by
// doing exactly what gendocs told them to do.
func checkDocumentConsistency(root string) ([]docCheck, error) {
	checks := make([]docCheck, 0, 4)
	for _, run := range []func(string) (docCheck, error){
		checkProseCounts,
		checkProseExampleCounts,
		checkCategoryIndex,
		checkDocumentLinks,
	} {
		check, err := run(root)
		if err != nil {
			return nil, err
		}
		checks = append(checks, check)
	}
	return checks, nil
}

// proseCountPaths are the documents that describe the standard library as it is
// now. A count in any of them is a claim about this build.
var proseCountPaths = []string{
	"README.md",
	"docs/COOKBOOK.md",
	"docs/WHAT_IS_MUTANT.md",
	"docs/WASM_REPL_REFERENCE.md",
	"docs/TUTORIAL_30_MIN.md",
	"docs/QUICK_REFERENCE.md",
	"docs/COMPARISON.md",
	"docs/STRUCTURED_DATA.md",
	"docs/INTERCHANGE_SCHEMAS.md",
	"docs/DETECTION_RULES.md",
	"docs/MUTANT_LANGUAGE_REFERENCE.md",
	"docs/EXECUTION_MODES.md",
}

// Deliberately not listed, and why: CHANGELOG.md and CONTRIBUTING.md record
// what was true at a past release, and the roadmap under plans/ records what a
// measurement found on a given day. A count in those is history, and correcting
// history would be the untruth. CAPABILITY_REFERENCE.md is generated and is
// compared byte for byte instead.

var (
	builtinCountPattern  = regexp.MustCompile(`(\d+)\s+builtins`)
	categoryCountPattern = regexp.MustCompile(`(\d+)\s+categories`)
	runnablePattern      = regexp.MustCompile(`(\d+)\s+runnable programs`)
)

// checkProseCounts is the drift gate on the oldest kind of stale claim here. A
// document that says how many builtins there are has to say the number there
// are: four of them once told a reader the standard library held 459 across 34
// categories, a count three releases old.
func checkProseCounts(root string) (docCheck, error) {
	check := docCheck{
		what:    "prose counts",
		noun:    "claim",
		verdict: "match the registry",
		floor:   1,
	}
	claims := []struct {
		pattern *regexp.Regexp
		want    int
		noun    string
	}{
		{builtinCountPattern, len(builtin.Builtins), "builtins"},
		{categoryCountPattern, len(categorySections), "categories"},
	}

	for _, path := range proseCountPaths {
		document, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			if os.IsNotExist(err) {
				check.problems = append(check.problems, docProblem{path: path, text: "listed in " +
					"proseCountPaths but not in the tree; remove it from cmd/gendocs/consistency.go"})
				continue
			}
			return check, fmt.Errorf("reading %s: %w", path, err)
		}
		for _, claim := range claims {
			problems, examined := countClaims(path, string(document), claim.pattern, claim.want, claim.noun)
			check.problems = append(check.problems, problems...)
			check.examined += examined
		}
	}
	return check, nil
}

// checkProseExampleCounts is the same check for the other number these
// documents quote, and it drifted too: the examples directory had grown by
// twelve programs since anyone last counted it.
//
// Its floor is zero on purpose. Only two documents quote this number, and a
// document is free to stop quoting it; a check on whether the sentence is right
// must not fail because somebody deleted the sentence.
func checkProseExampleCounts(root string) (docCheck, error) {
	check := docCheck{
		what:    "example counts",
		noun:    "claim",
		verdict: "match the tree",
		floor:   0,
	}

	want := 0
	examples := filepath.Join(root, "examples")
	err := filepath.WalkDir(examples, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".mut") {
			want++
		}
		return nil
	})
	if err != nil {
		return check, fmt.Errorf("walking examples: %w", err)
	}
	if want == 0 {
		return check, fmt.Errorf("walked %s and found no .mut programs", examples)
	}

	for _, path := range proseCountPaths {
		document, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			continue // reported by checkProseCounts
		}
		problems, examined := countClaims(path, string(document), runnablePattern, want, "runnable programs")
		check.problems = append(check.problems, problems...)
		check.examined += examined
	}
	return check, nil
}

// countClaims finds every claim of the pattern's shape and reports the ones
// that are not the number they should be.
//
// It searches the whole document rather than line by line, because these
// documents are hard-wrapped and "469 builtins across 35\ncategories" would
// otherwise walk straight past a check written for one line at a time. Newlines
// become spaces, which keeps every byte offset where it was, so a match is
// still reported at the line it is on.
func countClaims(path, text string, pattern *regexp.Regexp, want int, noun string) ([]docProblem, int) {
	var problems []docProblem
	examined := 0
	flat := strings.ReplaceAll(text, "\n", " ")
	for _, span := range pattern.FindAllStringSubmatchIndex(flat, -1) {
		got, err := strconv.Atoi(flat[span[2]:span[3]])
		if err != nil {
			continue
		}
		examined++
		if got == want {
			continue
		}
		problems = append(problems, docProblem{
			path: path,
			line: strings.Count(text[:span[0]], "\n") + 1,
			text: fmt.Sprintf("says %d %s; the tree has %d (the claim reads %q)",
				got, noun, want, strings.TrimSpace(flat[span[0]:span[1]])),
		})
	}
	return problems, examined
}

// categoryTableRow matches one row of the category index in
// docs/MUTANT_LANGUAGE_REFERENCE.md, which is written by hand and links into
// the generated reference by an anchor that carries the count in it.
var categoryTableRow = regexp.MustCompile(
	`\| \[([^\]]+)\]\(CAPABILITY_REFERENCE\.md#([a-z0-9-]+)\) \| (\d+) \| `)

// checkCategoryIndex guards the per-category table.
//
// The two totals above it were guarded and the thirty-nine rows under it were
// not, which is how the table came to be missing an entire category. On
// 2026-09-22 it listed 38 rows totalling 493 against a registry of 39 and 632:
// no row at all for the forensic ledger -- the whole of Phase 4 -- and five
// counts stale enough that their anchors pointed at headings that no longer
// existed. A reader following [Filesystem forensics](...#filesystem-forensics-37)
// landed nowhere, because the heading had said 115 for some time.
//
// The count is in the anchor as well as in the cell, so both are checked. An
// anchor is the half that fails silently: a wrong number in a cell is visibly
// wrong, and a wrong number in a link is a dead link somebody else discovers.
func checkCategoryIndex(root string) (docCheck, error) {
	const path = "docs/MUTANT_LANGUAGE_REFERENCE.md"
	check := docCheck{
		what:    "the category index",
		noun:    "row",
		verdict: "match the registry",
		floor:   1,
	}

	document, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return check, fmt.Errorf("reading %s: %w", path, err)
	}
	text := string(document)

	// The same grouping renderDocument does, so the table is checked against
	// the registry rather than against the generated file it links into.
	byCategory := make(map[string]int, len(categorySections))
	for _, b := range builtin.Builtins {
		if b.Name == "" {
			continue
		}
		byCategory[builtin.CapabilityCategory(b.Name)]++
	}

	listed := make(map[string]bool, len(categorySections))
	for _, span := range categoryTableRow.FindAllStringSubmatchIndex(text, -1) {
		heading := text[span[2]:span[3]]
		gotAnchor := text[span[4]:span[5]]
		gotCount := text[span[6]:span[7]]
		line := strings.Count(text[:span[0]], "\n") + 1
		check.examined++

		section := sectionByHeading(heading)
		if section == nil {
			check.problems = append(check.problems, docProblem{path: path, line: line,
				text: fmt.Sprintf("the category index has a row for %q, which is not a "+
					"section in cmd/gendocs/sections.go", heading)})
			continue
		}
		listed[section.category] = true

		want := byCategory[section.category]
		if gotCount != strconv.Itoa(want) {
			check.problems = append(check.problems, docProblem{path: path, line: line,
				text: fmt.Sprintf("the category index says %s holds %s builtins; the registry has %d",
					heading, gotCount, want)})
		}
		if wantAnchor := headingAnchor(section.heading, want); gotAnchor != wantAnchor {
			check.problems = append(check.problems, docProblem{path: path, line: line,
				text: fmt.Sprintf("the %s row links to #%s, and the reference's heading is #%s; "+
					"the link is dead", heading, gotAnchor, wantAnchor)})
		}
	}

	for _, section := range categorySections {
		if listed[section.category] {
			continue
		}
		check.problems = append(check.problems, docProblem{path: path,
			text: fmt.Sprintf("the category index has no row for %q (%d builtins), so nothing "+
				"in the reference points a reader at it", section.heading, byCategory[section.category])})
	}
	return check, nil
}

// sectionByHeading finds the section a hand-written index row names.
func sectionByHeading(heading string) *categorySection {
	for i := range categorySections {
		if strings.EqualFold(categorySections[i].heading, heading) {
			return &categorySections[i]
		}
	}
	return nil
}

// headingAnchor is the anchor of a generated "## Heading (N)" line.
//
// It is githubSlug of exactly the heading renderDocument writes, rather than a
// second slug implementation, so the index check and the link check cannot
// disagree about what an anchor is. The parenthesised count becomes a trailing
// -N, which is why a stale count breaks the link rather than merely reading
// wrong.
func headingAnchor(heading string, count int) string {
	return githubSlug(fmt.Sprintf("%s (%d)", heading, count))
}

// githubSlug is the anchor GitHub gives a heading: lower-cased, punctuation
// other than hyphens and underscores dropped, spaces turned into hyphens.
func githubSlug(heading string) string {
	heading = strings.ReplaceAll(heading, "`", "")
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case unicode.IsLetter(r) || unicode.IsNumber(r) || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// checkDocumentLinks is the anchor half: a relative link lands on a file that
// exists, and an anchor on a heading that exists. It reads the generated
// reference from disk, so it answers for the tree as it stands.
func checkDocumentLinks(root string) (docCheck, error) {
	check := docCheck{
		what:    "document links",
		noun:    "link",
		verdict: "resolve",
		floor:   1,
	}

	files, err := markdownFilesUnder(root)
	if err != nil {
		return check, err
	}

	anchorCache := map[string]map[string]bool{}
	for _, file := range files {
		lines, err := proseLinesOf(root, file)
		if err != nil {
			return check, err
		}
		dir := filepath.Dir(file)
		for _, line := range lines {
			for _, match := range markdownLink.FindAllStringSubmatch(line.text, -1) {
				target := match[1]
				if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
					continue
				}
				linked, anchor, _ := strings.Cut(target, "#")
				resolved := file
				if linked != "" {
					resolved = filepath.ToSlash(filepath.Join(dir, linked))
					if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(resolved))); err != nil {
						check.problems = append(check.problems, docProblem{path: file, line: line.n,
							text: fmt.Sprintf("link to %s, which does not exist", target)})
						continue
					}
				}
				check.examined++
				if anchor == "" || !strings.HasSuffix(resolved, ".md") {
					continue
				}
				if anchorCache[resolved] == nil {
					anchors, err := anchorsIn(root, resolved)
					if err != nil {
						return check, err
					}
					anchorCache[resolved] = anchors
				}
				if !anchorCache[resolved][strings.ToLower(anchor)] {
					check.problems = append(check.problems, docProblem{path: file, line: line.n,
						text: fmt.Sprintf("link to %s, but %s has no heading with anchor #%s",
							target, resolved, anchor)})
				}
			}
		}
	}
	return check, nil
}

// anchorsIn returns every heading anchor in a Markdown file, with GitHub's
// -1, -2 suffixes for repeated headings.
func anchorsIn(root, rel string) (map[string]bool, error) {
	lines, err := proseLinesOf(root, rel)
	if err != nil {
		return nil, err
	}
	anchors := map[string]bool{}
	counts := map[string]int{}
	for _, line := range lines {
		match := headingLine.FindStringSubmatch(line.text)
		if match == nil {
			continue
		}
		slug := githubSlug(match[2])
		if n := counts[slug]; n > 0 {
			anchors[slug+"-"+strconv.Itoa(n)] = true
		} else {
			anchors[slug] = true
		}
		counts[slug]++
	}
	return anchors, nil
}

var (
	markdownLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	headingLine  = regexp.MustCompile(`^(#{1,6})\s+(.*?)\s*#*\s*$`)
)

// docsSkippedDirs are not documentation a reader of this repository reads.
var docsSkippedDirs = map[string]bool{
	".git": true, ".codegraph": true, "node_modules": true, "dist": true, "plans": true,
	"example_output": true,
}

// markdownFilesUnder lists every Markdown file a reader of the repository sees,
// as paths relative to root and separated by slashes.
func markdownFilesUnder(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if docsSkippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".md") {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking documentation: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("found no Markdown under %s", root)
	}
	return files, nil
}

// proseLine is one line of a Markdown file outside a fence, with its 1-based
// number in the file.
type proseLine struct {
	n    int
	text string
}

// proseLinesOf yields each line of a Markdown file that is outside a fence.
func proseLinesOf(root, rel string) ([]proseLine, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rel, err)
	}
	var out []proseLine
	inFence := false
	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			out = append(out, proseLine{i + 1, line})
		}
	}
	return out, nil
}
