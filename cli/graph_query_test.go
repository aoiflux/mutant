package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The read side is tested against stores the write side actually wrote.
//
// Every test here exports a real tree and then asks the store a question, which
// is the only way to check the thing that matters: that the reader and the
// writer agree about what was indexed, what the labels are called, and what a
// declaration's identity is. A fixture store would freeze one side's idea of
// that and pass forever.

func ask(t *testing.T, dir, question, argument string) QueryAnswer {
	t.Helper()
	answer, err := QueryGraph(QueryOptions{Store: dir, Question: question, Argument: argument})
	if err != nil {
		t.Fatalf("%s %s: %v", question, argument, err)
	}
	return answer
}

func rows(answer QueryAnswer, title string) []string {
	for _, section := range answer.Sections {
		if section.Title == title || strings.HasPrefix(section.Title, title) {
			return section.Rows
		}
	}
	return nil
}

func allRows(answer QueryAnswer) string {
	var out strings.Builder
	out.WriteString(answer.Headline)
	out.WriteString("\n")
	for _, section := range answer.Sections {
		out.WriteString(section.Title)
		out.WriteString("\n")
		for _, row := range section.Rows {
			out.WriteString(row)
			out.WriteString("\n")
		}
	}
	for _, note := range answer.Notes {
		out.WriteString(note)
		out.WriteString("\n")
	}
	return out.String()
}

// fingerprint is every file in a directory, by name and content hash. A query
// that changed the store would change one of these.
func fingerprint(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		out = append(out, fmt.Sprintf("%s %s", entry.Name(), hex.EncodeToString(sum[:])))
	}
	sort.Strings(out)
	return out
}

// The store is evidence, and a question asked of it must not be a change to it.
//
// This is the reason the query opens read-only rather than reusing the export's
// own graphene.Open. That call takes an exclusive lock and rewrites
// graphene.lock -- with the running process's pid in it -- on open and again on
// close, so the same three questions asked through it would leave the store
// with a different hash each time and a record of who had read it.
func TestAskingAQuestionDoesNotChangeTheStore(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	before := fingerprint(t, dir)

	for _, question := range []struct{ name, argument string }{
		{"summary", ""},
		{"modules", ""},
		{"where", "label"},
		{"callers", "show"},
		{"callees", "line"},
		{"outline", "main.mut"},
		{"exported", ""},
	} {
		ask(t, dir, question.name, question.argument)
	}

	after := fingerprint(t, dir)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("the store changed:\nbefore:\n%s\nafter:\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
}

// Every question has to be reachable, or adding one to the list is how a
// question comes to exist in the help and nowhere else.
func TestEveryQuestionOnTheListCanBeAsked(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")

	arguments := map[string]string{
		"where":   "label",
		"callers": "show",
		"callees": "line",
		"outline": "main.mut",
	}
	for _, question := range QueryQuestions() {
		argument := arguments[question.Name]
		if question.Argument != "" && argument == "" {
			t.Fatalf("%s takes %s and this test has no argument for it",
				question.Name, question.Argument)
		}
		answer := ask(t, dir, question.Name, argument)
		if answer.Headline == "" {
			t.Fatalf("%s answered with no headline", question.Name)
		}
	}
}

// The summary is the store describing itself, and it has to describe the thing
// the export said it wrote.
func TestTheSummaryCountsWhatTheExportReported(t *testing.T) {
	summary, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	answer := ask(t, dir, "summary", "")

	if want := fmt.Sprintf("%d nodes, %d edges", summary.Nodes, summary.Edges); answer.Headline != want {
		t.Fatalf("headline %q, want %q", answer.Headline, want)
	}

	labels := strings.Join(rows(answer, "Nodes, by label"), "\n")
	for _, want := range []string{
		fmt.Sprintf("Module         %d", summary.Modules),
		fmt.Sprintf("Declaration    %d", summary.Declarations),
	} {
		if !strings.Contains(labels, want) {
			t.Fatalf("the label counts do not say %q:\n%s", want, labels)
		}
	}

	// The overlap is the whole reason this is reported as a breakdown rather
	// than as a total: a reader who adds these up gets more nodes than there
	// are, and nothing in graphene would tell them.
	if !strings.Contains(allRows(answer), "do not add up") {
		t.Fatal("the summary does not say its label counts overlap")
	}
}

// A directory that is not one of these exports must be refused by name, and --
// the half that a wrong --store would otherwise make expensive -- must be left
// exactly as it was found.
//
// graphene has no notion of "the wrong kind of store": Open creates one at a
// path that has none, and every open mode accepts an existing directory holding
// anything at all and reports zero nodes. Reading the label table before
// opening is what turns that into a refusal.
func TestADirectoryThatIsNotAnExportIsRefusedWithoutBeingTouched(t *testing.T) {
	junk := t.TempDir()
	for name, content := range map[string]string{
		"notes.txt": "nothing to do with graphs",
		"main.mut":  "let x = 1;\n",
	} {
		if err := os.WriteFile(filepath.Join(junk, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := fingerprint(t, junk)

	_, err := QueryGraph(QueryOptions{Store: junk, Question: "summary"})
	if err == nil {
		t.Fatal("a directory of unrelated files answered a question about a symbol graph")
	}
	if !strings.Contains(err.Error(), "not a symbol graph") {
		t.Fatalf("the refusal does not say what is wrong: %v", err)
	}

	after := fingerprint(t, junk)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("a refused query wrote into the directory it refused:\n%s",
			strings.Join(after, "\n"))
	}
}

func TestAPathThatDoesNotExistIsRefusedAndNotCreated(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "typo")

	_, err := QueryGraph(QueryOptions{Store: missing, Question: "summary"})
	if err == nil {
		t.Fatal("a path holding no store answered a question")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("the refusal does not say the path is missing: %v", err)
	}
	if _, statErr := os.Stat(missing); statErr == nil {
		t.Fatal("the query created the store it was asked to read")
	}
}

// A label table that is well formed, self-consistent and simply wrong about the
// data it labels is something graphene cannot detect: it opens clean, and a
// query for "Module" comes back with the declarations. The only cross-check
// available is the one this program compiled with.
func TestALabelTableThatDisagreesWithThisProgramIsRefused(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")

	path := filepath.Join(dir, "graphene.labels")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	swapped := strings.Replace(string(raw), "node\t32768\tModule", "node\t32768\tDeclaration", 1)
	swapped = strings.Replace(swapped, "node\t32769\tDeclaration", "node\t32769\tModule", 1)
	if swapped == string(raw) {
		t.Fatalf("the label table is not shaped the way this test assumes:\n%s", raw)
	}
	if err := os.WriteFile(path, []byte(swapped), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = QueryGraph(QueryOptions{Store: dir, Question: "summary"})
	if err == nil {
		t.Fatal("a store that calls its modules declarations answered anyway")
	}
	if !strings.Contains(err.Error(), "calls label 32768") {
		t.Fatalf("the refusal does not name the disagreement: %v", err)
	}
}

// A table torn mid-write parses, in graphene, as a shorter name. The writer
// always ends the file with a newline, so a file that does not is torn.
func TestATornLabelTableIsRefused(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")

	path := filepath.Join(dir, "graphene.labels")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:len(raw)-4], 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := QueryGraph(QueryOptions{Store: dir, Question: "summary"}); err == nil ||
		!strings.Contains(err.Error(), "torn") {
		t.Fatalf("a torn label table was accepted: %v", err)
	}
}

// A store whose image is gone still carries its label table, still opens, and
// still passes VerifyIndexes. What it does not have is any node -- and an
// export writes at least the module it was given, so zero is missing evidence
// rather than an empty program.
func TestAStoreWithNoImageIsRefusedRatherThanReportedEmpty(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	if err := os.Remove(filepath.Join(dir, "graphene.csr")); err != nil {
		t.Fatal(err)
	}

	_, err := QueryGraph(QueryOptions{Store: dir, Question: "summary"})
	if err == nil {
		t.Fatal("a store with no image reported an empty program instead of refusing")
	}
	if !strings.Contains(err.Error(), "holds no nodes") {
		t.Fatalf("the refusal does not say what is missing: %v", err)
	}
}

// Identity in this store is positional, so one name is as many declarations as
// there are places it is written. `label` is declared at the top level of two
// modules in the fixture, and an answer naming one of them would be naming
// whichever the index handed over first.
func TestWhereNamesEveryDeclarationAndNotTheFirst(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	answer := ask(t, dir, "where", "label")

	found := rows(answer, "Declared at")
	if len(found) != 2 {
		t.Fatalf("%d declarations of `label`, want 2:\n%s", len(found), allRows(answer))
	}
	joined := strings.Join(found, "\n")
	for _, want := range []string{"main.mut:3:5", "report.mut:2:5"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the answer does not name %s:\n%s", want, joined)
		}
	}
	if !strings.Contains(allRows(answer), "shadowed") {
		t.Fatal("the answer does not say why one name is two declarations")
	}
}

// The index is byte-exact and does no folding, so a name typed with the wrong
// casing matches nothing and reports no error. Saying which of the two it was
// costs one scan and is the difference between an answer and a confident
// nothing.
func TestAMisspeltNameIsAnsweredWithTheCasingThatExists(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")

	answer := ask(t, dir, "where", "Mean")
	if !strings.Contains(answer.Headline, "only in case") {
		t.Fatalf("a name differing only in case was reported as absent: %s", answer.Headline)
	}
	if !strings.Contains(strings.Join(rows(answer, "Declared, but"), "\n"), "stats.mut:2:5") {
		t.Fatalf("the answer does not point at the name that does exist:\n%s", allRows(answer))
	}

	absent := ask(t, dir, "where", "nosuchname")
	if !strings.Contains(absent.Headline, "nothing in this store is called") {
		t.Fatalf("a name that really is absent was not reported as absent: %s", absent.Headline)
	}
}

// A use written at the top level of a file has no enclosing declaration, so its
// REFERENCES edge starts at the module node. A renderer that expected a
// declaration on both ends would drop it -- and in the fixture the use it drops
// is the call that starts the program.
func TestAUseAtTheTopLevelOfAFileIsReportedAgainstTheFile(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	answer := ask(t, dir, "callers", "show")

	if !strings.Contains(answer.Headline, "1 recorded use") {
		t.Fatalf("headline %q, want one use of `show`", answer.Headline)
	}
	body := allRows(answer)
	if !strings.Contains(body, "top level of main.mut") {
		t.Fatalf("the caller is not reported as the file's top level:\n%s", body)
	}
	if !strings.Contains(body, "called") {
		t.Fatalf("the use is not reported as a call:\n%s", body)
	}
}

// A cross-module use lands on the import alias and never reaches the member, so
// `mean` -- which report.mut calls -- has no inbound reference at all. The
// number is right about the store and wrong about the program, and the only
// honest thing to do with it is to say so beside it.
func TestACrossModuleUseIsCountedAgainstTheAliasAndTheAnswerSaysSo(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")

	callers := ask(t, dir, "callers", "mean")
	if !strings.Contains(callers.Headline, "0 recorded use") {
		t.Fatalf("headline %q, want no recorded use of `mean`", callers.Headline)
	}
	if !strings.Contains(strings.Join(callers.Notes, "\n"), "import alias") {
		t.Fatalf("a zero that is not a zero was reported without its reason:\n%s",
			strings.Join(callers.Notes, "\n"))
	}

	// The other half of the same fact: the call is recorded, against `stats`.
	callees := ask(t, dir, "callees", "line")
	if !strings.Contains(allRows(callees), "stats (namespace)") {
		t.Fatalf("the call `stats.mean(...)` is not reported against the alias:\n%s",
			allRows(callees))
	}
}

// An outline is the lexical nest, and the nest is rebuilt from the ENCLOSES
// edges rather than walked. A traversal would deduplicate by neighbour and drop
// edges that run parallel to a DECLARES, which in this schema is most of them.
func TestAnOutlineNestsAParameterInsideItsFunction(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	answer := ask(t, dir, "outline", "lib/stats.mut")

	found := rows(answer, "Declarations")
	joined := strings.Join(found, "\n")
	if !strings.Contains(joined, "mean") || !strings.Contains(joined, "values") {
		t.Fatalf("the outline is missing a declaration:\n%s", joined)
	}

	var meanIndent, valuesIndent int
	for _, row := range found {
		indent := len(row) - len(strings.TrimLeft(row, " "))
		switch {
		case strings.Contains(row, "mean") && meanIndent == 0:
			meanIndent = indent
		case strings.Contains(row, "values") && valuesIndent == 0:
			valuesIndent = indent
		}
	}
	if valuesIndent <= meanIndent {
		t.Fatalf("a parameter is not nested inside its function:\n%s", joined)
	}
}

// A module is addressed by a canonical key -- an absolute path, lowercased on
// Windows -- and nobody types one of those. A short name resolves, and one that
// resolves to more than one module is refused rather than picked from.
func TestAModuleIsFoundByAShortNameAndAnAmbiguousOneIsRefused(t *testing.T) {
	_, dir, key := exportFixtureTo(t, exportFixture, "main.mut")

	for _, spelling := range []string{"main.mut", "lib/stats.mut", "stats.mut"} {
		answer := ask(t, dir, "outline", spelling)
		if answer.Headline == "" {
			t.Fatalf("%q did not resolve to a module", spelling)
		}
	}
	// The key itself is what the store holds, so it has to work too.
	if answer := ask(t, dir, "outline", key("lib/stats.mut")); answer.Headline == "" {
		t.Fatal("a module's own key did not resolve to it")
	}

	_, ambiguous, _ := exportFixtureTo(t, map[string]string{
		"main.mut":    "import a \"a/thing.mut\";\nimport b \"b/thing.mut\";\n",
		"a/thing.mut": "let here = 1;\n",
		"b/thing.mut": "let there = 2;\n",
	}, "main.mut")

	_, err := QueryGraph(QueryOptions{Store: ambiguous, Question: "outline", Argument: "thing.mut"})
	if err == nil {
		t.Fatal("a name matching two modules picked one of them")
	}
	if !strings.Contains(err.Error(), "names 2") {
		t.Fatalf("the refusal does not say the name is ambiguous: %v", err)
	}
}

// `exported` is in the blob and not in the index. A filter on it returns no
// rows and no error -- and ANDed onto a correct filter it empties that too --
// so the only way to answer this truthfully is to read the records.
//
// The number is therefore the point of the test: a filter would say nought.
func TestExportedIsAnsweredFromTheRecordsAndNotFromTheIndex(t *testing.T) {
	summary, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	answer := ask(t, dir, "exported", "")

	found := rows(answer, "Exported")
	if len(found) == 0 {
		t.Fatalf("no declaration is reported exported, which is what a property filter "+
			"on a blob key returns:\n%s", allRows(answer))
	}
	want := fmt.Sprintf("%d of %d declaration(s) are exported", len(found), summary.Declarations)
	if answer.Headline != want {
		t.Fatalf("headline %q, want %q", answer.Headline, want)
	}

	joined := strings.Join(found, "\n")
	for _, want := range []string{"mean", "line", "show"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("`%s` is exported and is not listed:\n%s", want, joined)
		}
	}
	// _total is top-level and begins with an underscore, which is the whole of
	// the rule.
	if strings.Contains(joined, "_total") {
		t.Fatalf("an underscored name is reported exported:\n%s", joined)
	}
	if !strings.Contains(strings.Join(answer.Notes, "\n"), "read every declaration record") {
		t.Fatal("a scan is not declared as one")
	}
}

// The import graph is the one answer in this store that is complete, because
// the export refuses to write an edge for an import it could not resolve.
func TestTheModulesAnswerNamesTheEntryAndTheImportsThatResolved(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")
	answer := ask(t, dir, "modules", "")

	if !strings.Contains(answer.Headline, "3 module(s)") {
		t.Fatalf("headline %q, want three modules", answer.Headline)
	}
	listing := strings.Join(rows(answer, "Modules"), "\n")
	for _, want := range []string{
		"main.mut",
		"imports numbers -> lib/stats.mut",
		"imports stats -> lib/stats.mut",
	} {
		if !strings.Contains(listing, want) {
			t.Fatalf("the listing does not say %q:\n%s", want, listing)
		}
	}

	entry := strings.Join(rows(answer, "Imported by nothing"), "\n")
	if !strings.Contains(entry, "main.mut") || strings.Contains(entry, "stats.mut") {
		t.Fatalf("the entry module is not the only one nothing imports:\n%s", entry)
	}
}

// Asking for something that is not on the list is refused with the list, rather
// than turned into a filter on a key nothing indexed.
func TestAQuestionThatIsNotOnTheListIsRefusedWithTheList(t *testing.T) {
	_, dir, _ := exportFixtureTo(t, exportFixture, "main.mut")

	_, err := QueryGraph(QueryOptions{Store: dir, Question: "unused"})
	if err == nil {
		t.Fatal("a question this store cannot answer was answered")
	}
	for _, want := range []string{"unused", "callers", "outline"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q: %v", want, err)
		}
	}

	if _, err := QueryGraph(QueryOptions{Store: dir, Question: "where"}); err == nil ||
		!strings.Contains(err.Error(), "needs <name>") {
		t.Fatalf("a question missing its argument was run anyway: %v", err)
	}
	if _, err := QueryGraph(QueryOptions{
		Store: dir, Question: "summary", Argument: "extra",
	}); err == nil || !strings.Contains(err.Error(), "takes no argument") {
		t.Fatalf("an argument was accepted where none is taken: %v", err)
	}
}
