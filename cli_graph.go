package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"mutant/cli"
)

// handleGraphCommand implements `mutant graph export` and `mutant graph query`.
//
// The two halves are one command because they are one contract. A store is
// written by the export and read by the query, and the vocabulary they agree
// on -- which labels exist, which properties are indexed, what a declaration's
// identity is -- lives in one package so that it cannot drift between them.
//
// The query is not a query *language*, and the help says so. graphene v0.9.0
// has none, and what makes a store answerable without one is what was indexed
// when it was written. So the read side offers a fixed set of named questions,
// each one a shape the export's index was designed for, and refuses the rest
// rather than compiling them into a filter that would match nothing and report
// no error.
func handleGraphCommand(args []string) int {
	if len(args) < 3 {
		printGraphHelp()
		return 2
	}
	switch args[2] {
	case "export":
		return runGraphExport(args[3:])
	case "query":
		return runGraphQuery(args[3:])
	default:
		fmt.Fprintf(os.Stderr, "unknown graph subcommand: %s\n\n", args[2])
		printGraphHelp()
		return 2
	}
}

func runGraphExport(args []string) int {
	set := flag.NewFlagSet("graph export", flag.ContinueOnError)
	out := set.String("out", "", "Directory to write the store into; must be empty or not exist.")
	var modulePaths []string
	registerModulePathFlag(set, &modulePaths)
	if err := set.Parse(args); err != nil {
		return 2
	}

	entries := set.Args()
	if len(entries) != 1 {
		fmt.Fprintln(os.Stderr,
			"usage: mutant graph export --out <dir> [--module-path DIR] <entry.mut>")
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr,
			"mutant graph export: --out is required. A graph store is a directory of "+
				"files, so there is no location to guess.")
		return 2
	}

	summary, err := cli.ExportGraph(cli.ExportOptions{
		Entry:       entries[0],
		Out:         *out,
		ModulePaths: modulePaths,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutant graph export: %v\n", err)
		return 1
	}

	fmt.Printf("wrote %s\n", summary.Out)
	fmt.Printf("  %d modules, %d declarations\n", summary.Modules, summary.Declarations)
	fmt.Printf("  %d nodes, %d edges (%d references, %d imports)\n",
		summary.Nodes, summary.Edges, summary.References, summary.Imports)

	// Refusals are printed and the export still succeeded. The graph describes
	// the program as written, and a program that will not compile is exactly
	// the one someone is exporting a graph of in order to understand.
	for _, refusal := range cli.SortedRefusals(summary) {
		fmt.Fprintf(os.Stderr, "  refused: %s\n", refusal)
	}
	return 0
}

// runGraphQuery separates a bad command line from a store it could not answer
// about: exit 2 for the first and exit 1 for the second, which is what the rest
// of this command already does. cli.QueryGraph checks its own arguments too --
// it is callable without this -- and the check here is what lets the difference
// be reported.
func runGraphQuery(args []string) int {
	set := flag.NewFlagSet("graph query", flag.ContinueOnError)
	storeDir := set.String("store", "", "The directory `mutant graph export --out` wrote.")
	if err := set.Parse(args); err != nil {
		return 2
	}

	rest := set.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "usage: mutant graph query --store <dir> <question> [argument]\n"+
			"questions: %s\n", strings.Join(queryQuestionNames(), ", "))
		return 2
	}
	if *storeDir == "" {
		fmt.Fprintln(os.Stderr,
			"mutant graph query: --store is required. There is no store to guess at: a graph is "+
				"a snapshot of one program at one moment, and the wrong one answers confidently.")
		return 2
	}

	question, known := findQueryQuestion(rest[0])
	if !known {
		fmt.Fprintf(os.Stderr, "mutant graph query: %q is not a question this store can be asked.\n"+
			"questions: %s\n", rest[0], strings.Join(queryQuestionNames(), ", "))
		return 2
	}
	if len(rest) > 2 {
		fmt.Fprintf(os.Stderr, "mutant graph query %s: one argument at most, got %d\n",
			question.Name, len(rest)-1)
		return 2
	}
	argument := ""
	if len(rest) == 2 {
		argument = rest[1]
	}
	if question.Argument == "" && argument != "" {
		fmt.Fprintf(os.Stderr, "mutant graph query %s: takes no argument, got %q\n",
			question.Name, argument)
		return 2
	}
	if question.Argument != "" && argument == "" {
		fmt.Fprintf(os.Stderr, "mutant graph query %s: needs %s\n", question.Name, question.Argument)
		return 2
	}

	answer, err := cli.QueryGraph(cli.QueryOptions{
		Store:    *storeDir,
		Question: question.Name,
		Argument: argument,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutant %v\n", err)
		return 1
	}

	printQueryAnswer(answer)
	return 0
}

// printQueryAnswer renders an answer.
//
// The warnings come first and the notes last, and both go to stdout with the
// answer rather than to stderr. They are not diagnostics: what a use-count does
// not count is part of what the number means, and a pipeline that kept the
// number and dropped the sentence would be keeping the half that misleads.
func printQueryAnswer(answer cli.QueryAnswer) {
	for _, warning := range answer.Warnings {
		fmt.Printf("! %s\n", wrapAt(warning, 76, "  "))
	}
	if len(answer.Warnings) > 0 {
		fmt.Println()
	}

	fmt.Println(answer.Headline)
	for _, section := range answer.Sections {
		fmt.Println()
		fmt.Printf("%s:\n", section.Title)
		if len(section.Rows) == 0 {
			fmt.Println(section.Empty)
			continue
		}
		for _, row := range section.Rows {
			fmt.Println(row)
		}
	}

	if len(answer.Notes) > 0 {
		fmt.Println()
		for _, note := range answer.Notes {
			fmt.Printf("  note: %s\n", wrapAt(note, 74, "        "))
		}
	}
}

// wrapAt breaks a sentence onto terminal-width lines. The notes are prose and
// there is no reason to make a reader scroll sideways through one.
func wrapAt(text string, width int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var out strings.Builder
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			out.WriteString(line)
			out.WriteString("\n")
			out.WriteString(indent)
			line = word
			continue
		}
		line += " " + word
	}
	out.WriteString(line)
	return out.String()
}

func findQueryQuestion(name string) (cli.QueryQuestion, bool) {
	for _, question := range cli.QueryQuestions() {
		if question.Name == name {
			return question, true
		}
	}
	return cli.QueryQuestion{}, false
}

func queryQuestionNames() []string {
	questions := cli.QueryQuestions()
	names := make([]string, 0, len(questions))
	for _, question := range questions {
		names = append(names, question.Name)
	}
	return names
}

func printGraphHelp() {
	fmt.Print(`mutant graph

Write the symbol graph of a program -- every declaration, every reference, and
every import across the whole module closure -- to a graphene store, and read it
back.

Usage:
  mutant graph export --out <dir> [--module-path DIR] <entry.mut>
  mutant graph query --store <dir> <question> [argument]

Export options:
  --out DIR             Directory to write the store into. It must be empty or
                        not exist: the store is written in one pass, so that
                        what is there describes one program at one moment.
  --module-path DIR     Directory to search for imported modules; repeat for
                        more, searched in order. The same list the build uses,
                        so an import resolves to the same file.

What is written:
  Module nodes, one per file in the closure, and a Declaration node for every
  name the program declares -- functions, values, parameters, loop bindings,
  import aliases, structs, enums, fields and variants. Each carries its kind as
  a second label, so counting the functions in a program needs no traversal.

  Edges: DECLARES (module to declaration), ENCLOSES (declaration to the
  declarations written inside it), REFERENCES (one per use, carrying the
  position and whether it was a call), IMPORTS (module to module) and USES_TYPE,
  which is a second label on the references that name a struct or an enum.

The store is self-describing: the label names are written beside the image, so
it stays readable without this program. Positions are file-local, matching the
source as it is on disk.

The graph is a snapshot. It is not consulted by the compiler or the editor,
which build their own in memory, and it goes stale the moment the source
changes.

Query options:
  --store DIR           The directory an export wrote. It is checked against the
                        label table this program writes before it is opened, so
                        a directory that is not one of these exports is refused
                        by name rather than answered about with zeroes.

Questions:
`)
	for _, question := range cli.QueryQuestions() {
		name := question.Name
		if question.Argument != "" {
			name += " " + question.Argument
		}
		fmt.Printf("  %-20s %s\n", name, question.Blurb)
	}
	fmt.Print(`
There is no query language here, because graphene v0.9.0 has none. What makes a
store answerable without one is what was indexed when it was written, so the
questions above are the shapes the export's index was built for, and a question
that is not on the list is refused rather than turned into a filter. A filter on
a property that was never indexed matches nothing and reports no error, and one
ANDed onto a correct filter empties it -- which is why no word you type here
ever becomes a property key.

Two of the questions read every declaration record rather than an index, and
say so when they answer: `)
	scanning := []string{}
	for _, question := range cli.QueryQuestions() {
		if question.Cost == "scan" {
			scanning = append(scanning, question.Name)
		}
	}
	fmt.Printf("%s.\n", strings.Join(scanning, ", "))
	fmt.Print(`
Every answer is complete only as far as the export got. A name the export could
not resolve leaves no node and no edge, and a use written through an import
alias is recorded against the alias rather than against the name it reaches --
so `)
	fmt.Print("`callers`")
	fmt.Print(` is complete within a module and a floor across one. Each answer
carries the limits of its own question beside it.

The store is opened read-only and nothing is written to it. A store on
write-protected media is opened without a lock instead, and the answer says so.

Note:
  example_graph_data*/ is already in .gitignore, which makes it a convenient
  --out while you are looking around.
`)
}
