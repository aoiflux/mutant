package main

import (
	"flag"
	"fmt"
	"os"

	"mutant/cli"
)

// handleGraphCommand implements `mutant graph export --out DIR <entry.mut>`.
//
// `export` is a subcommand rather than the whole of the command because it is
// the only half that exists yet. What a graph store is *for* is querying, and
// graphene v0.9.0 has no query language -- so `mutant graph query` is a thing
// that cannot be written honestly today, and leaving room for it costs one
// word.
func handleGraphCommand(args []string) int {
	if len(args) < 3 {
		printGraphHelp()
		return 2
	}
	if args[2] != "export" {
		fmt.Fprintf(os.Stderr, "unknown graph subcommand: %s\n\n", args[2])
		printGraphHelp()
		return 2
	}

	set := flag.NewFlagSet("graph export", flag.ContinueOnError)
	out := set.String("out", "", "Directory to write the store into; must be empty or not exist.")
	var modulePaths []string
	registerModulePathFlag(set, &modulePaths)
	if err := set.Parse(args[3:]); err != nil {
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

func printGraphHelp() {
	fmt.Print(`mutant graph export

Write the symbol graph of a program -- every declaration, every reference, and
every import across the whole module closure -- to a graphene store.

Usage:
  mutant graph export --out <dir> [--module-path DIR] <entry.mut>

Options:
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

  Edges: DECLARES (module to declaration), CONTAINS (declaration to the
  declarations inside it), REFERENCES (one per use, carrying the position and
  whether it was a call), IMPORTS (module to module) and USES_TYPE, which is a
  second label on the references that name a struct or an enum.

The store is self-describing: the label names are written beside the image, so
it stays readable without this program. Positions are file-local, matching the
source as it is on disk.

The graph is a snapshot. It is not consulted by the compiler or the editor,
which build their own in memory, and it goes stale the moment the source
changes.

Note:
  example_graph_data*/ is already in .gitignore, which makes it a convenient
  --out while you are looking around.
`)
}
