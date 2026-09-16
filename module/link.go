package module

import (
	"strings"

	"mutant/compiler"
)

// Key is the module's identity for the compiler: its path, canonicalised the
// same way the walker canonicalises one, so that two spellings of one file --
// which are one Module -- are also one key. Module.Path alone will not do,
// because an import that reached the same file by a different spelling records
// that other spelling.
func (m *Module) Key() string { return canonicalKey(m.Path) }

// Scope describes this module to the compiler: who it is, and what each of its
// imports named. It is what makes `ns.name` resolve to one particular file
// rather than to whichever module happened to define that name last.
func (m *Module) Scope() compiler.ModuleScope {
	namespaces := make(map[string]string, len(m.Imports))
	for _, imp := range m.Imports {
		namespaces[imp.Namespace] = canonicalKey(imp.Path)
	}

	return compiler.ModuleScope{
		Key:        m.Key(),
		Display:    m.Display,
		Namespaces: namespaces,
	}
}

// Linked is a module graph flattened into the single source coordinate system
// the compiler and the VM already work in.
//
// Modules are linked rather than compiled separately because the bytecode
// format gives no choice. The polymorphic engine shuffles the whole constant
// pool and rewrites every operand against it, the opcode permutation ships as
// one 256-entry table for the entire program, and jumps carry absolute stream
// offsets -- so two independently compiled modules could not be merged
// afterwards without each indexing the other's constants. One instruction
// stream, one constant pool, one global slot space.
//
// The cost of that is positional: every module's recorded lines are file-local
// and the blob is not. Link pays it once, up front, by rebasing each module's
// positions onto the blob before anything is compiled, and recording the spans
// needed to undo the rebase when a fault has to be reported. Nothing
// downstream -- the macro expander, the line tables, CompiledFunction,
// snippetFor -- has to learn what a module is.
type Linked struct {
	// SourceText is every module's source concatenated in link order. It
	// becomes ByteCode.SourceText, so a failing artifact can quote the line it
	// died on without opening a file.
	SourceText string

	// Spans map lines of SourceText back to the files they came from, in link
	// order. There is one per module, including the entry.
	Spans []compiler.ModuleSpan

	// Modules are the graph's modules in link order -- dependencies first,
	// entry last -- with their programs' positions already rebased onto
	// SourceText. Compile them in this order through one compiler.
	Modules []*Module

	// Entry is the entry module, the last element of Modules.
	Entry *Module

	// EntryPath is the entry module's display path. It becomes
	// ByteCode.SourceFile, which stays the program's identity: the spans say
	// which file any individual line came from.
	EntryPath string
}

// Link flattens the graph, rebasing every module's positions onto one
// concatenated source.
//
// It mutates the programs in the graph, because the whole point is that the
// compiler sees rebased positions and nothing else has to know. A Graph is
// therefore linked once; calling Link twice would shift the same positions
// twice and is a programming error rather than a supported operation.
func (g *Graph) Link() *Linked {
	if g == nil || len(g.Modules) == 0 {
		return &Linked{}
	}

	var text strings.Builder
	spans := make([]compiler.ModuleSpan, 0, len(g.Modules))

	line := 1
	offset := 0

	for _, mod := range g.Modules {
		spans = append(spans, compiler.ModuleSpan{Path: mod.Display, StartLine: line})

		// Rebase before the source is appended, using the running counts as
		// they stood at this module's start.
		mod.Program.ShiftPositions(line-1, offset)

		chunk := mod.Source
		// Every module begins on a line of its own. Without this a file that
		// does not end in a newline would run its last line into the next
		// module's first, putting two files' code on one line of the blob --
		// which no span can then separate.
		if !strings.HasSuffix(chunk, "\n") {
			chunk += "\n"
		}

		text.WriteString(chunk)
		line += strings.Count(chunk, "\n")
		offset += len(chunk)
	}

	return &Linked{
		SourceText: text.String(),
		Spans:      spans,
		Modules:    g.Modules,
		Entry:      g.Entry,
		EntryPath:  g.Entry.Display,
	}
}
