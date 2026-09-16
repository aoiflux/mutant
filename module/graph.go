package module

import (
	"os"
	"path/filepath"
	"strings"

	"mutant/ast"
	"mutant/lexer"
	"mutant/parser"
)

// Module is one parsed source file in the import graph.
type Module struct {
	// Path is the absolute, cleaned path of the file as it exists on disk.
	// Two spellings of the same file produce one Module, and this is the
	// spelling that was reached first.
	Path string

	// Display is Path rendered for a human: relative to the working directory
	// when that does not climb out of it, absolute otherwise. It is what
	// appears in cycle chains and tracebacks.
	Display string

	// Source is the file's contents, unmodified.
	Source string

	// Program is the parsed file. Its positions are still file-local; linking
	// rebases them onto the concatenated blob.
	Program *ast.Program

	// Imports are this file's imports in source order, already resolved.
	Imports []ResolvedImport
}

// ResolvedImport is one `import` statement with its target located.
type ResolvedImport struct {
	// Namespace is the name this import binds -- the alias when written,
	// otherwise the target's base name with the extension removed.
	Namespace string

	// Spelling is the path exactly as written in the source, for error
	// messages that have to match what the reader sees.
	Spelling string

	// Path is the absolute path of the imported file, matching the Path of
	// exactly one Module in the graph.
	Path string

	// Statement is the node this import came from, so a caller can recover its
	// source range for a diagnostic.
	Statement *ast.ImportStatement
}

// Graph is the result of walking an import graph.
type Graph struct {
	// Modules are every module reachable from the entry file, in post-order:
	// a module always appears after everything it imports and before anything
	// that imports it. Compiling them in this order means a dependency's
	// definitions exist before the code that uses them is compiled.
	//
	// The entry file is last.
	Modules []*Module

	// Entry is the entry module, the same pointer as the last element of
	// Modules.
	Entry *Module
}

// Load parses the file at entry, walks everything it imports, and returns the
// whole graph in compile order.
//
// searchPaths are the directories from `--module-path`, searched in order for
// any import that does not resolve relative to the file that wrote it.
func Load(entry string, searchPaths []string) (*Graph, error) {
	return NewResolver(searchPaths).Load(entry)
}

// Load walks the import graph from entry using this resolver's search paths.
func (r *Resolver) Load(entry string) (*Graph, error) {
	absolute, err := filepath.Abs(entry)
	if err != nil {
		return nil, &ReadError{Path: entry, Err: err}
	}
	absolute = filepath.Clean(absolute)

	w := &walker{
		resolver: r,
		byKey:    make(map[string]*Module),
		state:    make(map[string]walkState),
	}

	root, err := w.visit(absolute, nil)
	if err != nil {
		return nil, err
	}

	return &Graph{Modules: w.order, Entry: root}, nil
}

type walkState int

const (
	// walkUnseen is the zero value and means the file has not been reached.
	walkUnseen walkState = iota
	// walkOnStack means the file is an ancestor of the one being visited, so
	// reaching it again closes a cycle.
	walkOnStack
	// walkDone means the file and everything it imports are already in order.
	walkDone
)

type walker struct {
	resolver *Resolver
	byKey    map[string]*Module
	state    map[string]walkState
	order    []*Module
	// stack holds the display names of the files currently being visited, so a
	// cycle can be reported as the chain that closed it rather than as the one
	// file that repeated.
	stack []string
}

// visit loads one file and everything it imports, appending modules to order
// in post-order. importedAs carries the import statement that reached this
// file, or nil for the entry.
func (w *walker) visit(absolute string, importedAs *ast.ImportStatement) (*Module, error) {
	key := canonicalKey(absolute)

	switch w.state[key] {
	case walkDone:
		// A diamond: two files import this one. It is already compiled into
		// the order exactly once, which is the point of keying by file rather
		// than by import.
		return w.byKey[key], nil
	case walkOnStack:
		return nil, &CycleError{Chain: append(append([]string(nil), w.stack...), displayPath(absolute))}
	}

	source, err := os.ReadFile(absolute)
	if err != nil {
		return nil, &ReadError{Path: absolute, Err: err}
	}

	display := displayPath(absolute)

	p := parser.New(lexer.New(string(source)))
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) != 0 {
		return nil, &ParseError{Path: display, Errors: errs}
	}

	mod := &Module{
		Path:    absolute,
		Display: display,
		Source:  string(source),
		Program: program,
	}

	w.state[key] = walkOnStack
	w.stack = append(w.stack, display)
	w.byKey[key] = mod

	if err := w.visitImports(mod); err != nil {
		return nil, err
	}

	w.stack = w.stack[:len(w.stack)-1]
	w.state[key] = walkDone
	// Post-order: appended only once every import is already in the slice, so
	// a dependency is always compiled before its dependent.
	w.order = append(w.order, mod)

	return mod, nil
}

// visitImports resolves and walks each import of mod, in source order.
func (w *walker) visitImports(mod *Module) error {
	dir := filepath.Dir(mod.Path)
	boundBy := make(map[string]string)

	for _, stmt := range mod.Program.Statements {
		imp, ok := stmt.(*ast.ImportStatement)
		if !ok || imp == nil || imp.Path == nil {
			continue
		}

		spelling := imp.Path.Value
		namespace := imp.Namespace()

		if previous, taken := boundBy[namespace]; taken {
			return &DuplicateNamespaceError{
				Importer:  mod.Display,
				Namespace: namespace,
				First:     previous,
				Second:    spelling,
			}
		}
		boundBy[namespace] = spelling

		target, err := w.resolver.Resolve(spelling, dir)
		if err != nil {
			return decorateResolveError(mod.Display, err)
		}

		if _, err := w.visit(target, imp); err != nil {
			return err
		}

		mod.Imports = append(mod.Imports, ResolvedImport{
			Namespace: namespace,
			Spelling:  spelling,
			Path:      target,
			Statement: imp,
		})
	}

	return nil
}

// decorateResolveError names the file that wrote the failing import. The
// resolver knows the directory it searched from but not which file asked, and
// the file is what the reader has to open to fix it.
func decorateResolveError(importer string, err error) error {
	switch e := err.(type) {
	case *NotFoundError:
		if e.Importer == "" {
			e.Importer = importer
		}
	case *InvalidPathError:
		if e.Importer == "" {
			e.Importer = importer
		}
	}
	return err
}

// displayPath renders an absolute path the way it should appear in a message:
// relative to the working directory when that stays inside it, absolute
// otherwise. A relative path is what the reader typed and can paste back; a
// `../../..` chain is neither, so the absolute path is clearer.
func displayPath(absolute string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return absolute
	}

	rel, err := filepath.Rel(cwd, absolute)
	if err != nil || rel == "" || rel == "." {
		return absolute
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return absolute
	}
	return rel
}
