package sema

import (
	"mutant/ast"
)

// A Program is every module of one compilation, each with its own Graph.
//
// # Why it takes parsed files rather than a module.Graph
//
// Because it cannot take one. module imports compiler and compiler imports
// this package, so a sema that imported module would close the cycle. That is
// not merely a build constraint -- it is the same layering that put
// CanonicalKey here instead of in module, where it was written: the rules that
// decide what a name means sit underneath the loader that finds the files.
//
// So the caller hands over what it already has. module.Graph.Modules is a slice
// of exactly these four fields, and turning one into a []ProgramFile is a loop.
// It is the ScopeCtx arrangement again: state is passed in, never reached for.
//
// # What it adds over calling BuildFile in a loop
//
// Two things, and both need every module present at once.
//
// The first is that an import alias only has a target if the module it names is
// already known, so the facts for every file have to be recorded before any
// graph is built. A loop that built each graph as it went would give the first
// module an alias pointing at nothing.
//
// The second is the program-wide type-name table. Struct and enum names are not
// module-scoped in Mutant: compiler.claimTypeName refuses two modules declaring
// the same struct name anywhere in the program, and ByteCode.StructDefs is one
// flat map. A per-module graph cannot see that, so it is decided here, and the
// refusal is the compiler's own sentence rather than a second phrasing of it.
//
// # What it does not do
//
// It does not link. Every range in every graph here is file-local, which is the
// whole reason the graph is built before module.Graph.Link rebases positions
// onto the concatenated blob: after linking there is no offset in a ModuleSpan
// to un-rebase with, so the file-local position an editor needs could not be
// recovered. program_test.go pins that as a test rather than a comment.
//
// It does not cache. A Program describes one compilation and is discarded with
// it; a cached one is the single way stale edges could get into the compile
// path, which the package doc refuses.
type Program struct {
	// Modules are the modules in the order they were given, which for a
	// module.Graph is compile order with the entry last.
	Modules []*ModuleGraph

	// Refusals are the program-wide rules this program breaks, in the order
	// they were found. It is not "errors": a refusal is a decision, and
	// whether it stops a build or draws a squiggle is the caller's posture.
	Refusals []*Refusal

	byKey map[string]*ModuleGraph
	types map[string]*ModuleGraph
	ws    *Workspace
}

// ModuleGraph is one module's graph with the identity the loader gave it.
type ModuleGraph struct {
	// Key is the CanonicalKey of Path, and is what every DeclID in Graph
	// names as its module.
	Key string

	// Path is the file on disk; Display is the same file as a reader would
	// write it, which is what a refusal names.
	Path, Display string

	Graph *Graph
}

// ProgramFile is one parsed file, in the shape a loader already holds it.
//
// URI is optional and exists for the one caller that has both: the language
// server knows a file by the name an editor gave it as well as by its path, and
// a resolution has to be turned back into the former.
type ProgramFile struct {
	Path    string
	URI     string
	Display string
	Program *ast.Program
}

// BuildProgram builds a graph for every file, with imports resolved between
// them.
//
// It never fails. Every way this can go wrong -- an import naming a file that
// was not passed, a struct name claimed twice, a file that did not parse -- is
// a fact about the program rather than about the call, and is reported as a
// refusal or as an alias with no target. A caller that must not proceed reads
// Refusals; the export writes them down and carries on, because a graph of a
// program that will not compile is exactly the graph someone is looking at when
// they are trying to find out why.
//
// searchPaths are the --module-path directories, in order, so that an import
// resolves here to the same file the loader resolved it to.
//
// No StructOf is supplied, so `p.x` resolves to a struct field in no module.
// Which struct a binding holds is inference: it is heuristic, it is
// per-snapshot, and the language server is the only caller that has it. A
// program graph that guessed would be a graph the compiler could come to depend
// on.
func BuildProgram(files []ProgramFile, searchPaths []string) *Program {
	p := &Program{
		Modules: make([]*ModuleGraph, 0, len(files)),
		byKey:   make(map[string]*ModuleGraph, len(files)),
		types:   make(map[string]*ModuleGraph, 8),
		ws:      NewWorkspace(searchPaths),
	}

	// Pass one: what every file declares. It has to finish before any graph is
	// built, because an import alias reads the workspace for the module it
	// names and a module recorded later would not be there yet.
	for _, file := range files {
		if file.Program == nil {
			continue
		}
		uri := file.URI
		if uri == "" {
			uri = file.Path
		}
		p.ws.PutFile(uri, file.Path, file.Program)
	}

	// Pass two: the graphs, and the program-wide type table alongside them.
	for _, file := range files {
		if file.Program == nil {
			continue
		}
		key := CanonicalKey(file.Path)
		if _, already := p.byKey[key]; already {
			// Two spellings of one file. The loader dedupes these, and one
			// that did not would otherwise get two graphs and a spurious
			// duplicate-type refusal against itself.
			continue
		}
		module := &ModuleGraph{
			Key:     key,
			Path:    file.Path,
			Display: file.Display,
			Graph:   BuildFile(key, file.Program, p.ws, nil),
		}
		p.Modules = append(p.Modules, module)
		p.byKey[key] = module
		p.claimTypeNames(module)
	}

	return p
}

// claimTypeNames files this module's struct and enum names in the program-wide
// table, refusing a name another module already claimed.
//
// First claimant wins, which matches the compiler: it walks modules in the same
// order and its typeOwners map is filled the same way, so the two name the same
// pair in the same order and the sentence reads identically.
func (p *Program) claimTypeNames(module *ModuleGraph) {
	graph := module.Graph
	if graph == nil || graph.Types == nil {
		return
	}

	for _, declared := range graph.Types.order {
		kind := ""
		switch declared.Kind {
		case KindStruct:
			kind = "struct"
		case KindEnum:
			kind = "enum"
		default:
			continue
		}

		owner, taken := p.types[declared.Name]
		if !taken {
			p.types[declared.Name] = module
			continue
		}
		if owner.Key == module.Key {
			continue
		}
		p.Refusals = append(p.Refusals,
			duplicateTypeNameRefusal(kind, declared.Name, owner.name(), module.name()))
	}
}

// name is the module as a refusal should name it, mirroring the compiler's
// moduleName: the display spelling where there is one, the key otherwise.
func (m *ModuleGraph) name() string {
	if m == nil {
		return "this program"
	}
	if m.Display != "" {
		return m.Display
	}
	if m.Key == "" {
		return "this program"
	}
	return m.Key
}

// ModuleFor returns the graph for one module key.
func (p *Program) ModuleFor(key string) (*ModuleGraph, bool) {
	if p == nil {
		return nil, false
	}
	module, known := p.byKey[key]
	return module, known
}

// Workspace is the index the graphs were built against, so a caller can ask it
// what an import resolved to or what a module exports without rebuilding one.
func (p *Program) Workspace() *Workspace {
	if p == nil {
		return nil
	}
	return p.ws
}

// TypeOwner returns the module that claimed a struct or enum name
// program-wide.
//
// Program-wide is the point. A type name is the one thing in Mutant that is not
// module-scoped, so "which module declares Point" has a single answer across
// the whole program and asking any one graph would give an answer that is right
// only by luck.
func (p *Program) TypeOwner(name string) (*ModuleGraph, bool) {
	if p == nil {
		return nil, false
	}
	module, claimed := p.types[name]
	return module, claimed
}
