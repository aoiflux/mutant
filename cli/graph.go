package cli

// `mutant graph export` writes the symbol graph of a program to a graphene
// store, so that questions about a whole codebase can be asked of a database
// rather than of a compiler.
//
// # Why this is an export and not an engine
//
// graphene v0.9.0 describes itself as experimental and pre-production, and it
// has no query language. It is therefore an analysis target and nothing else:
// it stays out of the compile path and off the keystroke path, which
// policy/sema_guard_test.go enforces by reading the imports of every package
// that resolves a name. The graph the compiler and the editor use is the
// in-memory one in sema, and this writes a copy of it down.
//
// A consequence worth stating plainly: with no query language, what makes a
// store useful is what is *indexed* and what the labels are called. So every
// node carries its kind as a second label -- CountNodesByType then answers "how
// many functions are in this program" with no traversal -- and the properties a
// reader would look something up by are registered as index entries rather than
// left in the blob.
//
// # Identity
//
// sema.DeclID must not be persisted, and sema/id.go says so. It is a handle
// into one Graph: its ScopePath carries NUL bytes to keep reserved roots
// unspellable, and its Seq counts declarations of one name within one scope.
// Both are meaningful only to the graph that minted them. A store keyed on one
// would name declarations in a vocabulary that nothing outside this process can
// read, and a reader holding such an id has no way to get from it to a place in
// a file -- which is the one thing a reader of a stored graph always wants.
//
// So the export mints its own, and it is positional: the module a declaration
// is in and where it starts. That resolves. Given `<module>#12:5` you open the
// file and look, with no graph, no index and no mutant binary. Two exports of
// one unchanged tree agree on it, and an export of an edited tree says plainly
// which declarations moved instead of quietly reusing an ordinal.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"mutant/module"
	"mutant/sema"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"
)

// Node and edge labels. The numbers are the store's; the names are what
// DeclareTypeNames writes beside the image so the store stays readable without
// this program.
const (
	nodeModule store.NodeType = store.NodeTypeCustomBase + iota
	nodeDeclaration
	nodeValue
	nodeFunction
	nodeParam
	nodeLoopBind
	nodeNamespace
	nodeStruct
	nodeEnum
	nodeField
	nodeVariant
)

const (
	edgeDeclares store.EdgeType = store.EdgeType(store.NodeTypeCustomBase) + iota
	edgeEncloses
	edgeReferences
	edgeImports
	edgeUsesType
)

func labelNames() (map[store.NodeType]string, map[store.EdgeType]string) {
	return map[store.NodeType]string{
			nodeModule:      "Module",
			nodeDeclaration: "Declaration",
			nodeValue:       "Value",
			nodeFunction:    "Function",
			nodeParam:       "Param",
			nodeLoopBind:    "LoopBind",
			nodeNamespace:   "Namespace",
			nodeStruct:      "Struct",
			nodeEnum:        "Enum",
			nodeField:       "Field",
			nodeVariant:     "Variant",
		}, map[store.EdgeType]string{
			edgeDeclares:   "DECLARES",
			edgeEncloses:   "ENCLOSES",
			edgeReferences: "REFERENCES",
			edgeImports:    "IMPORTS",
			edgeUsesType:   "USES_TYPE",
		}
}

// kindLabel is the second label a declaration carries, beside Declaration.
// Every sema.NodeKind has one: a kind with no label would be a node that
// CountNodesByType cannot see, and the absence would look like an absence of
// declarations rather than of a mapping.
func kindLabel(kind sema.NodeKind) store.NodeType {
	switch kind {
	case sema.KindValue:
		return nodeValue
	case sema.KindFunction:
		return nodeFunction
	case sema.KindParam:
		return nodeParam
	case sema.KindLoopBind:
		return nodeLoopBind
	case sema.KindNamespace:
		return nodeNamespace
	case sema.KindStruct:
		return nodeStruct
	case sema.KindEnum:
		return nodeEnum
	case sema.KindField:
		return nodeField
	case sema.KindVariant:
		return nodeVariant
	}
	return nodeValue
}

// ExportOptions is what `mutant graph export` was asked for.
type ExportOptions struct {
	// Entry is the program's entry file. Everything it imports, transitively,
	// is exported with it -- the export describes a program, not a file.
	Entry string

	// Out is the directory the store is written to. It must not already hold
	// one: a bulk load needs an empty store, and merging into an existing
	// graph would give a store describing two versions of one program at once.
	Out string

	// ModulePaths are the --module-path directories, in order, so that an
	// import resolves here to the file the build would have resolved it to.
	ModulePaths []string
}

// ExportSummary is what was written, for the caller to print.
type ExportSummary struct {
	Out          string
	Modules      int
	Declarations int
	References   int
	Imports      int
	Nodes        int
	Edges        int

	// UnresolvedImports is the number of `import` statements that named a
	// module the program does not contain, and which therefore have no edge.
	// It is reported rather than merely skipped: an import graph with fewer
	// edges than the source has imports is a fact about the export, and a
	// reader who is not told will read the absence as "this module imports
	// nothing".
	UnresolvedImports int

	// Refusals are the program-wide rules the exported program breaks. They do
	// not stop the export: a graph of a program that will not compile is
	// exactly the graph someone is looking at when they are working out why.
	Refusals []string
}

// declProps is one declaration's blob. The field names are the whole schema a
// later reader has, so they are spelled out rather than abbreviated.
type declProps struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Module   string `json:"module"`
	Scope    string `json:"scope"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	EndLine  int    `json:"end_line"`
	EndCol   int    `json:"end_column"`
	Written  bool   `json:"name_written"`
	Exported bool   `json:"exported"`
	Target   string `json:"target,omitempty"`
}

type moduleProps struct {
	Key     string `json:"key"`
	Path    string `json:"path"`
	Display string `json:"display"`
	Name    string `json:"name"`
}

type refProps struct {
	Line   int  `json:"line"`
	Column int  `json:"column"`
	Call   bool `json:"call"`
}

type importProps struct {
	Alias    string `json:"alias"`
	Spelling string `json:"spelling"`
	Line     int    `json:"line"`
}

// ExportGraph loads the program at opts.Entry, builds its symbol graph, and
// writes it to a new graphene store at opts.Out.
func ExportGraph(opts ExportOptions) (ExportSummary, error) {
	summary := ExportSummary{Out: opts.Out}

	if opts.Out == "" {
		return summary, fmt.Errorf("graph export: an output directory is required")
	}
	// Checked before the load, so that a bad argument is reported as a bad
	// argument rather than after a compile's worth of work.
	if err := requireEmptyDirectory(opts.Out); err != nil {
		return summary, err
	}

	loaded, err := module.Load(opts.Entry, opts.ModulePaths)
	if err != nil {
		return summary, err
	}

	// Built from the loaded graph before anything links it. Link rebases every
	// position onto a concatenated blob and documents calling it twice as a
	// programming error, so an export that ran afterwards would hold positions
	// no editor could open -- and could not undo them, because a ModuleSpan
	// carries a start line and no offset.
	files := make([]sema.ProgramFile, 0, len(loaded.Modules))
	for _, mod := range loaded.Modules {
		files = append(files, sema.ProgramFile{
			Path:    mod.Path,
			Display: mod.Display,
			Program: mod.Program,
		})
	}
	return ExportProgram(sema.BuildProgram(files, opts.ModulePaths), opts.Out)
}

// ExportProgram writes an already-built program graph to a new store at out.
//
// It is separate from ExportGraph because the two answer to different things.
// ExportGraph's input is a path, and what it can produce is limited by what
// module.Load will accept -- it refuses an import that does not resolve, so
// through that door every alias has a target. A Program has no such guarantee:
// it is built from whatever files it was handed, and an import naming a file
// that was not among them leaves an alias bound to nothing.
//
// That is a real shape, it is what a partially-indexed workspace looks like,
// and the writer has to not produce an edge to a module that is not in the
// store. graphene does not check an edge's endpoints -- a delete is allowed to
// leave one dangling until the cascade reaches it -- so an unresolved import
// would become an edge into node zero and read, to anything walking it, as an
// import of whatever happened to be written first.
func ExportProgram(program *sema.Program, out string) (ExportSummary, error) {
	summary := ExportSummary{Out: out}
	if out == "" {
		return summary, fmt.Errorf("graph export: an output directory is required")
	}
	if err := requireEmptyDirectory(out); err != nil {
		return summary, err
	}

	for _, refusal := range program.Refusals {
		summary.Refusals = append(summary.Refusals, refusal.Error())
	}

	g, err := graphene.Open(out)
	if err != nil {
		return summary, fmt.Errorf("graph export: %w", err)
	}
	defer func() { _ = g.Close() }()

	nodeNames, edgeNames := labelNames()
	if err := g.DeclareTypeNames(nodeNames, edgeNames); err != nil {
		return summary, fmt.Errorf("graph export: %w", err)
	}

	writer := &graphWriter{program: program}
	loadedGraph, err := g.BulkLoad(writer.nodes, writer.edges)
	if err != nil {
		return summary, fmt.Errorf("graph export: %w", err)
	}
	// BulkLoad closes the receiver and returns a fresh Graph on the written
	// image. The deferred Close above would otherwise close a store that is
	// already closed and leave the new one open.
	g = loadedGraph

	summary.Modules = len(program.Modules)
	summary.UnresolvedImports = writer.unresolved
	summary.Declarations = writer.declarations
	summary.References = writer.references
	summary.Imports = writer.importEdges
	summary.Nodes = writer.nodeCount
	summary.Edges = writer.edgeCount
	return summary, nil
}

// requireEmptyDirectory refuses a target that already holds something.
//
// A bulk load refuses a non-empty store, so this would fail anyway -- but it
// would fail after the program had been loaded and its graph built, with an
// error about the store rather than about the argument. Checking first is what
// makes the message name the thing the caller got wrong.
func requireEmptyDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("graph export: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("graph export: %w", err)
	case len(entries) > 0:
		return fmt.Errorf("graph export: %s is not empty. A graph store is written "+
			"in one pass into an empty directory, so that what is there describes "+
			"one program at one moment", filepath.Clean(dir))
	}
	return nil
}

// graphWriter carries the node identifiers from the load's node pass to its
// edge pass.
//
// A bulk load reads its source twice and hands identifiers back as the nodes go
// by, which is what lets it write the image in one forward pass without holding
// the graph. So the ids have to be kept here: the alternative is a source that
// can only be read once, which has to be staged first anyway.
type graphWriter struct {
	program *sema.Program

	modules map[string]store.NodeID
	decls   map[string]map[sema.DeclID]store.NodeID

	nodeCount    int
	edgeCount    int
	declarations int
	references   int
	importEdges  int
	unresolved   int
}

// declKey is the minted identity: where a declaration is, not what it is
// called. See the file header on why sema.DeclID is not used.
func declKey(moduleKey string, node *sema.Node) string {
	anchor := node.Anchor()
	return fmt.Sprintf("%s#%d:%d", moduleKey, anchor.Start.Line, anchor.Start.Column)
}

func (w *graphWriter) nodes(out *graphene.BulkNodeWriter) error {
	w.modules = make(map[string]store.NodeID, len(w.program.Modules))
	w.decls = make(map[string]map[sema.DeclID]store.NodeID, len(w.program.Modules))

	for _, mod := range w.program.Modules {
		blob, err := json.Marshal(moduleProps{
			Key:     mod.Key,
			Path:    mod.Path,
			Display: mod.Display,
			Name:    moduleName(mod),
		})
		if err != nil {
			return err
		}
		id, err := out.AddNode(graphene.BulkNode{
			Labels:     []store.NodeType{nodeModule},
			Properties: blob,
			Index: []graphene.BulkProperty{
				{Key: "key", Value: []byte(mod.Key)},
				{Key: "name", Value: []byte(moduleName(mod))},
			},
		})
		if err != nil {
			return err
		}
		w.modules[mod.Key] = id
		w.nodeCount++
	}

	for _, mod := range w.program.Modules {
		byDecl := make(map[sema.DeclID]store.NodeID, len(mod.Graph.Declarations()))
		for _, node := range mod.Graph.Declarations() {
			id, err := w.addDeclaration(out, mod, node)
			if err != nil {
				return err
			}
			byDecl[node.ID] = id
		}
		w.decls[mod.Key] = byDecl
	}
	return nil
}

func (w *graphWriter) addDeclaration(out *graphene.BulkNodeWriter, mod *sema.ModuleGraph, node *sema.Node) (store.NodeID, error) {
	anchor := node.Anchor()
	key := declKey(mod.Key, node)

	blob, err := json.Marshal(declProps{
		ID:      key,
		Name:    node.Name,
		Kind:    node.Kind.String(),
		Module:  mod.Key,
		Scope:   readableScope(node),
		Line:    anchor.Start.Line,
		Column:  anchor.Start.Column,
		EndLine: node.FullRange.End.Line,
		EndCol:  node.FullRange.End.Column,
		// A derived import alias is bound without being written: the name
		// `report` of `import "lib/report.mut";` appears nowhere in the file.
		// A reader that offers to rename has to know that, which is the same
		// distinction DeclRange and FullRange draw in the graph.
		Written:  node.DeclRange.IsValid(),
		Exported: isExported(node),
		Target:   node.Target,
	})
	if err != nil {
		return 0, err
	}

	id, err := out.AddNode(graphene.BulkNode{
		Labels:     []store.NodeType{nodeDeclaration, kindLabel(node.Kind)},
		Properties: blob,
		Index: []graphene.BulkProperty{
			{Key: "id", Value: []byte(key)},
			{Key: "name", Value: []byte(node.Name)},
			{Key: "kind", Value: []byte(node.Kind.String())},
			{Key: "module", Value: []byte(mod.Key)},
		},
	})
	if err != nil {
		return 0, err
	}
	w.nodeCount++
	w.declarations++
	return id, nil
}

func (w *graphWriter) edges(out *graphene.BulkEdgeWriter) error {
	for _, mod := range w.program.Modules {
		moduleID, known := w.modules[mod.Key]
		if !known {
			continue
		}
		byDecl := w.decls[mod.Key]

		if err := w.importEdgesOf(out, mod, moduleID); err != nil {
			return err
		}
		if err := w.declarationEdgesOf(out, mod, moduleID, byDecl); err != nil {
			return err
		}
		if err := w.referenceEdgesOf(out, mod, moduleID, byDecl); err != nil {
			return err
		}
	}
	return nil
}

func (w *graphWriter) importEdgesOf(out *graphene.BulkEdgeWriter, mod *sema.ModuleGraph, moduleID store.NodeID) error {
	for _, edge := range mod.Graph.Imports() {
		// An import that resolved to nothing gets no edge. The alias is still
		// a declaration -- it is a binding whether or not the file exists --
		// but an edge to a module that is not in the program would be an
		// endpoint pointing at nothing, and graphene does not check endpoints.
		target, resolved := w.modules[edge.To]
		if !resolved {
			w.unresolved++
			continue
		}
		blob, err := json.Marshal(importProps{
			Alias:    edge.Alias,
			Spelling: edge.Spelling,
			Line:     edge.Range.Start.Line,
		})
		if err != nil {
			return err
		}
		if _, err := out.AddEdge(graphene.BulkEdge{
			Src: moduleID, Dst: target,
			Labels:     []store.EdgeType{edgeImports},
			Properties: blob,
			Index: []graphene.BulkProperty{
				{Key: "alias", Value: []byte(edge.Alias)},
			},
		}); err != nil {
			return err
		}
		w.edgeCount++
		w.importEdges++
	}
	return nil
}

// declarationEdgesOf writes which module declares a name and which declaration
// encloses it.
//
// DECLARES goes to every declaration in the module, not only the top-level
// ones: "which file is this parameter in" is the question a reader of a
// program-wide store asks first, and answering it by following ENCLOSES
// upwards would be a traversal per node.
//
// ENCLOSES is the plan's CONTAINS under another name. "contains" is one of
// graphene's own built-in edge names -- it means EvidenceFile to
// MicroArtefact -- and registering it would make one selector mean two things,
// which the engine refuses outright. The word for what this edge says is
// anyway that a declaration encloses the ones written inside it.
func (w *graphWriter) declarationEdgesOf(out *graphene.BulkEdgeWriter, mod *sema.ModuleGraph,
	moduleID store.NodeID, byDecl map[sema.DeclID]store.NodeID) error {

	for _, node := range mod.Graph.Declarations() {
		id, known := byDecl[node.ID]
		if !known {
			continue
		}
		if _, err := out.AddEdge(graphene.BulkEdge{
			Src: moduleID, Dst: id,
			Labels: []store.EdgeType{edgeDeclares},
		}); err != nil {
			return err
		}
		w.edgeCount++

		owner := scopeOwner(node)
		if owner == nil {
			continue
		}
		ownerID, known := byDecl[owner.ID]
		if !known {
			continue
		}
		if _, err := out.AddEdge(graphene.BulkEdge{
			Src: ownerID, Dst: id,
			Labels: []store.EdgeType{edgeEncloses},
		}); err != nil {
			return err
		}
		w.edgeCount++
	}
	return nil
}

// referenceEdgesOf writes one edge per recorded use.
//
// A use of a type carries USES_TYPE as a second label on the same edge rather
// than as an edge of its own, which is what makes "everything that uses Point"
// a lookup without letting it drift out of step with the references it is a
// subset of. A call is a property on the edge for the same reason and the one
// the plan gives: a separate set of call edges can disagree with the reference
// set, and a field on the reference cannot.
func (w *graphWriter) referenceEdgesOf(out *graphene.BulkEdgeWriter, mod *sema.ModuleGraph,
	moduleID store.NodeID, byDecl map[sema.DeclID]store.NodeID) error {

	for _, ref := range mod.Graph.References() {
		target, known := byDecl[ref.Target]
		if !known {
			continue
		}

		// A use outside every declaration belongs to the file. Attributing it
		// to the nearest declaration above it would invent a containment the
		// language does not have.
		source := moduleID
		if ref.From != nil {
			if fromID, known := byDecl[ref.From.ID]; known {
				source = fromID
			}
		}

		labels := []store.EdgeType{edgeReferences}
		if node, found := mod.Graph.NodeFor(ref.Target); found &&
			(node.Kind == sema.KindStruct || node.Kind == sema.KindEnum) {
			labels = append(labels, edgeUsesType)
		}

		blob, err := json.Marshal(refProps{
			Line:   ref.UseRange.Start.Line,
			Column: ref.UseRange.Start.Column,
			Call:   ref.InCallPosition,
		})
		if err != nil {
			return err
		}
		if _, err := out.AddEdge(graphene.BulkEdge{
			Src: source, Dst: target,
			Labels:     labels,
			Properties: blob,
			Index: []graphene.BulkProperty{
				{Key: "module", Value: []byte(mod.Key)},
			},
		}); err != nil {
			return err
		}
		w.edgeCount++
		w.references++
	}
	return nil
}

// readableScope renders a scope path for a human. The reserved roots carry a
// NUL so that a scope an author opened can never be spelled the same way as
// one the graph reserved; NUL is not something to write into a JSON string, so
// it is rendered as the word it stands for.
func readableScope(node *sema.Node) string {
	if node.Scope == nil {
		return ""
	}
	path := string(node.Scope.Path)
	out := make([]rune, 0, len(path))
	for _, r := range path {
		if r == 0 {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// scopeOwner is the declaration that opened the scope a declaration lives in,
// and nil at the top level of a file.
func scopeOwner(node *sema.Node) *sema.Node {
	if node == nil || node.Scope == nil {
		return nil
	}
	return node.Scope.Owner
}

// isExported reports whether another module could name this declaration: a
// top-level name that does not begin with an underscore. The underscore is the
// whole of Mutant's export rule, and it applies only at the top level -- a
// local `_x` is private to nothing, because nothing could reach it anyway.
func isExported(node *sema.Node) bool {
	if node.Scope == nil || node.Scope.Path != sema.ScopeTopLevel {
		return false
	}
	switch node.Kind {
	case sema.KindValue, sema.KindFunction:
		return node.Name != "" && node.Name[0] != '_'
	}
	return false
}

func moduleName(mod *sema.ModuleGraph) string {
	if mod.Display != "" {
		return mod.Display
	}
	return filepath.Base(mod.Path)
}

// SortedRefusals is the refusal list in a stable order, for a caller that
// prints them.
func SortedRefusals(summary ExportSummary) []string {
	out := append([]string(nil), summary.Refusals...)
	sort.Strings(out)
	return out
}
