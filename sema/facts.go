package sema

import (
	"hash/fnv"
	"sort"

	"mutant/ast"
)

// SymKind is what a declaration declares.
//
// It is deliberately coarser than the language server's CompletionItemKind and
// narrower than the compiler's SymbolScope: those describe how a name is
// presented and where its slot lives, which are the two things this package is
// careful not to decide.
type SymKind uint8

const (
	SymValue SymKind = iota
	SymFunction
	SymStruct
	SymEnum
)

// ExportFact is one top-level declaration, as seen from outside its module.
//
// It carries only what a reach from another file can legitimately use. In
// particular it carries no ast.Node: a fact about a module travels to every
// module that imports it, and nothing in this package may hold a node belonging
// to a file other than its own. DeclRange is a position inside the declaring
// file and is meaningless without knowing which file that is, so it is only
// ever read alongside the module key that produced it.
type ExportFact struct {
	Name string
	Kind SymKind

	// Private is IsModulePrivate(Name), precomputed because every consumer
	// filters on it.
	Private bool

	// DeclRange is the identifier's own range, file-local. It is the zero value
	// on the compile path, which has no use for it.
	DeclRange ast.Range

	// Params are a function's parameter names, in order, and nil for anything
	// else. They are strings rather than nodes for the reason the whole type
	// is: a fact about a module travels to every module that imports it, and
	// nothing here may hold an ast.Node belonging to another file.
	//
	// Names only. Mutant has no parameter type annotations, and the language
	// server's inferred kinds are per-snapshot and explicitly heuristic -- one
	// file's guess about another file's function would be a guess presented as
	// a fact.
	Params []string
}

// TypeFact is a struct or enum declaration.
//
// It is kept apart from ExportFact because a type name is not an export: struct
// and enum names are program-global in Mutant. claimTypeName refuses two
// modules declaring one struct name program-wide, and ByteCode.StructDefs is a
// flat map, so a type is written bare -- `Colour.Red`, never `ns.Colour`. Filing
// types among a module's exports would offer them behind `ns.`, which is a
// spelling the compiler does not accept.
type TypeFact struct {
	Name string

	// Kind is SymStruct or SymEnum.
	Kind SymKind

	// Members are the struct's fields or the enum's variants, in declaration
	// order -- the order matters for an enum, whose variants are tagged by
	// position.
	Members []string

	DeclRange ast.Range
}

// ImportFact is one `import` statement, recorded as written.
//
// Spelling is deliberately not resolved here. Resolving it means asking the
// filesystem which candidate exists, and PutFile runs on the keystroke path
// where it must not do that. Workspace.resolveImport performs the same walk
// module.Resolver performs, substituting "is this file indexed?" for "does this
// file exist?", which is what keeps an editor's answer and a build's answer the
// same shape.
type ImportFact struct {
	// Alias is the name this import binds, already through
	// ImportStatement.Namespace -- the explicit alias when one was written and
	// otherwise the derivation from the file name. Empty means no usable name
	// could be derived, which the compiler reports as an import needing an
	// explicit alias.
	Alias string

	// Spelling is the path exactly as the author typed it.
	Spelling string

	// Range covers the whole import statement, file-local. It is what a
	// documentLink attaches to.
	Range ast.Range
}

// ModuleFacts is everything about one file that another file could need.
//
// It is the unit of incremental work: PutFile rebuilds one of these from an
// already-parsed Program, reading top-level statements only. Nothing here
// requires walking into a function body, so typing inside one changes no fact
// and costs nothing beyond the parse the editor already did.
type ModuleFacts struct {
	// Key is the CanonicalKey of the file. It is what imports resolve to and
	// what everything in the Workspace is filed under.
	Key string

	// URI is the document URI the editor knows this file by, kept so a
	// resolution can be turned back into a location the client can open.
	URI string

	// Path is the file's location as it was actually spelled, before
	// CanonicalKey folded its case. It exists only to be shown to a reader.
	//
	// Key and Path are deliberately separate: a key is an identity, and on
	// Windows it is lowercased so that two spellings of one file compare equal.
	// Printing that identity in a message would show someone a path they did
	// not write, and the compiler's own refusals name the file as the loader
	// saw it -- so a message built from a key would be a second phrasing of a
	// sentence that is supposed to be one.
	Path string

	Exports map[string]ExportFact
	Types   map[string]TypeFact
	Imports []ImportFact

	// Hash covers the names, kinds and import spellings above -- and
	// deliberately not the ranges.
	//
	// Its only job is to answer "could this edit have changed what another
	// module sees?". Moving a declaration down three lines cannot: an importer
	// resolves to a name, and reads the range from these facts at query time,
	// which is why nothing caches another module's positions. Including ranges
	// would bump the generation on every keystroke in the file and defeat the
	// whole point.
	Hash uint64
}

// FactsOf reads one file's top level.
//
// It never touches the filesystem and never descends into a function body. Both
// are load-bearing: this runs on the keystroke path.
//
// A nil program yields empty facts rather than nil, so a file that failed to
// parse is a module with nothing in it rather than a module that does not
// exist. The difference matters to the editor -- an unparseable import target
// should stop offering stale members, not start resolving by guesswork
// somewhere else.
func FactsOf(key, uri, path string, program *ast.Program) *ModuleFacts {
	facts := &ModuleFacts{
		Key:     key,
		URI:     uri,
		Path:    path,
		Exports: make(map[string]ExportFact, 8),
		Types:   make(map[string]TypeFact, 2),
	}
	if program == nil {
		facts.Hash = facts.computeHash()
		return facts
	}

	rangeOf := func(n ast.Node) ast.Range {
		if n == nil {
			return ast.Range{}
		}
		r, _ := program.RangeOf(n)
		return r
	}

	for _, statement := range program.Statements {
		switch node := statement.(type) {
		case *ast.LetStatement:
			kind := SymValue
			var params []string
			if fn, isFn := node.Value.(*ast.FunctionLiteral); isFn {
				kind = SymFunction
				params = make([]string, 0, len(fn.Parameters))
				for _, parameter := range fn.Parameters {
					if parameter != nil {
						params = append(params, parameter.Value)
					}
				}
			}
			// Name and Names are both populated forms: `let x = ...` uses the
			// first, `let value, err = ...` the second. A destructured binding
			// is never a function however it was produced, so only the single
			// form can carry SymFunction.
			if node.Name != nil {
				facts.addExport(node.Name.Value, kind, rangeOf(node.Name), params)
			}
			for _, name := range node.Names {
				facts.addExport(name.Value, SymValue, rangeOf(name), nil)
			}

		case *ast.StructStatement:
			if node.Name != nil {
				facts.addType(node.Name.Value, SymStruct, node.Fields, rangeOf(node.Name))
			}

		case *ast.EnumStatement:
			if node.Name != nil {
				facts.addType(node.Name.Value, SymEnum, node.Variants, rangeOf(node.Name))
			}

		case *ast.ImportStatement:
			spelling := ""
			if node.Path != nil {
				spelling = node.Path.Value
			}
			facts.Imports = append(facts.Imports, ImportFact{
				Alias:    node.Namespace(),
				Spelling: spelling,
				Range:    rangeOf(node),
			})
		}
	}

	facts.Hash = facts.computeHash()
	return facts
}

func (f *ModuleFacts) addExport(name string, kind SymKind, declRange ast.Range, params []string) {
	if name == "" {
		return
	}
	// A redeclaration keeps the first: that is what the reader of the file sees
	// at the point of an earlier use, and the compiler's own store is written
	// in the same order.
	if _, already := f.Exports[name]; already {
		return
	}
	f.Exports[name] = ExportFact{
		Name:      name,
		Kind:      kind,
		Private:   IsModulePrivate(name),
		DeclRange: declRange,
		Params:    params,
	}
}

func (f *ModuleFacts) addType(name string, kind SymKind, members []*ast.Identifier, declRange ast.Range) {
	if name == "" {
		return
	}
	if _, already := f.Types[name]; already {
		return
	}
	names := make([]string, 0, len(members))
	for _, member := range members {
		if member != nil {
			names = append(names, member.Value)
		}
	}
	f.Types[name] = TypeFact{Name: name, Kind: kind, Members: names, DeclRange: declRange}
}

// computeHash folds the facts in a fixed order so that one file's hash depends
// on what it declares and not on map iteration order, which is randomised.
func (f *ModuleFacts) computeHash() uint64 {
	h := fnv.New64a()
	write := func(parts ...string) {
		for _, part := range parts {
			_, _ = h.Write([]byte(part))
			_, _ = h.Write([]byte{0})
		}
	}

	names := make([]string, 0, len(f.Exports))
	for name := range f.Exports {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		export := f.Exports[name]
		write("e", name, string(rune(export.Kind)))
		write(export.Params...)
	}

	names = names[:0]
	for name := range f.Types {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		declared := f.Types[name]
		write("t", name, string(rune(declared.Kind)))
		write(declared.Members...)
	}

	// Imports stay in source order: reordering two imports genuinely changes
	// nothing, but they are few and comparing them in order is cheaper than
	// sorting a slice on every keystroke.
	for _, imported := range f.Imports {
		write("i", imported.Alias, imported.Spelling)
	}

	return h.Sum64()
}

// ExportedNames returns the names another module may reach through `ns.`,
// sorted, with the module-private ones left out.
//
// This is what SymbolTable.ModuleNames has always returned to nobody: the
// compiler built the list the editor needs and the editor could not reach it.
// The filter is the whole export rule, so it lives in one place -- see
// IsModulePrivate.
func (f *ModuleFacts) ExportedNames() []string {
	if f == nil {
		return nil
	}
	names := make([]string, 0, len(f.Exports))
	for name, export := range f.Exports {
		if export.Private {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
