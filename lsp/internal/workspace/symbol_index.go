package workspace

import (
	"sort"
	"strings"
	"sync"

	mast "mutant/ast"
	"mutant/lsp/internal/analyzer"
	localprotocol "mutant/lsp/internal/protocol"
	"mutant/sema"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// What this index knows is where names are written. What a name *means* is
// sema's to say, and this file no longer has an opinion about it.
//
// It used to. UniqueTopLevelDefinition answered "where is this declared?" by
// matching the string against every indexed document, and ReferenceLocations
// answered "where else is it used?" the same way. Neither knew what an import
// was, so both were wrong in ways a user met daily: go-to-definition jumped
// into modules nothing had imported, `_private` resolved across files that the
// compiler refuses, and two modules legally declaring one name made both
// unresolvable because the ambiguity was bailed on rather than scoped away.
//
// The replacement keeps the collection -- somebody has to walk the documents --
// and hands every question of visibility to sema.Workspace, which knows what an
// import binds.

type SymbolIndex struct {
	mu   sync.RWMutex
	docs map[lsp.DocumentUri]indexedDocument
}

type indexedDocument struct {
	topLevel []indexedTopLevelSymbol

	// bare is every identifier written on its own, and member every `a.b`
	// written as a reach through a name. They are collected without resolving
	// anything: resolution needs the workspace, which needs the other documents,
	// and this runs once per document as it is indexed.
	bare   []indexedUsage
	member []indexedMemberUsage
}

type indexedTopLevelSymbol struct {
	name string
	kind lsp.SymbolKind
	rng  lsp.Range
}

type indexedUsage struct {
	name string
	rng  lsp.Range
}

type indexedMemberUsage struct {
	// left is the name before the dot as written -- an import alias if this
	// document imports one by that name, and otherwise something else entirely.
	// Deciding which is sema's job and is done at query time.
	left   string
	member string

	// rng covers the member name alone, not the whole expression: renaming
	// `mean` must not eat the `stats.` in front of it.
	rng lsp.Range

	// inCall reports that the whole `a.b` stood in the function position of a
	// call. A call hierarchy needs it and find-references must not: `stats.mean`
	// written without calling it is a use of the name and is not an edge in the
	// call graph.
	inCall bool
}

func NewSymbolIndex() *SymbolIndex {
	return &SymbolIndex{docs: make(map[lsp.DocumentUri]indexedDocument)}
}

func (i *SymbolIndex) Update(uri lsp.DocumentUri, snapshot *analyzer.Snapshot) {
	if i == nil {
		return
	}
	if snapshot == nil || snapshot.Program == nil {
		i.Delete(uri)
		return
	}

	bare, member := collectUsages(snapshot)
	doc := indexedDocument{
		topLevel: collectTopLevelSymbols(snapshot),
		bare:     bare,
		member:   member,
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	i.docs[uri] = doc
}

func (i *SymbolIndex) Delete(uri lsp.DocumentUri) {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.docs, uri)
}

// ReferencesTo collects every use of one declaration that is written in a file
// other than the one declaring it.
//
// The declaration is named by the module it is in rather than by a URI, because
// that is what sema answers about. The file-local uses are the snapshot's to
// find; this adds only what crosses a file boundary, and there are exactly two
// ways for a use to do that:
//
//   - a type, written bare. Struct and enum names are program-global, so `Point`
//     in an importing file is a use of the `Point` another file declares.
//   - a value, written `alias.name`, where alias is an import bound to the
//     declaring module in the file doing the writing. Never bare: an import
//     binds one namespace and nothing else crosses.
//
// Both are restricted to modules whose closure contains the declaring one. A
// file that does not import it, directly or transitively, cannot be referring
// to it however exactly its spelling matches.
func (i *SymbolIndex) ReferencesTo(w *sema.Workspace, declModule, name string, writtenBare bool, declaration *lsp.Location, includeDeclaration bool) []lsp.Location {
	if i == nil || w == nil || declModule == "" || name == "" {
		return nil
	}

	locations := make([]lsp.Location, 0, 4)
	seen := make(map[lsp.Location]struct{}, 8)
	add := func(location lsp.Location) {
		if _, already := seen[location]; already {
			return
		}
		seen[location] = struct{}{}
		locations = append(locations, location)
	}

	if includeDeclaration && declaration != nil {
		add(*declaration)
	}

	// Importers is the reverse of the closure, computed rather than stored --
	// see sema.Workspace.Importers for why that trade is the right way round.
	reachers := make(map[string]bool, 8)
	for _, key := range w.Importers(declModule) {
		reachers[key] = true
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	for uri, doc := range i.docs {
		key, known := w.KeyForURI(string(uri))
		if !known || key == declModule || !reachers[key] {
			continue
		}

		if writtenBare {
			// A document that declares the name itself is talking about its own,
			// whatever the type table says. This cannot happen for two types --
			// claimTypeName refuses that program -- but a `let Point` shadows in
			// the value namespace and its uses are not uses of the struct, and
			// two modules may both declare a macro of one name.
			if declaresTopLevel(doc, name) {
				continue
			}
			for _, usage := range doc.bare {
				if usage.name == name {
					add(lsp.Location{URI: uri, Range: usage.rng})
				}
			}
			continue
		}

		forEachMemberUseLocked(w, key, declModule, name, doc, func(usage indexedMemberUsage) {
			add(lsp.Location{URI: uri, Range: usage.rng})
		})
	}

	sortLocations(locations)
	if len(locations) == 0 {
		return nil
	}
	return locations
}

// forEachMemberUseLocked visits every `alias.name` in one document where alias
// is an import bound to declModule. The caller holds the read lock: taking it
// again here would be a second RLock on a mutex a writer may be queued behind,
// which is the documented way to deadlock a sync.RWMutex.
func forEachMemberUseLocked(w *sema.Workspace, key, declModule, name string, doc indexedDocument, visit func(indexedMemberUsage)) {
	for _, alias := range w.AliasesFor(key, declModule) {
		for _, usage := range doc.member {
			if usage.left == alias && usage.member == name {
				visit(usage)
			}
		}
	}
}

// MemberCallSites returns the places in other files where the declaration is
// CALLED, as against merely named.
//
// It is ReferencesTo narrowed twice: to member uses, because a call into
// another module is always written `alias.name(...)` -- an import binds one
// namespace and nothing else crosses, so there is no bare spelling to find --
// and to the ones standing in a call's function position.
//
// A type is not here at all. Struct and enum names do cross files bare, and
// nothing calls them.
func (i *SymbolIndex) MemberCallSites(w *sema.Workspace, declModule, name string) []lsp.Location {
	if i == nil || w == nil || declModule == "" || name == "" {
		return nil
	}

	locations := make([]lsp.Location, 0, 4)
	seen := make(map[lsp.Location]struct{}, 8)

	i.mu.RLock()
	defer i.mu.RUnlock()

	// No Importers walk, deliberately, where ReferencesTo has one. That filter
	// is what scopes the TYPE branch, which has no alias to go on -- a bare
	// `Point` looks the same in every file. A member use is already scoped by
	// the alias: AliasesFor answers about imports bound to this module and
	// returns nothing for a file that does not import it, so asking twice
	// narrows nothing and cannot be made to fail.
	for uri, doc := range i.docs {
		key, known := w.KeyForURI(string(uri))
		if !known || key == declModule {
			continue
		}
		forEachMemberUseLocked(w, key, declModule, name, doc, func(usage indexedMemberUsage) {
			if !usage.inCall {
				return
			}
			location := lsp.Location{URI: uri, Range: usage.rng}
			if _, already := seen[location]; already {
				return
			}
			seen[location] = struct{}{}
			locations = append(locations, location)
		})
	}

	sortLocations(locations)
	if len(locations) == 0 {
		return nil
	}
	return locations
}

func (i *SymbolIndex) WorkspaceSymbols(query string, limit int) []lsp.SymbolInformation {
	if i == nil {
		return nil
	}

	q := strings.TrimSpace(strings.ToLower(query))
	if limit <= 0 {
		limit = 100
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	results := make([]lsp.SymbolInformation, 0, limit)
	for uri, doc := range i.docs {
		for _, symbol := range doc.topLevel {
			if !isWorkspaceResolvableTopLevelKind(symbol.kind) {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(symbol.name), q) {
				continue
			}

			results = append(results, lsp.SymbolInformation{
				Name: symbol.name,
				Kind: symbol.kind,
				Location: lsp.Location{
					URI:   uri,
					Range: symbol.rng,
				},
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Name != results[j].Name {
			return results[i].Name < results[j].Name
		}
		if results[i].Location.URI != results[j].Location.URI {
			return results[i].Location.URI < results[j].Location.URI
		}
		if results[i].Location.Range.Start.Line != results[j].Location.Range.Start.Line {
			return results[i].Location.Range.Start.Line < results[j].Location.Range.Start.Line
		}
		return results[i].Location.Range.Start.Character < results[j].Location.Range.Start.Character
	})

	if len(results) > limit {
		results = results[:limit]
	}
	if len(results) == 0 {
		return nil
	}
	return results
}

// TopLevelKind reports how a document declares a top-level name, so a caller can
// tell a struct from a value without walking the document again.
func (i *SymbolIndex) TopLevelKind(uri lsp.DocumentUri, name string) (lsp.SymbolKind, bool) {
	if i == nil {
		return 0, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()

	for _, symbol := range i.docs[uri].topLevel {
		if symbol.name == name {
			return symbol.kind, true
		}
	}
	return 0, false
}

func declaresTopLevel(doc indexedDocument, name string) bool {
	for _, symbol := range doc.topLevel {
		if symbol.name == name {
			return true
		}
	}
	return false
}

func collectTopLevelSymbols(snapshot *analyzer.Snapshot) []indexedTopLevelSymbol {
	if snapshot == nil || snapshot.Program == nil {
		return nil
	}

	symbols := snapshot.DocumentSymbols()
	result := make([]indexedTopLevelSymbol, 0, len(symbols))
	for _, symbol := range symbols {
		if !isWorkspaceResolvableTopLevelKind(symbol.Kind) {
			continue
		}
		result = append(result, indexedTopLevelSymbol{name: symbol.Name, kind: symbol.Kind, rng: symbol.SelectionRange})
	}
	return result
}

// collectUsages records where names are written, and decides nothing.
//
// Its one piece of syntax-level judgement is which identifiers are bare. The
// `mean` in `stats.mean` is an identifier with a position of its own, but it is
// not a name written on its own: nothing in this file could declare it, and
// counting it as bare would make a rename of some unrelated `mean` reach into
// the middle of a namespaced call.
func collectUsages(snapshot *analyzer.Snapshot) ([]indexedUsage, []indexedMemberUsage) {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil, nil
	}
	positions := snapshot.Program.NodePositions

	fields := make(map[*mast.Identifier]struct{}, 8)
	// callees is every expression standing in the function position of a call,
	// which is how a member use is told from a member call. It is gathered in
	// the same pass as the field names because both are questions about a
	// node's PARENT, and the positions map is the only place the parents are.
	callees := make(map[mast.Expression]struct{}, 8)
	for node := range positions {
		switch typed := node.(type) {
		case *mast.FieldExpression:
			if typed != nil && typed.Field != nil {
				fields[typed.Field] = struct{}{}
			}
		case *mast.CallExpression:
			if typed != nil && typed.Function != nil {
				callees[typed.Function] = struct{}{}
			}
		}
	}

	bare := make([]indexedUsage, 0, len(positions)/4)
	member := make([]indexedMemberUsage, 0, 4)
	for node, rng := range positions {
		if !rng.IsValid() {
			continue
		}
		switch typed := node.(type) {
		case *mast.Identifier:
			if typed == nil || typed.Value == "" {
				continue
			}
			if _, isFieldName := fields[typed]; isFieldName {
				continue
			}
			bare = append(bare, indexedUsage{name: typed.Value, rng: localprotocol.ToLSPRange(rng)})
		case *mast.FieldExpression:
			if typed == nil || typed.Field == nil {
				continue
			}
			left, isIdent := typed.Left.(*mast.Identifier)
			if !isIdent || left == nil {
				continue
			}
			fieldRange, known := positions[typed.Field]
			if !known || !fieldRange.IsValid() {
				continue
			}
			_, isCall := callees[mast.Expression(typed)]
			member = append(member, indexedMemberUsage{
				left:   left.Value,
				member: typed.Field.Value,
				rng:    localprotocol.ToLSPRange(fieldRange),
				inCall: isCall,
			})
		}
	}

	return bare, member
}

func isWorkspaceResolvableTopLevelKind(kind lsp.SymbolKind) bool {
	switch kind {
	case lsp.SymbolKindVariable, lsp.SymbolKindFunction, lsp.SymbolKindStruct, lsp.SymbolKindEnum:
		return true
	default:
		return false
	}
}

// IsTypeKind reports whether a symbol kind is one that is written bare across
// module boundaries. It is here rather than in the server because it is the
// same question isWorkspaceResolvableTopLevelKind answers, narrowed.
//
// It covers the two kinds the protocol has a name for. A macro is written
// bare too and is not an lsp.SymbolKind of its own, so it is decided by
// sema.Workspace.ResolveMacro rather than here.
func IsTypeKind(kind lsp.SymbolKind) bool {
	return kind == lsp.SymbolKindStruct || kind == lsp.SymbolKindEnum
}

// sortLocations gives the result a stable order. The index is a map, so without
// this the same query returns its answers shuffled, which a client renders as
// the references list reordering itself between identical requests.
func sortLocations(locations []lsp.Location) {
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].URI != locations[j].URI {
			return locations[i].URI < locations[j].URI
		}
		if locations[i].Range.Start.Line != locations[j].Range.Start.Line {
			return locations[i].Range.Start.Line < locations[j].Range.Start.Line
		}
		return locations[i].Range.Start.Character < locations[j].Range.Start.Character
	})
}
