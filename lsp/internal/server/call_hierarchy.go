package server

import (
	"os"
	"path/filepath"
	"sort"

	mast "mutant/ast"
	"mutant/lsp/internal/analyzer"
	localprotocol "mutant/lsp/internal/protocol"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

// Call hierarchy: who calls this, and what does this call.
//
// The graph is already a call graph -- every reference it records carries the
// declaration it sits inside and whether it stands in a call's function
// position -- so the file-local half is a read, done in the analyzer. This file
// adds the half that crosses a file boundary, which the graph deliberately
// cannot: it holds nothing from another module, so the calls into and out of
// one are assembled from the workspace index at query time.
//
// Query time, and not sooner. A reverse index of "who calls whom" across a
// workspace is the eager bookkeeping sema exists to avoid; this is an explicit
// user action, it is allowed to walk the indexed documents, and it costs
// nothing at all until someone opens the view.
//
// Nothing here carries a sema.DeclID between requests. The protocol hands an
// item back after any number of edits, and a DeclID is valid only inside the
// Graph that minted it -- so what travels is the URI and the position, and the
// declaration is resolved afresh. That is the contract go-to-definition already
// works under, and it is why a file edited between prepare and incomingCalls
// answers about what is there now rather than about what was.

func (s *Server) prepareCallHierarchy(_ *glsp.Context, params *lsp.CallHierarchyPrepareParams) ([]lsp.CallHierarchyItem, error) {
	uri := params.TextDocument.URI
	// snapshotFor rather than the open documents: a hierarchy may be rooted on
	// a declaration in a file nobody has opened -- the editor asks about
	// whatever the cursor reached, including a file it has just navigated to.
	snapshot, ok := s.snapshotFor(uri)
	if !ok || snapshot == nil {
		return nil, nil
	}

	// A reach into another module is resolved first, because the cursor is then
	// on a name this file does not declare and the local graph would answer
	// about the alias instead.
	if _, name, declaration, found := snapshot.ModuleMemberTarget(params.Position); found {
		if item, made := s.callItemInModule(name, declaration.URI); made {
			return []lsp.CallHierarchyItem{item}, nil
		}
	}

	root, found := snapshot.CallHierarchyRootAt(params.Position)
	if !found {
		return nil, nil
	}
	return []lsp.CallHierarchyItem{callItem(root, uri)}, nil
}

func (s *Server) callHierarchyIncomingCalls(_ *glsp.Context, params *lsp.CallHierarchyIncomingCallsParams) ([]lsp.CallHierarchyIncomingCall, error) {
	item := params.Item
	snapshot, ok := s.snapshotFor(item.URI)
	if !ok || snapshot == nil {
		return nil, nil
	}

	position := item.SelectionRange.Start
	calls := make([]lsp.CallHierarchyIncomingCall, 0, 4)
	for _, caller := range snapshot.IncomingCalls(position) {
		calls = append(calls, lsp.CallHierarchyIncomingCall{
			From:       callItem(caller, item.URI),
			FromRanges: lspRanges(caller.CallRanges),
		})
	}

	calls = append(calls, s.crossFileIncomingCalls(snapshot, item, position)...)
	if len(calls) == 0 {
		return nil, nil
	}
	return calls, nil
}

func (s *Server) callHierarchyOutgoingCalls(_ *glsp.Context, params *lsp.CallHierarchyOutgoingCallsParams) ([]lsp.CallHierarchyOutgoingCall, error) {
	item := params.Item
	snapshot, ok := s.snapshotFor(item.URI)
	if !ok || snapshot == nil {
		return nil, nil
	}

	calls := make([]lsp.CallHierarchyOutgoingCall, 0, 4)
	for _, callee := range snapshot.OutgoingCalls(item.SelectionRange.Start) {
		calls = append(calls, lsp.CallHierarchyOutgoingCall{
			To:         callItem(callee, item.URI),
			FromRanges: lspRanges(callee.CallRanges),
		})
	}
	if len(calls) == 0 {
		return nil, nil
	}
	return calls, nil
}

// crossFileIncomingCalls finds the calls into this declaration written in other
// files, and names the declaration each one sits inside.
//
// A call across a file boundary is always `alias.name(...)`: an import binds
// one namespace and nothing else crosses, so there is no bare spelling to look
// for. The index knows where those are written; which declaration contains one
// is a question about THAT file, so its graph is asked, which means reading it.
// That is the cost of an explicit action and is paid nowhere else.
func (s *Server) crossFileIncomingCalls(snapshot *analyzer.Snapshot, item lsp.CallHierarchyItem, position lsp.Position) []lsp.CallHierarchyIncomingCall {
	declared, ok := s.workspaceDeclarationAt(snapshot, item.URI, position)
	if !ok || declared.isType {
		// A type is never called, so there is nothing to look for.
		return nil
	}

	sites := s.symbols.MemberCallSites(s.sema, declared.module, declared.name)
	if len(sites) == 0 {
		return nil
	}

	// Grouped by the declaration that contains them rather than by file, so a
	// file with two functions calling this one contributes two callers.
	type callerKey struct {
		uri  lsp.DocumentUri
		name string
		line lsp.UInteger
	}
	byCaller := make(map[callerKey]*lsp.CallHierarchyIncomingCall, 4)
	order := make([]callerKey, 0, 4)

	for _, site := range sites {
		caller, named := s.callerAt(site)
		if !named {
			continue
		}
		key := callerKey{uri: site.URI, name: caller.Name, line: caller.SelectionRange.Start.Line}
		existing, seen := byCaller[key]
		if !seen {
			order = append(order, key)
			byCaller[key] = &lsp.CallHierarchyIncomingCall{From: caller, FromRanges: []lsp.Range{site.Range}}
			continue
		}
		existing.FromRanges = append(existing.FromRanges, site.Range)
	}

	calls := make([]lsp.CallHierarchyIncomingCall, 0, len(order))
	for _, key := range order {
		calls = append(calls, *byCaller[key])
	}
	sort.SliceStable(calls, func(i, j int) bool {
		if calls[i].From.URI != calls[j].From.URI {
			return calls[i].From.URI < calls[j].From.URI
		}
		return calls[i].From.SelectionRange.Start.Line < calls[j].From.SelectionRange.Start.Line
	})
	return calls
}

// callerAt names the declaration a call site sits inside.
//
// A call written at a file's top level has no enclosing declaration, and the
// graph says so rather than inventing one. The file itself is what makes that
// call, so it is what the item names -- an editor needs something to show, and
// "the file" is true where "some function" would not be.
func (s *Server) callerAt(site lsp.Location) (lsp.CallHierarchyItem, bool) {
	snapshot, ok := s.snapshotFor(site.URI)
	if !ok || snapshot == nil {
		return lsp.CallHierarchyItem{}, false
	}

	line, column := int(site.Range.Start.Line)+1, int(site.Range.Start.Character)+1
	if caller, found := snapshot.EnclosingCallNodeAt(line, column); found {
		return callItem(caller, site.URI), true
	}

	name := "<file>"
	if path, converted := uriToPath(site.URI); converted {
		name = filepath.Base(path)
	}
	return lsp.CallHierarchyItem{
		Name:           name,
		Kind:           lsp.SymbolKindFile,
		URI:            site.URI,
		Range:          site.Range,
		SelectionRange: site.Range,
	}, true
}

// callItemInModule makes an item for a declaration in another file, which is
// what the cursor is on when it is on `stats.mean`.
func (s *Server) callItemInModule(name string, uri lsp.DocumentUri) (lsp.CallHierarchyItem, bool) {
	snapshot, ok := s.snapshotFor(uri)
	if !ok || snapshot == nil {
		return lsp.CallHierarchyItem{}, false
	}
	declared, found := snapshot.DeclarationCallNode(name)
	if !found {
		return lsp.CallHierarchyItem{}, false
	}
	return callItem(declared, uri), true
}

// snapshotFor returns an analysis of a document whether or not it is open.
//
// The open ones are the server's; the rest are on disk, and a call hierarchy is
// the one place that matters -- the file calling yours is very often one nobody
// has opened. It is read here rather than kept, because keeping a snapshot per
// scanned file is memory spent on a question almost nobody asks.
func (s *Server) snapshotFor(uri lsp.DocumentUri) (*analyzer.Snapshot, bool) {
	if snapshot, ok := s.snapshot(uri); ok && snapshot != nil {
		return snapshot, true
	}
	if doc, ok := s.documents.Snapshot(uri); ok && doc != nil {
		return s.analyzeDoc(uri, doc.Text), true
	}
	path, ok := uriToPath(uri)
	if !ok {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return s.analyzeDoc(uri, string(data)), true
}

func callItem(node analyzer.CallNode, uri lsp.DocumentUri) lsp.CallHierarchyItem {
	rng := node.Range
	if !rng.IsValid() {
		rng = node.SelectionRange
	}
	selection := node.SelectionRange
	if !selection.IsValid() {
		selection = rng
	}
	return lsp.CallHierarchyItem{
		Name:           node.Name,
		Kind:           node.Kind,
		URI:            uri,
		Range:          localprotocol.ToLSPRange(rng),
		SelectionRange: localprotocol.ToLSPRange(selection),
	}
}

func lspRanges(ranges []mast.Range) []lsp.Range {
	out := make([]lsp.Range, 0, len(ranges))
	for _, rng := range ranges {
		out = append(out, localprotocol.ToLSPRange(rng))
	}
	return out
}
