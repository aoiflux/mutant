package workspace

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	mast "mutant/ast"
	"mutant/lsp/internal/analyzer"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

type SymbolIndex struct {
	mu   sync.RWMutex
	docs map[lsp.DocumentUri]indexedDocument
}

type indexedDocument struct {
	topLevel   []indexedTopLevelSymbol
	unresolved []indexedIdentifierUsage
}

type indexedTopLevelSymbol struct {
	name string
	kind lsp.SymbolKind
	rng  lsp.Range
}

type indexedIdentifierUsage struct {
	name     string
	location lsp.Location
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

	doc := indexedDocument{
		topLevel:   collectTopLevelSymbols(snapshot),
		unresolved: collectUnresolvedIdentifierUsages(uri, snapshot),
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

func (i *SymbolIndex) UniqueTopLevelDefinition(name string, sourceURI lsp.DocumentUri) (*lsp.Location, bool) {
	if i == nil || name == "" {
		return nil, false
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	var match *lsp.Location
	for uri, doc := range i.docs {
		if sourceURI != "" && uri == sourceURI {
			continue
		}
		for _, symbol := range doc.topLevel {
			if symbol.name != name || !isWorkspaceResolvableTopLevelKind(symbol.kind) {
				continue
			}
			candidate := &lsp.Location{URI: uri, Range: symbol.rng}
			if match != nil {
				return nil, false
			}
			match = candidate
		}
	}

	if match == nil {
		return nil, false
	}
	clone := *match
	return &clone, true
}

func (i *SymbolIndex) ReferenceLocations(name string, declaration *lsp.Location, includeDeclaration bool) []lsp.Location {
	if i == nil || name == "" {
		return nil
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	locations := make([]lsp.Location, 0, 4)
	seen := make(map[string]struct{})

	if includeDeclaration && declaration != nil {
		locations = append(locations, *declaration)
		seen[locationKey(*declaration)] = struct{}{}
	}

	for _, doc := range i.docs {
		for _, usage := range doc.unresolved {
			if usage.name != name {
				continue
			}
			key := locationKey(usage.location)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			locations = append(locations, usage.location)
		}
	}

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

func collectUnresolvedIdentifierUsages(uri lsp.DocumentUri, snapshot *analyzer.Snapshot) []indexedIdentifierUsage {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	declaredNames := collectDeclaredIdentifierNames(snapshot)
	usages := make([]indexedIdentifierUsage, 0, len(snapshot.Program.NodePositions)/4)
	for node, rng := range snapshot.Program.NodePositions {
		ident, ok := node.(*mast.Identifier)
		if !ok || ident == nil || ident.Value == "" || !rng.IsValid() {
			continue
		}

		// Fast path: if the name is never declared in this document, the identifier
		// cannot resolve to a local definition.
		if _, declared := declaredNames[ident.Value]; declared {
			pos := lsp.Position{Line: lsp.UInteger(rng.Start.Line - 1), Character: lsp.UInteger(rng.Start.Column - 1)}
			if _, ok := snapshot.DefinitionLocation(uri, pos); ok {
				continue
			}
		}

		usages = append(usages, indexedIdentifierUsage{
			name: ident.Value,
			location: lsp.Location{
				URI:   uri,
				Range: localprotocol.ToLSPRange(rng),
			},
		})
	}
	return usages
}

func collectDeclaredIdentifierNames(snapshot *analyzer.Snapshot) map[string]struct{} {
	declared := make(map[string]struct{})
	if snapshot == nil || snapshot.Program == nil {
		return declared
	}
	for _, stmt := range snapshot.Program.Statements {
		markDeclaredInStatement(stmt, declared)
	}
	return declared
}

func markDeclaredInStatement(stmt mast.Statement, declared map[string]struct{}) {
	if isNilInterface(stmt) {
		return
	}

	switch node := stmt.(type) {
	case *mast.LetStatement:
		names := node.Names
		if len(names) == 0 && node.Name != nil {
			names = []*mast.Identifier{node.Name}
		}
		for _, ident := range names {
			if ident != nil && ident.Value != "" {
				declared[ident.Value] = struct{}{}
			}
		}
		if node.Value != nil {
			markDeclaredInExpression(node.Value, declared)
		}
	case *mast.StructStatement:
		if node.Name != nil && node.Name.Value != "" {
			declared[node.Name.Value] = struct{}{}
		}
		for _, field := range node.Fields {
			if field != nil && field.Value != "" {
				declared[field.Value] = struct{}{}
			}
		}
	case *mast.EnumStatement:
		if node.Name != nil && node.Name.Value != "" {
			declared[node.Name.Value] = struct{}{}
		}
		for _, variant := range node.Variants {
			if variant != nil && variant.Value != "" {
				declared[variant.Value] = struct{}{}
			}
		}
	case *mast.ReturnStatement:
		for _, expr := range node.ReturnValues {
			markDeclaredInExpression(expr, declared)
		}
		if len(node.ReturnValues) == 0 && node.ReturnValue != nil {
			markDeclaredInExpression(node.ReturnValue, declared)
		}
	case *mast.ExpressionStatement:
		if node.Expression != nil {
			markDeclaredInExpression(node.Expression, declared)
		}
	case *mast.BlockStatement:
		for _, inner := range node.Statements {
			markDeclaredInStatement(inner, declared)
		}
	case *mast.ForStatement:
		if node.Init != nil {
			markDeclaredInStatement(node.Init, declared)
		}
		if node.Condition != nil {
			markDeclaredInExpression(node.Condition, declared)
		}
		if node.Post != nil {
			markDeclaredInExpression(node.Post, declared)
		}
		if node.Body != nil {
			markDeclaredInStatement(node.Body, declared)
		}
	}
}

func markDeclaredInExpression(expr mast.Expression, declared map[string]struct{}) {
	if isNilInterface(expr) {
		return
	}

	switch node := expr.(type) {
	case *mast.FunctionLiteral:
		for _, param := range node.Parameters {
			if param != nil && param.Value != "" {
				declared[param.Value] = struct{}{}
			}
		}
		if node.Body != nil {
			markDeclaredInStatement(node.Body, declared)
		}
	case *mast.MacroLiteral:
		for _, param := range node.Parameters {
			if param != nil && param.Value != "" {
				declared[param.Value] = struct{}{}
			}
		}
		if node.Body != nil {
			markDeclaredInStatement(node.Body, declared)
		}
	case *mast.IfExpression:
		if node.Condition != nil {
			markDeclaredInExpression(node.Condition, declared)
		}
		if node.Consequence != nil {
			markDeclaredInStatement(node.Consequence, declared)
		}
		if node.Alternative != nil {
			markDeclaredInStatement(node.Alternative, declared)
		}
	case *mast.CallExpression:
		if node.Function != nil {
			markDeclaredInExpression(node.Function, declared)
		}
		for _, arg := range node.Arguments {
			markDeclaredInExpression(arg, declared)
		}
	case *mast.PrefixExpression:
		if node.Right != nil {
			markDeclaredInExpression(node.Right, declared)
		}
	case *mast.InfixExpression:
		if node.Left != nil {
			markDeclaredInExpression(node.Left, declared)
		}
		if node.Right != nil {
			markDeclaredInExpression(node.Right, declared)
		}
	case *mast.IndexExpression:
		if node.Left != nil {
			markDeclaredInExpression(node.Left, declared)
		}
		if node.Index != nil {
			markDeclaredInExpression(node.Index, declared)
		}
	case *mast.AssignExpression:
		if node.Left != nil {
			markDeclaredInExpression(node.Left, declared)
		}
		if node.Value != nil {
			markDeclaredInExpression(node.Value, declared)
		}
	case *mast.FieldExpression:
		if node.Left != nil {
			markDeclaredInExpression(node.Left, declared)
		}
	case *mast.StructLiteral:
		if node.Name != nil {
			markDeclaredInExpression(node.Name, declared)
		}
		for _, field := range node.Fields {
			if field != nil && field.Value != nil {
				markDeclaredInExpression(field.Value, declared)
			}
		}
	case *mast.ArrayLiteral:
		for _, element := range node.Elements {
			markDeclaredInExpression(element, declared)
		}
	case *mast.HashLiteral:
		for key, value := range node.Pairs {
			markDeclaredInExpression(key, declared)
			markDeclaredInExpression(value, declared)
		}
	}
}

func isWorkspaceResolvableTopLevelKind(kind lsp.SymbolKind) bool {
	switch kind {
	case lsp.SymbolKindVariable, lsp.SymbolKindFunction, lsp.SymbolKindStruct, lsp.SymbolKindEnum:
		return true
	default:
		return false
	}
}

func locationKey(location lsp.Location) string {
	return fmt.Sprintf("%s:%d:%d:%d:%d", location.URI, location.Range.Start.Line, location.Range.Start.Character, location.Range.End.Line, location.Range.End.Character)
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
