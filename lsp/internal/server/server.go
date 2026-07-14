package server

import (
	"fmt"
	"log"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"unicode"

	mast "mutant/ast"
	"mutant/builtin"
	"mutant/lsp/internal/analyzer"
	localprotocol "mutant/lsp/internal/protocol"
	"mutant/lsp/internal/workspace"
	"mutant/token"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

const (
	serverName    = "mlsp"
	serverVersion = "0.1.0"
)

type Server struct {
	handler   *lsp.Handler
	documents *workspace.Store
	symbols   *workspace.SymbolIndex
	analyzer  *analyzer.Analyzer

	mu                     sync.RWMutex
	snapshots              map[lsp.DocumentUri]*analyzer.Snapshot
	lintConfig             analyzer.LintConfig
	shutdown               bool
	semanticFallbackWarned bool
}

func New(debug bool) *Server {
	handler := &lsp.Handler{}
	s := &Server{
		handler:    handler,
		documents:  workspace.NewStore(),
		symbols:    workspace.NewSymbolIndex(),
		analyzer:   analyzer.New(),
		snapshots:  make(map[lsp.DocumentUri]*analyzer.Snapshot),
		lintConfig: analyzer.DefaultLintConfig(),
	}
	_ = debug

	handler.Initialize = s.initialize
	handler.Initialized = s.initialized
	handler.WorkspaceDidChangeConfiguration = s.didChangeConfiguration
	handler.Shutdown = s.shutdownRequest
	handler.Exit = s.exit
	handler.TextDocumentDidOpen = s.didOpen
	handler.TextDocumentDidChange = s.didChange
	handler.TextDocumentDidClose = s.didClose
	handler.TextDocumentHover = s.hover
	handler.TextDocumentCompletion = s.completion
	handler.TextDocumentSignatureHelp = s.signatureHelp
	handler.TextDocumentCodeAction = s.codeActions
	handler.TextDocumentDocumentHighlight = s.documentHighlights
	handler.TextDocumentDocumentSymbol = s.documentSymbols
	handler.TextDocumentDefinition = s.definition
	handler.TextDocumentTypeDefinition = s.typeDefinition
	handler.TextDocumentReferences = s.references
	handler.TextDocumentPrepareRename = s.prepareRename
	handler.TextDocumentRename = s.rename
	handler.TextDocumentSemanticTokensFull = s.semanticTokensFull
	handler.TextDocumentFormatting = s.formatting
	handler.TextDocumentOnTypeFormatting = s.onTypeFormatting
	handler.WorkspaceSymbol = s.workspaceSymbols

	return s
}

func (s *Server) Run() error {
	return runOverStdio(s.handler)
}

func (s *Server) initialize(_ *glsp.Context, _ *lsp.InitializeParams) (any, error) {
	syncKind := lsp.TextDocumentSyncKindIncremental
	openClose := true
	hover := true
	docSymbols := true
	completion := &lsp.CompletionOptions{TriggerCharacters: []string{".", ":"}}
	signatureHelp := &lsp.SignatureHelpOptions{TriggerCharacters: []string{"(", ","}, RetriggerCharacters: []string{","}}
	onTypeFormatting := &lsp.DocumentOnTypeFormattingOptions{FirstTriggerCharacter: "}", MoreTriggerCharacter: []string{";", "\n"}}
	semanticTokens := &lsp.SemanticTokensOptions{
		Legend: analyzer.SemanticTokenLegend(),
		Full:   true,
	}

	result := &lsp.InitializeResult{
		Capabilities: lsp.ServerCapabilities{
			TextDocumentSync: &lsp.TextDocumentSyncOptions{
				OpenClose: &openClose,
				Change:    &syncKind,
			},
			HoverProvider:                    hover,
			CompletionProvider:               completion,
			SignatureHelpProvider:            signatureHelp,
			CodeActionProvider:               true,
			DocumentHighlightProvider:        true,
			WorkspaceSymbolProvider:          true,
			DefinitionProvider:               true,
			TypeDefinitionProvider:           true,
			ReferencesProvider:               true,
			RenameProvider:                   true,
			DocumentSymbolProvider:           docSymbols,
			SemanticTokensProvider:           semanticTokens,
			DocumentFormattingProvider:       true,
			DocumentOnTypeFormattingProvider: onTypeFormatting,
		},
		ServerInfo: &lsp.InitializeResultServerInfo{
			Name:    serverName,
			Version: strptr(serverVersion),
		},
	}

	return result, nil
}

func (s *Server) initialized(_ *glsp.Context, _ *lsp.InitializedParams) error {
	return nil
}

func (s *Server) didChangeConfiguration(ctx *glsp.Context, params *lsp.DidChangeConfigurationParams) error {
	s.setLintConfig(parseLintConfig(params.Settings))
	s.republishAllDiagnostics(ctx)
	return nil
}

func (s *Server) shutdownRequest(_ *glsp.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdown = true
	return nil
}

func (s *Server) exit(_ *glsp.Context) error {
	return nil
}

func (s *Server) didOpen(ctx *glsp.Context, params *lsp.DidOpenTextDocumentParams) error {
	doc := s.documents.Open(params.TextDocument.URI, lsp.UInteger(params.TextDocument.Version), params.TextDocument.Text)
	snapshot := s.analyzer.Analyze(doc.Text)
	s.setSnapshot(doc.URI, snapshot)
	s.publishDiagnostics(ctx, doc.URI, doc.Version, snapshot)
	return nil
}

func (s *Server) didChange(ctx *glsp.Context, params *lsp.DidChangeTextDocumentParams) error {
	doc, err := s.documents.Update(params.TextDocument.URI, lsp.UInteger(params.TextDocument.Version), params.ContentChanges)
	if err != nil {
		return err
	}
	snapshot := s.analyzer.Analyze(doc.Text)
	s.setSnapshot(doc.URI, snapshot)
	s.publishDiagnostics(ctx, doc.URI, doc.Version, snapshot)
	return nil
}

func (s *Server) didClose(ctx *glsp.Context, params *lsp.DidCloseTextDocumentParams) error {
	s.documents.Close(params.TextDocument.URI)
	s.mu.Lock()
	delete(s.snapshots, params.TextDocument.URI)
	s.mu.Unlock()
	s.safeSymbolDelete(params.TextDocument.URI)
	s.publishDiagnostics(ctx, params.TextDocument.URI, 0, &analyzer.Snapshot{})
	return nil
}

func (s *Server) hover(_ *glsp.Context, params *lsp.HoverParams) (*lsp.Hover, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	text, rng, ok := snapshot.HoverText(params.Position)
	if !ok {
		return nil, nil
	}
	return &lsp.Hover{
		Contents: lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: text},
		Range:    rangePtr(localprotocol.ToLSPRange(rng)),
	}, nil
}

func (s *Server) completion(_ *glsp.Context, params *lsp.CompletionParams) (any, error) {
	snapshot, _ := s.snapshot(params.TextDocument.URI)
	items := analyzer.New().Analyze("").CompletionItems()
	if snapshot != nil {
		items = snapshot.CompletionItemsAt(params.Position)
	}
	return &lsp.CompletionList{IsIncomplete: false, Items: items}, nil
}

func (s *Server) signatureHelp(_ *glsp.Context, params *lsp.SignatureHelpParams) (*lsp.SignatureHelp, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	help, ok := snapshot.SignatureHelp(params.Position)
	if !ok {
		return nil, nil
	}
	return help, nil
}

func (s *Server) codeActions(_ *glsp.Context, params *lsp.CodeActionParams) (any, error) {
	doc, ok := s.documents.Snapshot(params.TextDocument.URI)
	if !ok || doc == nil {
		return nil, nil
	}
	snapshot, _ := s.snapshot(params.TextDocument.URI)

	actions := make([]lsp.CodeAction, 0, len(params.Context.Diagnostics))
	for _, diagnostic := range params.Context.Diagnostics {
		if diagnosticActions := quickFixesForDiagnostic(params.TextDocument.URI, doc.Text, snapshot, diagnostic); len(diagnosticActions) > 0 {
			actions = append(actions, diagnosticActions...)
		}
	}

	if len(actions) == 0 {
		return nil, nil
	}
	return actions, nil
}

func (s *Server) documentHighlights(_ *glsp.Context, params *lsp.DocumentHighlightParams) ([]lsp.DocumentHighlight, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	highlights, ok := snapshot.DocumentHighlights(params.TextDocument.URI, params.Position)
	if !ok {
		return nil, nil
	}
	return highlights, nil
}

func (s *Server) workspaceSymbols(_ *glsp.Context, params *lsp.WorkspaceSymbolParams) ([]lsp.SymbolInformation, error) {
	if s.symbols == nil {
		return nil, nil
	}
	return s.symbols.WorkspaceSymbols(params.Query, 100), nil
}

func quickFixesForDiagnostic(uri lsp.DocumentUri, text string, snapshot *analyzer.Snapshot, diagnostic lsp.Diagnostic) []lsp.CodeAction {
	if diagnostic.Source == nil {
		return nil
	}

	kind := lsp.CodeActionKindQuickFix
	preferred := true
	actions := make([]lsp.CodeAction, 0, 2)

	if *diagnostic.Source == "mutant-lint" {
		if strings.HasPrefix(diagnostic.Message, "duplicate top-level declaration `") {
			rng, ok := lineDeleteRange(text, diagnostic.Range.Start.Line)
			if !ok {
				return nil
			}
			actions = append(actions, lsp.CodeAction{
				Title:       "Remove duplicate top-level declaration",
				Kind:        &kind,
				Diagnostics: []lsp.Diagnostic{diagnostic},
				IsPreferred: &preferred,
				Edit: &lsp.WorkspaceEdit{Changes: map[lsp.DocumentUri][]lsp.TextEdit{
					uri: {{Range: rng, NewText: ""}},
				}},
			})
			return actions
		}

		if strings.HasPrefix(diagnostic.Message, "unused declaration `") {
			rng, ok := lineDeleteRange(text, diagnostic.Range.Start.Line)
			if !ok {
				return nil
			}
			actions = append(actions, lsp.CodeAction{
				Title:       "Remove unused declaration",
				Kind:        &kind,
				Diagnostics: []lsp.Diagnostic{diagnostic},
				IsPreferred: &preferred,
				Edit: &lsp.WorkspaceEdit{Changes: map[lsp.DocumentUri][]lsp.TextEdit{
					uri: {{Range: rng, NewText: ""}},
				}},
			})
			return actions
		}

		if strings.HasPrefix(diagnostic.Message, "undefined identifier `") {
			actions = append(actions, quickFixesForUndefinedIdentifier(uri, text, snapshot, diagnostic)...)
			if len(actions) > 0 {
				return actions
			}
		}
	}

	if *diagnostic.Source == "mutant-parser" && strings.Contains(diagnostic.Message, "expected next token to be ;") {
		insertAt := diagnostic.Range.Start
		actions = append(actions, lsp.CodeAction{
			Title:       "Insert missing ';'",
			Kind:        &kind,
			Diagnostics: []lsp.Diagnostic{diagnostic},
			IsPreferred: &preferred,
			Edit: &lsp.WorkspaceEdit{Changes: map[lsp.DocumentUri][]lsp.TextEdit{
				uri: {{Range: lsp.Range{Start: insertAt, End: insertAt}, NewText: ";"}},
			}},
		})
		return actions
	}

	if *diagnostic.Source == "mutant-parser" && strings.HasPrefix(diagnostic.Message, "no prefix parse function for ") {
		actions = append(actions, lsp.CodeAction{
			Title:       "Remove unexpected token",
			Kind:        &kind,
			Diagnostics: []lsp.Diagnostic{diagnostic},
			IsPreferred: &preferred,
			Edit: &lsp.WorkspaceEdit{Changes: map[lsp.DocumentUri][]lsp.TextEdit{
				uri: {{Range: diagnostic.Range, NewText: ""}},
			}},
		})
		return actions
	}

	return nil
}

func quickFixesForUndefinedIdentifier(uri lsp.DocumentUri, text string, snapshot *analyzer.Snapshot, diagnostic lsp.Diagnostic) []lsp.CodeAction {
	name, ok := diagnosticBacktickName(diagnostic.Message)
	if !ok || name == "" {
		return nil
	}

	kind := lsp.CodeActionKindQuickFix
	preferred := true
	actions := make([]lsp.CodeAction, 0, 2)

	if insertAt, ok := lineStartPosition(text, diagnostic.Range.Start.Line); ok {
		actions = append(actions, lsp.CodeAction{
			Title:       fmt.Sprintf("Create declaration `%s`", name),
			Kind:        &kind,
			Diagnostics: []lsp.Diagnostic{diagnostic},
			IsPreferred: &preferred,
			Edit: &lsp.WorkspaceEdit{Changes: map[lsp.DocumentUri][]lsp.TextEdit{
				uri: {{Range: lsp.Range{Start: insertAt, End: insertAt}, NewText: fmt.Sprintf("let %s = 0;\n", name)}},
			}},
		})
	}

	candidates := symbolCandidatesAt(snapshot, diagnostic.Range.Start)
	if nearest, ok := nearestIdentifierCandidate(name, candidates); ok && nearest != name {
		actions = append(actions, lsp.CodeAction{
			Title:       fmt.Sprintf("Replace with `%s`", nearest),
			Kind:        &kind,
			Diagnostics: []lsp.Diagnostic{diagnostic},
			Edit: &lsp.WorkspaceEdit{Changes: map[lsp.DocumentUri][]lsp.TextEdit{
				uri: {{Range: diagnostic.Range, NewText: nearest}},
			}},
		})
	}

	return actions
}

func diagnosticBacktickName(message string) (string, bool) {
	start := strings.Index(message, "`")
	if start < 0 {
		return "", false
	}
	rest := message[start+1:]
	end := strings.Index(rest, "`")
	if end < 0 {
		return "", false
	}
	name := rest[:end]
	if name == "" {
		return "", false
	}
	return name, true
}

func lineStartPosition(text string, line lsp.UInteger) (lsp.Position, bool) {
	normalized := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 0 {
		return lsp.Position{}, false
	}

	idx := int(line)
	if idx < 0 || idx >= len(lines) {
		return lsp.Position{}, false
	}

	return lsp.Position{Line: lsp.UInteger(idx), Character: 0}, true
}

func symbolCandidatesAt(snapshot *analyzer.Snapshot, pos lsp.Position) []string {
	if snapshot == nil {
		return nil
	}

	items := snapshot.CompletionItemsAt(pos)
	seen := make(map[string]struct{}, len(items)+len(builtin.Builtins))
	result := make([]string, 0, len(items)+len(builtin.Builtins))

	for _, item := range items {
		if !completionItemCanBeIdentifier(item) {
			continue
		}
		label := item.Label
		if !isIdentifierName(label) {
			continue
		}
		if _, exists := seen[label]; exists {
			continue
		}
		seen[label] = struct{}{}
		result = append(result, label)
	}

	for _, def := range builtin.Builtins {
		if !isIdentifierName(def.Name) {
			continue
		}
		if _, exists := seen[def.Name]; exists {
			continue
		}
		seen[def.Name] = struct{}{}
		result = append(result, def.Name)
	}

	return result
}

func completionItemCanBeIdentifier(item lsp.CompletionItem) bool {
	if item.Kind == nil {
		return false
	}

	switch *item.Kind {
	case lsp.CompletionItemKindVariable,
		lsp.CompletionItemKindFunction,
		lsp.CompletionItemKindStruct,
		lsp.CompletionItemKindEnum,
		lsp.CompletionItemKindEnumMember,
		lsp.CompletionItemKindField:
		return true
	default:
		return false
	}
}

func isIdentifierName(name string) bool {
	if name == "" {
		return false
	}

	runes := []rune(name)
	for i, r := range runes {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}

	return true
}

func nearestIdentifierCandidate(target string, candidates []string) (string, bool) {
	if target == "" || len(candidates) == 0 {
		return "", false
	}

	targetLower := strings.ToLower(target)
	best := ""
	bestDistance := 1<<31 - 1

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		candLower := strings.ToLower(candidate)
		distance := levenshteinDistance(targetLower, candLower)
		if distance < bestDistance || (distance == bestDistance && candidate < best) {
			best = candidate
			bestDistance = distance
		}
	}

	if best == "" {
		return "", false
	}
	if bestDistance > 2 {
		return "", false
	}

	return best, true
}

func levenshteinDistance(a, b string) int {
	ar := []rune(a)
	br := []rune(b)
	if len(ar) == 0 {
		return len(br)
	}
	if len(br) == 0 {
		return len(ar)
	}

	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := 0; j <= len(br); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 0
			if ar[i-1] != br[j-1] {
				cost = 1
			}

			deletion := prev[j] + 1
			insertion := cur[j-1] + 1
			substitution := prev[j-1] + cost

			cur[j] = deletion
			if insertion < cur[j] {
				cur[j] = insertion
			}
			if substitution < cur[j] {
				cur[j] = substitution
			}
		}
		prev, cur = cur, prev
	}

	return prev[len(br)]
}

func lineDeleteRange(text string, line lsp.UInteger) (lsp.Range, bool) {
	normalized := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 0 {
		return lsp.Range{}, false
	}

	idx := int(line)
	if idx < 0 || idx >= len(lines) {
		return lsp.Range{}, false
	}

	if idx == len(lines)-1 {
		return lsp.Range{
			Start: lsp.Position{Line: lsp.UInteger(idx), Character: 0},
			End:   lsp.Position{Line: lsp.UInteger(idx), Character: lsp.UInteger(len([]rune(lines[idx])))},
		}, true
	}

	return lsp.Range{
		Start: lsp.Position{Line: lsp.UInteger(idx), Character: 0},
		End:   lsp.Position{Line: lsp.UInteger(idx + 1), Character: 0},
	}, true
}

func (s *Server) documentSymbols(_ *glsp.Context, params *lsp.DocumentSymbolParams) (any, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	return snapshot.DocumentSymbols(), nil
}

func (s *Server) definition(_ *glsp.Context, params *lsp.DefinitionParams) (any, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	location, ok := snapshot.DefinitionLocation(params.TextDocument.URI, params.Position)
	if !ok {
		if _, workspaceLocation, ok := s.resolveWorkspaceTopLevelAtPosition(snapshot, params.TextDocument.URI, params.Position, params.TextDocument.URI, false); ok {
			return workspaceLocation, nil
		}
		return nil, nil
	}
	return location, nil
}

func (s *Server) typeDefinition(_ *glsp.Context, params *lsp.TypeDefinitionParams) (any, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	location, ok := snapshot.TypeDefinitionLocation(params.TextDocument.URI, params.Position)
	if !ok {
		return nil, nil
	}
	return location, nil
}

func (s *Server) references(_ *glsp.Context, params *lsp.ReferenceParams) ([]lsp.Location, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	locations, ok := snapshot.ReferenceLocations(params.TextDocument.URI, params.Position, params.Context.IncludeDeclaration)
	if !ok {
		locations = nil
	}

	identName, workspaceLocation, ok := s.resolveWorkspaceTopLevelAtPosition(snapshot, params.TextDocument.URI, params.Position, "", true)
	if !ok {
		if len(locations) == 0 {
			return nil, nil
		}
		return locations, nil
	}

	workspaceLocations := s.workspaceReferenceLocations(identName, workspaceLocation, params.Context.IncludeDeclaration)
	locations = append(locations, workspaceLocations...)
	locations = dedupeLocations(locations)
	if len(locations) == 0 {
		return nil, nil
	}
	return locations, nil
}

func (s *Server) prepareRename(_ *glsp.Context, params *lsp.PrepareRenameParams) (any, error) {
	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	placeholder, rng, ok := snapshot.PrepareRename(params.Position)
	if !ok {
		name, identRange, ok := identifierNameAndRangeAt(snapshot, params.Position)
		if !ok {
			return nil, nil
		}
		if _, ok := s.resolveWorkspaceTopLevelByName(snapshot, params.TextDocument.URI, params.Position, name, params.TextDocument.URI, false); !ok {
			return nil, nil
		}
		return &lsp.RangeWithPlaceholder{
			Range:       localprotocol.ToLSPRange(identRange),
			Placeholder: name,
		}, nil
	}
	return &lsp.RangeWithPlaceholder{
		Range:       localprotocol.ToLSPRange(rng),
		Placeholder: placeholder,
	}, nil
}

func (s *Server) rename(_ *glsp.Context, params *lsp.RenameParams) (*lsp.WorkspaceEdit, error) {
	if !isValidIdentifierName(params.NewName) {
		return nil, fmt.Errorf("invalid identifier name %q", params.NewName)
	}

	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	locations, ok := snapshot.ReferenceLocations(params.TextDocument.URI, params.Position, true)
	if !ok {
		locations = nil
	}
	if len(locations) == 0 {
		identName, workspaceLocation, ok := s.resolveWorkspaceTopLevelAtPosition(snapshot, params.TextDocument.URI, params.Position, params.TextDocument.URI, false)
		if !ok {
			return nil, nil
		}
		locations = s.workspaceReferenceLocations(identName, workspaceLocation, true)
		if len(locations) == 0 {
			return nil, nil
		}
	}

	editsByURI := make(map[lsp.DocumentUri][]lsp.TextEdit)
	for _, location := range locations {
		editsByURI[location.URI] = append(editsByURI[location.URI], lsp.TextEdit{Range: location.Range, NewText: params.NewName})
	}
	for uri, edits := range editsByURI {
		sort.Slice(edits, func(i, j int) bool {
			if edits[i].Range.Start.Line != edits[j].Range.Start.Line {
				return edits[i].Range.Start.Line < edits[j].Range.Start.Line
			}
			return edits[i].Range.Start.Character < edits[j].Range.Start.Character
		})
		editsByURI[uri] = edits
	}

	if len(editsByURI) == 0 {
		return nil, nil
	}

	return &lsp.WorkspaceEdit{Changes: editsByURI}, nil
}

func (s *Server) semanticTokensFull(ctx *glsp.Context, params *lsp.SemanticTokensParams) (tokens *lsp.SemanticTokens, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logRecoveredPanic("textDocument/semanticTokens/full", params.TextDocument.URI, recovered)
			if s.shouldNotifySemanticFallback() {
				ctx.Notify(string(lsp.ServerWindowShowMessage), lsp.ShowMessageParams{
					Type:    lsp.MessageTypeWarning,
					Message: "Mutant LSP recovered from a semantic token failure and temporarily disabled semantic coloring for this request. See Mutant LSP logs for details.",
				})
			}
			tokens = &lsp.SemanticTokens{Data: []lsp.UInteger{}}
			err = nil
		}
	}()

	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	data := snapshot.SemanticTokensData()
	if len(data) == 0 {
		return &lsp.SemanticTokens{Data: []lsp.UInteger{}}, nil
	}
	return &lsp.SemanticTokens{Data: data}, nil
}

func (s *Server) formatting(_ *glsp.Context, params *lsp.DocumentFormattingParams) ([]lsp.TextEdit, error) {
	doc, ok := s.documents.Snapshot(params.TextDocument.URI)
	if !ok || doc == nil {
		return nil, nil
	}

	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok || snapshot == nil {
		snapshot = s.analyzer.Analyze(doc.Text)
	}

	formatted := formatSnapshotText(snapshot, newFormatterConfig(params.Options))
	if formatted == doc.Text {
		return nil, nil
	}

	return []lsp.TextEdit{{
		Range:   fullDocumentRange(doc.Text),
		NewText: formatted,
	}}, nil
}

func (s *Server) onTypeFormatting(_ *glsp.Context, params *lsp.DocumentOnTypeFormattingParams) ([]lsp.TextEdit, error) {
	if params == nil {
		return nil, nil
	}

	allowed := params.Ch == "}" || params.Ch == ";" || params.Ch == "\n"
	if !allowed {
		return nil, nil
	}

	doc, ok := s.documents.Snapshot(params.TextDocument.URI)
	if !ok || doc == nil {
		return nil, nil
	}

	snapshot, ok := s.snapshot(params.TextDocument.URI)
	if !ok || snapshot == nil {
		snapshot = s.analyzer.Analyze(doc.Text)
	}

	formatted := formatSnapshotText(snapshot, newFormatterConfig(params.Options))
	if formatted == doc.Text {
		return nil, nil
	}

	return []lsp.TextEdit{{
		Range:   fullDocumentRange(doc.Text),
		NewText: formatted,
	}}, nil
}

func (s *Server) publishDiagnostics(ctx *glsp.Context, uri lsp.DocumentUri, version lsp.UInteger, snapshot *analyzer.Snapshot) {
	params := lsp.PublishDiagnosticsParams{
		URI:         uri,
		Version:     &version,
		Diagnostics: analyzer.Diagnostics(snapshot, s.currentLintConfig()),
	}
	ctx.Notify(string(lsp.ServerTextDocumentPublishDiagnostics), params)
}

func (s *Server) republishAllDiagnostics(ctx *glsp.Context) {
	s.mu.RLock()
	uris := make([]lsp.DocumentUri, 0, len(s.snapshots))
	for uri := range s.snapshots {
		uris = append(uris, uri)
	}
	s.mu.RUnlock()

	for _, uri := range uris {
		doc, ok := s.documents.Snapshot(uri)
		if !ok || doc == nil {
			continue
		}
		snapshot, ok := s.snapshot(uri)
		if !ok || snapshot == nil {
			continue
		}
		s.publishDiagnostics(ctx, uri, doc.Version, snapshot)
	}
}

func (s *Server) snapshot(uri lsp.DocumentUri) (*analyzer.Snapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot, ok := s.snapshots[uri]
	return snapshot, ok
}

func (s *Server) setSnapshot(uri lsp.DocumentUri, snapshot *analyzer.Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots[uri] = snapshot
	s.safeSymbolUpdate(uri, snapshot)
}

func (s *Server) currentLintConfig() analyzer.LintConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lintConfig
}

func (s *Server) setLintConfig(config analyzer.LintConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lintConfig = config
}

func (s *Server) safeSymbolUpdate(uri lsp.DocumentUri, snapshot *analyzer.Snapshot) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logRecoveredPanic("symbolIndex.update", uri, recovered)
		}
	}()
	if s.symbols == nil {
		return
	}
	s.symbols.Update(uri, snapshot)
}

func (s *Server) safeSymbolDelete(uri lsp.DocumentUri) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logRecoveredPanic("symbolIndex.delete", uri, recovered)
		}
	}()
	if s.symbols == nil {
		return
	}
	s.symbols.Delete(uri)
}

func logRecoveredPanic(method string, uri lsp.DocumentUri, recovered any) {
	log.Printf("recover method=%s uri=%s panic=%v stack=%s", method, uri, recovered, debug.Stack())
}

func (s *Server) shouldNotifySemanticFallback() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.semanticFallbackWarned {
		return false
	}
	s.semanticFallbackWarned = true
	return true
}

func (s *Server) workspaceTopLevelDefinition(name string, sourceURI lsp.DocumentUri) (*lsp.Location, bool) {
	return s.symbols.UniqueTopLevelDefinition(name, sourceURI)
}

func (s *Server) workspaceReferenceLocations(name string, declaration *lsp.Location, includeDeclaration bool) []lsp.Location {
	return s.symbols.ReferenceLocations(name, declaration, includeDeclaration)
}

func rangePtr(rng lsp.Range) *lsp.Range {
	return &rng
}

func strptr(value string) *string {
	return &value
}

func isValidIdentifierName(name string) bool {
	if name == "" || token.LookupIdent(name) != token.IDENT {
		return false
	}
	first := true
	for _, ch := range name {
		if first {
			first = false
			if !unicode.IsLetter(ch) {
				return false
			}
			continue
		}
		if !unicode.IsLetter(ch) && !unicode.IsDigit(ch) && ch != '_' {
			return false
		}
	}
	return true
}

func identifierAt(snapshot *analyzer.Snapshot, pos lsp.Position) (string, bool) {
	name, _, ok := identifierNameAndRangeAt(snapshot, pos)
	if !ok {
		return "", false
	}
	return name, true
}

func (s *Server) resolveWorkspaceTopLevelAtPosition(snapshot *analyzer.Snapshot, documentURI lsp.DocumentUri, pos lsp.Position, sourceURI lsp.DocumentUri, requireTopLevelLocalDef bool) (string, *lsp.Location, bool) {
	name, ok := identifierAt(snapshot, pos)
	if !ok {
		return "", nil, false
	}
	location, ok := s.resolveWorkspaceTopLevelByName(snapshot, documentURI, pos, name, sourceURI, requireTopLevelLocalDef)
	if !ok {
		return "", nil, false
	}
	return name, location, true
}

func (s *Server) resolveWorkspaceTopLevelByName(snapshot *analyzer.Snapshot, documentURI lsp.DocumentUri, pos lsp.Position, name string, sourceURI lsp.DocumentUri, requireTopLevelLocalDef bool) (*lsp.Location, bool) {
	if snapshot == nil || name == "" {
		return nil, false
	}
	if requireTopLevelLocalDef {
		if definitionLocation, ok := snapshot.DefinitionLocation(documentURI, pos); ok && !isTopLevelDefinitionLocation(snapshot, definitionLocation) {
			return nil, false
		}
	}
	return s.workspaceTopLevelDefinition(name, sourceURI)
}

func identifierNameAndRangeAt(snapshot *analyzer.Snapshot, pos lsp.Position) (string, mast.Range, bool) {
	if snapshot == nil {
		return "", mast.Range{}, false
	}
	node, rng, ok := snapshot.NodeAt(pos)
	if !ok {
		return "", mast.Range{}, false
	}
	ident, ok := node.(*mast.Identifier)
	if !ok || ident == nil || ident.Value == "" {
		return "", mast.Range{}, false
	}
	return ident.Value, rng, true
}

func isTopLevelDefinitionLocation(snapshot *analyzer.Snapshot, location *lsp.Location) bool {
	if snapshot == nil || snapshot.Program == nil || location == nil {
		return false
	}
	for _, symbol := range snapshot.DocumentSymbols() {
		if isTopLevelSymbol(symbol, *location) {
			return true
		}
	}
	return false
}

func isTopLevelSymbol(symbol lsp.DocumentSymbol, location lsp.Location) bool {
	switch symbol.Kind {
	case lsp.SymbolKindVariable, lsp.SymbolKindFunction, lsp.SymbolKindStruct, lsp.SymbolKindEnum:
		if symbol.SelectionRange == location.Range {
			return true
		}
	}
	for _, child := range symbol.Children {
		if isTopLevelSymbol(child, location) {
			return true
		}
	}
	return false
}

func dedupeLocations(locations []lsp.Location) []lsp.Location {
	if len(locations) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(locations))
	unique := make([]lsp.Location, 0, len(locations))
	for _, location := range locations {
		key := locationKey(location)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, location)
	}
	return unique
}

func locationKey(location lsp.Location) string {
	return fmt.Sprintf("%s:%d:%d:%d:%d", location.URI, location.Range.Start.Line, location.Range.Start.Character, location.Range.End.Line, location.Range.End.Character)
}

func formatDocumentText(input string) string {
	return normalizeDocumentWhitespace(input)
}

func fullDocumentRange(text string) lsp.Range {
	normalized := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	if normalized == "" {
		return lsp.Range{}
	}

	lines := strings.Split(normalized, "\n")
	lastLine := len(lines) - 1
	lastCharacter := len([]rune(lines[lastLine]))

	return lsp.Range{
		Start: lsp.Position{Line: 0, Character: 0},
		End:   lsp.Position{Line: lsp.UInteger(lastLine), Character: lsp.UInteger(lastCharacter)},
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

func (s *Server) String() string {
	return fmt.Sprintf("%s@%s", serverName, serverVersion)
}
