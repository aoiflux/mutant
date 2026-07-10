package server

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/tliron/glsp"
	lsp "github.com/tliron/glsp/protocol_3_16"
)

func TestInitializeAdvertisesMVPCapabilities(t *testing.T) {
	s := New(false)

	resultAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialize),
		Params: mustJSON(t, lsp.InitializeParams{}),
	})
	if err != nil {
		t.Fatalf("initialize returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("initialize validity flags = method:%t params:%t", validMethod, validParams)
	}

	result, ok := resultAny.(*lsp.InitializeResult)
	if !ok {
		t.Fatalf("initialize result type = %T, want *protocol.InitializeResult", resultAny)
	}

	if result.ServerInfo == nil || result.ServerInfo.Name != serverName {
		t.Fatalf("server info = %#v, want name %q", result.ServerInfo, serverName)
	}

	syncOpts, ok := result.Capabilities.TextDocumentSync.(*lsp.TextDocumentSyncOptions)
	if !ok {
		t.Fatalf("textDocumentSync type = %T, want *TextDocumentSyncOptions", result.Capabilities.TextDocumentSync)
	}
	if syncOpts.OpenClose == nil || !*syncOpts.OpenClose {
		t.Fatalf("OpenClose = %#v, want true", syncOpts.OpenClose)
	}
	if syncOpts.Change == nil || *syncOpts.Change != lsp.TextDocumentSyncKindIncremental {
		t.Fatalf("Change = %#v, want Incremental", syncOpts.Change)
	}
	if provider, ok := result.Capabilities.HoverProvider.(bool); !ok || !provider {
		t.Fatalf("HoverProvider = %#v, want true", result.Capabilities.HoverProvider)
	}
	if provider, ok := result.Capabilities.DocumentSymbolProvider.(bool); !ok || !provider {
		t.Fatalf("DocumentSymbolProvider = %#v, want true", result.Capabilities.DocumentSymbolProvider)
	}
	if provider, ok := result.Capabilities.DefinitionProvider.(bool); !ok || !provider {
		t.Fatalf("DefinitionProvider = %#v, want true", result.Capabilities.DefinitionProvider)
	}
	if provider, ok := result.Capabilities.TypeDefinitionProvider.(bool); !ok || !provider {
		t.Fatalf("TypeDefinitionProvider = %#v, want true", result.Capabilities.TypeDefinitionProvider)
	}
	if provider, ok := result.Capabilities.ReferencesProvider.(bool); !ok || !provider {
		t.Fatalf("ReferencesProvider = %#v, want true", result.Capabilities.ReferencesProvider)
	}
	if provider, ok := result.Capabilities.RenameProvider.(bool); !ok || !provider {
		t.Fatalf("RenameProvider = %#v, want true", result.Capabilities.RenameProvider)
	}
	if result.Capabilities.CompletionProvider == nil {
		t.Fatal("CompletionProvider is nil")
	}
	if result.Capabilities.SignatureHelpProvider == nil {
		t.Fatal("SignatureHelpProvider is nil")
	}
	sigOpts := result.Capabilities.SignatureHelpProvider
	if !containsString(sigOpts.TriggerCharacters, "(") {
		t.Fatalf("signature help trigger chars missing '(': %#v", sigOpts.TriggerCharacters)
	}
	if !containsString(sigOpts.TriggerCharacters, ",") {
		t.Fatalf("signature help trigger chars missing ',': %#v", sigOpts.TriggerCharacters)
	}
	if provider, ok := result.Capabilities.CodeActionProvider.(bool); !ok || !provider {
		t.Fatalf("CodeActionProvider = %#v, want true", result.Capabilities.CodeActionProvider)
	}
	if provider, ok := result.Capabilities.DocumentHighlightProvider.(bool); !ok || !provider {
		t.Fatalf("DocumentHighlightProvider = %#v, want true", result.Capabilities.DocumentHighlightProvider)
	}
	if provider, ok := result.Capabilities.WorkspaceSymbolProvider.(bool); !ok || !provider {
		t.Fatalf("WorkspaceSymbolProvider = %#v, want true", result.Capabilities.WorkspaceSymbolProvider)
	}
	if result.Capabilities.SemanticTokensProvider == nil {
		t.Fatal("SemanticTokensProvider is nil")
	}
	semanticOpts, ok := result.Capabilities.SemanticTokensProvider.(*lsp.SemanticTokensOptions)
	if !ok || semanticOpts == nil {
		t.Fatalf("SemanticTokensProvider type = %T, want *SemanticTokensOptions", result.Capabilities.SemanticTokensProvider)
	}
	if len(semanticOpts.Legend.TokenTypes) == 0 {
		t.Fatal("semantic token legend is empty")
	}
	if !containsString(semanticOpts.Legend.TokenTypes, "type") {
		t.Fatalf("semantic token legend missing 'type': %#v", semanticOpts.Legend.TokenTypes)
	}
	if !containsString(semanticOpts.Legend.TokenTypes, "parameter") {
		t.Fatalf("semantic token legend missing 'parameter': %#v", semanticOpts.Legend.TokenTypes)
	}
	if !containsString(semanticOpts.Legend.TokenTypes, "property") {
		t.Fatalf("semantic token legend missing 'property': %#v", semanticOpts.Legend.TokenTypes)
	}
	if !containsString(semanticOpts.Legend.TokenTypes, "operator") {
		t.Fatalf("semantic token legend missing 'operator': %#v", semanticOpts.Legend.TokenTypes)
	}
	if !containsString(semanticOpts.Legend.TokenTypes, "punctuation") {
		t.Fatalf("semantic token legend missing 'punctuation': %#v", semanticOpts.Legend.TokenTypes)
	}
	if !containsString(semanticOpts.Legend.TokenModifiers, "defaultLibrary") {
		t.Fatalf("semantic token legend missing 'defaultLibrary' modifier: %#v", semanticOpts.Legend.TokenModifiers)
	}
	if provider, ok := result.Capabilities.DocumentFormattingProvider.(bool); !ok || !provider {
		t.Fatalf("DocumentFormattingProvider = %#v, want true", result.Capabilities.DocumentFormattingProvider)
	}
	if result.Capabilities.DocumentOnTypeFormattingProvider == nil {
		t.Fatal("DocumentOnTypeFormattingProvider is nil")
	}
	onType := result.Capabilities.DocumentOnTypeFormattingProvider
	if onType == nil {
		t.Fatal("DocumentOnTypeFormattingProvider should not be nil")
	}
	if onType.FirstTriggerCharacter != "}" {
		t.Fatalf("on-type first trigger = %q, want %q", onType.FirstTriggerCharacter, "}")
	}
}

func TestDidOpenPublishesParserDiagnostics(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///test.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let x = ;",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	if diag.URI != "file:///test.mut" {
		t.Fatalf("diagnostic URI = %q, want file:///test.mut", diag.URI)
	}
	if diag.Version == nil || *diag.Version != 1 {
		t.Fatalf("diagnostic version = %#v, want 1", diag.Version)
	}
	if len(diag.Diagnostics) == 0 {
		t.Fatal("expected at least one parser diagnostic")
	}
	if diag.Diagnostics[0].Message == "" {
		t.Fatal("first diagnostic has empty message")
	}
	if diag.Diagnostics[0].Severity == nil || *diag.Diagnostics[0].Severity != lsp.DiagnosticSeverityError {
		t.Fatalf("diagnostic severity = %#v, want error", diag.Diagnostics[0].Severity)
	}
	if diag.Diagnostics[0].Source == nil || *diag.Diagnostics[0].Source != "mutant-parser" {
		t.Fatalf("diagnostic source = %#v, want mutant-parser", diag.Diagnostics[0].Source)
	}
}

func TestDidOpenPublishesSupplementalDelimiterDiagnostics(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///syntax-balance.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let x = (1 + 2;\nlet y = [1, 2;\n}\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	if len(diag.Diagnostics) < 2 {
		t.Fatalf("diagnostic count = %d, want at least 2", len(diag.Diagnostics))
	}

	foundBalanceMessage := false
	for _, d := range diag.Diagnostics {
		if strings.Contains(d.Message, "unclosed delimiter") || strings.Contains(d.Message, "unexpected closing delimiter") || strings.Contains(d.Message, "mismatched delimiter") {
			foundBalanceMessage = true
			break
		}
	}
	if !foundBalanceMessage {
		t.Fatalf("expected supplemental delimiter diagnostics, got messages: %#v", diagnosticMessages(diag.Diagnostics))
	}
}

func TestDidOpenPublishesMultipleParserDiagnosticsForRecoveredStatements(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///syntax-multi-errors.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let first = ;\nlet second = ;\nlet ok = 1;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	parserCount := 0
	for _, d := range diag.Diagnostics {
		if d.Source != nil && *d.Source == "mutant-parser" {
			parserCount++
		}
	}
	if parserCount < 2 {
		t.Fatalf("expected at least 2 parser diagnostics after recovery, got=%d messages=%#v", parserCount, diagnosticMessages(diag.Diagnostics))
	}
}

func TestDidOpenPublishesDuplicateTopLevelDeclarationLintDiagnostic(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-duplicate.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let answer = 1;\nlet answer = 2;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	if len(diag.Diagnostics) != 1 {
		t.Fatalf("diagnostic count = %d, want 1", len(diag.Diagnostics))
	}
	if diag.Diagnostics[0].Severity == nil || *diag.Diagnostics[0].Severity != lsp.DiagnosticSeverityWarning {
		t.Fatalf("diagnostic severity = %#v, want warning", diag.Diagnostics[0].Severity)
	}
	if diag.Diagnostics[0].Source == nil || *diag.Diagnostics[0].Source != "mutant-lint" {
		t.Fatalf("diagnostic source = %#v, want mutant-lint", diag.Diagnostics[0].Source)
	}
	if diag.Diagnostics[0].Message != "duplicate top-level declaration `answer`" {
		t.Fatalf("diagnostic message = %q, want duplicate declaration message", diag.Diagnostics[0].Message)
	}
	if diag.Diagnostics[0].Range.Start.Line != 1 || diag.Diagnostics[0].Range.Start.Character != 4 {
		t.Fatalf("diagnostic range start = %+v, want line 1 char 4", diag.Diagnostics[0].Range.Start)
	}
}

func TestDuplicateDeclarationSuppressedWhenMultiNameBindingUsedOnImmediateNextLine(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-duplicate-suppressed.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let abc, err = gets();\nabc;\nerr;\nlet abc = 1;\nabc;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	for _, d := range diag.Diagnostics {
		if strings.Contains(d.Message, "duplicate top-level declaration `abc`") {
			t.Fatalf("unexpected duplicate diagnostic for immediate-next-line usage case: %#v", d)
		}
	}
}

func TestDuplicateDeclarationNotSuppressedWithoutImmediateNextLineUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-duplicate-not-suppressed.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let abc, err = gets();\nlet abc = 1;\nabc;\nerr;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	foundDuplicate := false
	for _, d := range diag.Diagnostics {
		if d.Message == "duplicate top-level declaration `abc`" {
			foundDuplicate = true
			break
		}
	}
	if !foundDuplicate {
		t.Fatalf("expected duplicate diagnostic, got messages: %#v", diagnosticMessages(diag.Diagnostics))
	}
}

func TestDuplicateDeclarationSuppressionAppliesInFunctionScope(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-duplicate-local-suppressed.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let run = fn() {\n" +
					"  let abc, err = gets();\n" +
					"  abc;\n" +
					"  let abc = 1;\n" +
					"  err;\n" +
					"};\n" +
					"run;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	for _, d := range diag.Diagnostics {
		if d.Message == "duplicate declaration `abc`" {
			t.Fatalf("unexpected local duplicate diagnostic in suppression case: %#v", d)
		}
	}
}

func TestDuplicateDeclarationReportedInFunctionScopeWithoutImmediateUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-duplicate-local.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let run = fn() {\n" +
					"  let abc, err = gets();\n" +
					"  let abc = 1;\n" +
					"  abc;\n" +
					"  err;\n" +
					"};\n" +
					"run;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	foundDuplicate := false
	for _, d := range diag.Diagnostics {
		if d.Message == "duplicate declaration `abc`" {
			foundDuplicate = true
			break
		}
	}
	if !foundDuplicate {
		t.Fatalf("expected local duplicate diagnostic, got messages: %#v", diagnosticMessages(diag.Diagnostics))
	}
}

func TestDidOpenPublishesUnusedTopLevelDeclarationLintDiagnostic(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-unused.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let orphan = 1;\nlet used = 2;\nused;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	if len(diag.Diagnostics) != 1 {
		t.Fatalf("diagnostic count = %d, want 1", len(diag.Diagnostics))
	}
	if diag.Diagnostics[0].Severity == nil || *diag.Diagnostics[0].Severity != lsp.DiagnosticSeverityWarning {
		t.Fatalf("diagnostic severity = %#v, want warning", diag.Diagnostics[0].Severity)
	}
	if diag.Diagnostics[0].Source == nil || *diag.Diagnostics[0].Source != "mutant-lint" {
		t.Fatalf("diagnostic source = %#v, want mutant-lint", diag.Diagnostics[0].Source)
	}
	if diag.Diagnostics[0].Message != "unused declaration `orphan`" {
		t.Fatalf("diagnostic message = %q, want unused declaration message", diag.Diagnostics[0].Message)
	}
	if diag.Diagnostics[0].Range.Start.Line != 0 || diag.Diagnostics[0].Range.Start.Character != 4 {
		t.Fatalf("diagnostic range start = %+v, want line 0 char 4", diag.Diagnostics[0].Range.Start)
	}
}

func TestDidOpenPublishesUndefinedDeclarationLintDiagnostic(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-undefined.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "puts(abc);\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	found := false
	for _, d := range diag.Diagnostics {
		if d.Message == "undefined identifier `abc`" {
			found = true
			if d.Severity == nil || *d.Severity != lsp.DiagnosticSeverityError {
				t.Fatalf("undefined identifier severity = %#v, want error", d.Severity)
			}
			if d.Source == nil || *d.Source != "mutant-lint" {
				t.Fatalf("undefined identifier source = %#v, want mutant-lint", d.Source)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected undefined identifier diagnostic, got messages: %#v", diagnosticMessages(diag.Diagnostics))
	}
}

func TestDidOpenDoesNotPublishUndefinedDeclarationForInScopeIdentifiers(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-undefined-scoped.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let run = fn(x) {\n" +
					"  let y = x;\n" +
					"  len(y);\n" +
					"};\n" +
					"run(1);\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	for _, d := range diag.Diagnostics {
		if strings.HasPrefix(d.Message, "undefined identifier `") {
			t.Fatalf("unexpected undefined identifier diagnostic: %#v", d)
		}
	}
}

func TestDidOpenPublishesNestingComplexityDiagnosticInFunctionBody(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-nesting.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let run = fn(x) {\n" +
					"  if (x) {\n" +
					"    if (x) {\n" +
					"      if (x) {\n" +
					"        return 1;\n" +
					"      }\n" +
					"    }\n" +
					"  }\n" +
					"  return 0;\n" +
					"};\n" +
					"run(1);\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	found := false
	for _, d := range diag.Diagnostics {
		if strings.Contains(d.Message, "nesting depth") {
			found = true
			if d.Severity == nil || *d.Severity != lsp.DiagnosticSeverityWarning {
				t.Fatalf("nesting severity = %#v, want warning", d.Severity)
			}
			if d.Source == nil || *d.Source != "mutant-lint" {
				t.Fatalf("nesting source = %#v, want mutant-lint", d.Source)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected nesting diagnostic, got messages: %#v", diagnosticMessages(diag.Diagnostics))
	}
}

func TestDidOpenDoesNotPublishNestingComplexityOutsideFunctionBody(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-nesting-top-level.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "if (true) {\n" +
					"  if (true) {\n" +
					"    if (true) {\n" +
					"      1;\n" +
					"    }\n" +
					"  }\n" +
					"}\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	for _, d := range diag.Diagnostics {
		if strings.Contains(d.Message, "nesting depth") {
			t.Fatalf("unexpected top-level nesting diagnostic: %#v", d)
		}
	}
}

func TestDidOpenPublishesUnusedLocalDeclarationLintDiagnostic(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-unused-local.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let run = fn() {\n" +
					"  let temp = 1;\n" +
					"  return 0;\n" +
					"};\n" +
					"run;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	foundUnusedLocal := false
	for _, d := range diag.Diagnostics {
		if d.Message == "unused declaration `temp`" {
			foundUnusedLocal = true
			break
		}
	}
	if !foundUnusedLocal {
		t.Fatalf("expected unused local diagnostic, got messages: %#v", diagnosticMessages(diag.Diagnostics))
	}
}

func TestDidOpenDoesNotPublishUnusedLocalWhenUsed(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-unused-local-used.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let run = fn() {\n" +
					"  let temp = 1;\n" +
					"  temp;\n" +
					"  return 0;\n" +
					"};\n" +
					"run;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	for _, d := range diag.Diagnostics {
		if d.Message == "unused declaration `temp`" {
			t.Fatalf("unexpected unused local diagnostic: %#v", d)
		}
	}
}

func TestDidChangeConfigurationUpdatesLintSeverity(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-config-duplicate.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let answer = 1;\nlet answer = 2;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodWorkspaceDidChangeConfiguration),
		Params: mustJSON(t, lsp.DidChangeConfigurationParams{Settings: map[string]any{
			"lint": map[string]any{
				"rules": map[string]any{
					"duplicateTopLevelDeclaration": map[string]any{"severity": "error"},
				},
			},
		}}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didChangeConfiguration returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didChangeConfiguration validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	if len(diag.Diagnostics) != 1 {
		t.Fatalf("diagnostic count = %d, want 1", len(diag.Diagnostics))
	}
	if diag.Diagnostics[0].Severity == nil || *diag.Diagnostics[0].Severity != lsp.DiagnosticSeverityError {
		t.Fatalf("diagnostic severity = %#v, want error", diag.Diagnostics[0].Severity)
	}
}

func TestDidChangeConfigurationSuppressesLintRuleWhenOff(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-config-unused.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let orphan = 1;\nlet used = 2;\nused;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodWorkspaceDidChangeConfiguration),
		Params: mustJSON(t, lsp.DidChangeConfigurationParams{Settings: map[string]any{
			"mutant": map[string]any{
				"lint": map[string]any{
					"rules": map[string]any{
						"unusedDeclaration": map[string]any{"severity": "off"},
					},
				},
			},
		}}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didChangeConfiguration returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didChangeConfiguration validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	if len(diag.Diagnostics) != 0 {
		t.Fatalf("diagnostic count = %d, want 0 when rule is off", len(diag.Diagnostics))
	}
}

func TestDidChangeConfigurationSuppressesUndefinedRuleWhenOff(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-config-undefined.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "puts(abc);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodWorkspaceDidChangeConfiguration),
		Params: mustJSON(t, lsp.DidChangeConfigurationParams{Settings: map[string]any{
			"mutant": map[string]any{
				"lint": map[string]any{
					"rules": map[string]any{
						"undefinedDeclaration": map[string]any{"severity": "off"},
					},
				},
			},
		}}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didChangeConfiguration returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didChangeConfiguration validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	for _, d := range diag.Diagnostics {
		if strings.HasPrefix(d.Message, "undefined identifier `") {
			t.Fatalf("unexpected undefined identifier diagnostic when rule is off: %#v", d)
		}
	}
}

func TestDidChangeConfigurationSuppressesNestingRuleWhenOff(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///lint-config-nesting.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let run = fn(x) {\n" +
					"  if (x) {\n" +
					"    if (x) {\n" +
					"      if (x) {\n" +
					"        return 1;\n" +
					"      }\n" +
					"    }\n" +
					"  }\n" +
					"  return 0;\n" +
					"};\n" +
					"run(1);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodWorkspaceDidChangeConfiguration),
		Params: mustJSON(t, lsp.DidChangeConfigurationParams{Settings: map[string]any{
			"mutant": map[string]any{
				"lint": map[string]any{
					"rules": map[string]any{
						"nestingComplexity": map[string]any{"severity": "off"},
					},
				},
			},
		}}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didChangeConfiguration returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didChangeConfiguration validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	for _, d := range diag.Diagnostics {
		if strings.Contains(d.Message, "nesting depth") {
			t.Fatalf("unexpected nesting diagnostic when rule is off: %#v", d)
		}
	}
}

func TestDidOpenRemainsStableWhenSymbolIndexUnavailable(t *testing.T) {
	s := New(false)
	initializeServer(t, s)
	s.symbols = nil

	notifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///stable-open.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let answer = 1;\n",
			},
		}),
		Notify: func(method string, params any) {
			notifications = append(notifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didOpen validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, notifications)
	if diag.URI != "file:///stable-open.mut" {
		t.Fatalf("diagnostic URI = %q, want file:///stable-open.mut", diag.URI)
	}
}

func TestSemanticFallbackWarningIsEmittedOnce(t *testing.T) {
	s := New(false)
	if !s.shouldNotifySemanticFallback() {
		t.Fatal("first semantic fallback notify should return true")
	}
	if s.shouldNotifySemanticFallback() {
		t.Fatal("second semantic fallback notify should return false")
	}
}

func TestDidChangeIncrementalUpdateRefreshesDiagnostics(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	openNotifications := make([]capturedNotification, 0, 1)
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///change.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let x = ;\nx;\n",
			},
		}),
		Notify: func(method string, params any) {
			openNotifications = append(openNotifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}
	if len(onlyDiagnosticsNotification(t, openNotifications).Diagnostics) == 0 {
		t.Fatal("expected opening invalid document to publish diagnostics")
	}

	changeNotifications := make([]capturedNotification, 0, 1)
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidChange),
		Params: mustJSON(t, lsp.DidChangeTextDocumentParams{
			TextDocument: lsp.VersionedTextDocumentIdentifier{
				TextDocumentIdentifier: lsp.TextDocumentIdentifier{URI: "file:///change.mut"},
				Version:                2,
			},
			ContentChanges: []any{
				lsp.TextDocumentContentChangeEvent{
					Range: &lsp.Range{
						Start: lsp.Position{Line: 0, Character: 8},
						End:   lsp.Position{Line: 0, Character: 8},
					},
					Text: "5",
				},
			},
		}),
		Notify: func(method string, params any) {
			changeNotifications = append(changeNotifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didChange returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("didChange validity flags = method:%t params:%t", validMethod, validParams)
	}

	diag := onlyDiagnosticsNotification(t, changeNotifications)
	if diag.Version == nil || *diag.Version != 2 {
		t.Fatalf("diagnostic version = %#v, want 2", diag.Version)
	}
	if len(diag.Diagnostics) != 0 {
		t.Fatalf("expected diagnostics to clear after valid incremental edit, got %d", len(diag.Diagnostics))
	}

	doc, ok := s.documents.Snapshot("file:///change.mut")
	if !ok {
		t.Fatal("document missing from workspace store after didChange")
	}
	if doc.Text != "let x = 5;\nx;\n" {
		t.Fatalf("document text = %q, want %q", doc.Text, "let x = 5;\\nx;\\n")
	}
}

func TestHoverDefinitionAndReferencesRemainStableAcrossRepeatedOpenChangeCycles(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///cycle-defs.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs returned error: %v", err)
	}

	usageText := "shared;\n"
	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///cycle-usage.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       usageText,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	for i := 0; i < 30; i++ {
		if i%2 == 0 {
			usageText = "shared;\n"
		} else {
			usageText = "shared;\nshared;\n"
		}

		_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
			Method: string(lsp.MethodTextDocumentDidChange),
			Params: mustJSON(t, lsp.DidChangeTextDocumentParams{
				TextDocument: lsp.VersionedTextDocumentIdentifier{
					TextDocumentIdentifier: lsp.TextDocumentIdentifier{URI: "file:///cycle-usage.mut"},
					Version:                lsp.Integer(i + 2),
				},
				ContentChanges: []any{
					lsp.TextDocumentContentChangeEvent{Text: usageText},
				},
			}),
			Notify: func(string, any) {},
		})
		if err != nil {
			t.Fatalf("didChange iteration %d returned error: %v", i, err)
		}
		if !validMethod || !validParams {
			t.Fatalf("didChange iteration %d validity flags = method:%t params:%t", i, validMethod, validParams)
		}

		hoverAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
			Method: string(lsp.MethodTextDocumentHover),
			Params: mustJSON(t, lsp.HoverParams{
				TextDocumentPositionParams: lsp.TextDocumentPositionParams{
					TextDocument: lsp.TextDocumentIdentifier{URI: "file:///cycle-usage.mut"},
					Position:     lsp.Position{Line: 0, Character: 1},
				},
			}),
		})
		if err != nil {
			t.Fatalf("hover iteration %d returned error: %v", i, err)
		}
		if !validMethod || !validParams {
			t.Fatalf("hover iteration %d validity flags = method:%t params:%t", i, validMethod, validParams)
		}
		hover, ok := hoverAny.(*lsp.Hover)
		if !ok || hover == nil {
			t.Fatalf("hover iteration %d result type = %T, want *Hover", i, hoverAny)
		}
		contents, ok := hover.Contents.(lsp.MarkupContent)
		if !ok {
			t.Fatalf("hover iteration %d contents type = %T, want MarkupContent", i, hover.Contents)
		}
		if contents.Value != "identifier `shared`" {
			t.Fatalf("hover iteration %d contents = %q, want identifier hover for shared", i, contents.Value)
		}

		defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
			Method: string(lsp.MethodTextDocumentDefinition),
			Params: mustJSON(t, lsp.DefinitionParams{
				TextDocumentPositionParams: lsp.TextDocumentPositionParams{
					TextDocument: lsp.TextDocumentIdentifier{URI: "file:///cycle-usage.mut"},
					Position:     lsp.Position{Line: 0, Character: 1},
				},
			}),
		})
		if err != nil {
			t.Fatalf("definition iteration %d returned error: %v", i, err)
		}
		if !validMethod || !validParams {
			t.Fatalf("definition iteration %d validity flags = method:%t params:%t", i, validMethod, validParams)
		}
		location, ok := defAny.(*lsp.Location)
		if !ok || location == nil {
			t.Fatalf("definition iteration %d result type = %T, want *Location", i, defAny)
		}
		if location.URI != "file:///cycle-defs.mut" {
			t.Fatalf("definition iteration %d URI = %q, want file:///cycle-defs.mut", i, location.URI)
		}
		if location.Range.Start.Line != 0 || location.Range.Start.Character != 4 {
			t.Fatalf("definition iteration %d start = %+v, want line 0 char 4", i, location.Range.Start)
		}

		referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
			Method: string(lsp.MethodTextDocumentReferences),
			Params: mustJSON(t, lsp.ReferenceParams{
				TextDocumentPositionParams: lsp.TextDocumentPositionParams{
					TextDocument: lsp.TextDocumentIdentifier{URI: "file:///cycle-usage.mut"},
					Position:     lsp.Position{Line: 0, Character: 1},
				},
				Context: lsp.ReferenceContext{IncludeDeclaration: true},
			}),
		})
		if err != nil {
			t.Fatalf("references iteration %d returned error: %v", i, err)
		}
		if !validMethod || !validParams {
			t.Fatalf("references iteration %d validity flags = method:%t params:%t", i, validMethod, validParams)
		}
		locations, ok := referencesAny.([]lsp.Location)
		if !ok {
			t.Fatalf("references iteration %d result type = %T, want []Location", i, referencesAny)
		}
		if len(locations) < 2 {
			t.Fatalf("references iteration %d count = %d, want at least 2", i, len(locations))
		}

		foundDeclaration := false
		for _, loc := range locations {
			if loc.URI == "file:///cycle-defs.mut" && loc.Range.Start.Line == 0 && loc.Range.Start.Character == 4 {
				foundDeclaration = true
				break
			}
		}
		if !foundDeclaration {
			t.Fatalf("references iteration %d did not include declaration in cycle-defs.mut", i)
		}
	}
}

func TestSemanticTokensFullReturnsData(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///semantic.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let answer = 42;\nanswer;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	tokensAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentSemanticTokensFull),
		Params: mustJSON(t, lsp.SemanticTokensParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///semantic.mut"},
		}),
	})
	if err != nil {
		t.Fatalf("semanticTokens/full returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("semanticTokens/full validity flags = method:%t params:%t", validMethod, validParams)
	}
	tokens, ok := tokensAny.(*lsp.SemanticTokens)
	if !ok || tokens == nil {
		t.Fatalf("semanticTokens/full result type = %T, want *SemanticTokens", tokensAny)
	}
	if len(tokens.Data) == 0 {
		t.Fatal("semantic tokens data is empty")
	}
	if len(tokens.Data)%5 != 0 {
		t.Fatalf("semantic tokens data length = %d, want multiple of 5", len(tokens.Data))
	}
}

func TestSemanticTokensClassifyParameterAndProperty(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///semantic-classification.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "struct Point { x; y; }\n" +
					"let make = fn(x) { x; };\n" +
					"let p = Point { x: 1, y: 2 };\n" +
					"p.x;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	initAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialize),
		Params: mustJSON(t, lsp.InitializeParams{}),
	})
	if err != nil {
		t.Fatalf("initialize returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("initialize validity flags = method:%t params:%t", validMethod, validParams)
	}
	initResult, ok := initAny.(*lsp.InitializeResult)
	if !ok || initResult == nil || initResult.Capabilities.SemanticTokensProvider == nil {
		t.Fatalf("initialize result = %T, want semantic tokens capability", initAny)
	}
	semanticOpts, ok := initResult.Capabilities.SemanticTokensProvider.(*lsp.SemanticTokensOptions)
	if !ok || semanticOpts == nil {
		t.Fatalf("SemanticTokensProvider type = %T, want *SemanticTokensOptions", initResult.Capabilities.SemanticTokensProvider)
	}
	parameterTypeID := tokenTypeID(t, semanticOpts.Legend.TokenTypes, "parameter")
	propertyTypeID := tokenTypeID(t, semanticOpts.Legend.TokenTypes, "property")

	tokensAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentSemanticTokensFull),
		Params: mustJSON(t, lsp.SemanticTokensParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///semantic-classification.mut"},
		}),
	})
	if err != nil {
		t.Fatalf("semanticTokens/full returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("semanticTokens/full validity flags = method:%t params:%t", validMethod, validParams)
	}
	tokens, ok := tokensAny.(*lsp.SemanticTokens)
	if !ok || tokens == nil {
		t.Fatalf("semanticTokens/full result type = %T, want *SemanticTokens", tokensAny)
	}

	decoded := decodeSemanticTokens(t, tokens.Data)
	assertSemanticToken(t, decoded, 1, 14, 1, parameterTypeID)
	assertSemanticToken(t, decoded, 2, 16, 1, propertyTypeID)
	assertSemanticToken(t, decoded, 3, 2, 1, propertyTypeID)
}

func TestSemanticTokensClassifyBuiltinAsDefaultLibraryFunction(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///semantic-builtins.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let xs = [1, 2];\nlen(xs);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	initAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialize),
		Params: mustJSON(t, lsp.InitializeParams{}),
	})
	if err != nil {
		t.Fatalf("initialize returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("initialize validity flags = method:%t params:%t", validMethod, validParams)
	}
	initResult, ok := initAny.(*lsp.InitializeResult)
	if !ok || initResult == nil || initResult.Capabilities.SemanticTokensProvider == nil {
		t.Fatalf("initialize result = %T, want semantic tokens capability", initAny)
	}
	semanticOpts, ok := initResult.Capabilities.SemanticTokensProvider.(*lsp.SemanticTokensOptions)
	if !ok || semanticOpts == nil {
		t.Fatalf("SemanticTokensProvider type = %T, want *SemanticTokensOptions", initResult.Capabilities.SemanticTokensProvider)
	}
	functionTypeID := tokenTypeID(t, semanticOpts.Legend.TokenTypes, "function")
	defaultLibraryModBit := tokenModifierBit(t, semanticOpts.Legend.TokenModifiers, "defaultLibrary")

	tokensAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentSemanticTokensFull),
		Params: mustJSON(t, lsp.SemanticTokensParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///semantic-builtins.mut"},
		}),
	})
	if err != nil {
		t.Fatalf("semanticTokens/full returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("semanticTokens/full validity flags = method:%t params:%t", validMethod, validParams)
	}
	tokens, ok := tokensAny.(*lsp.SemanticTokens)
	if !ok || tokens == nil {
		t.Fatalf("semanticTokens/full result type = %T, want *SemanticTokens", tokensAny)
	}

	decoded := decodeSemanticTokens(t, tokens.Data)
	assertSemanticTokenWithModifier(t, decoded, 1, 0, 3, functionTypeID, defaultLibraryModBit)
}

func TestSemanticTokensClassifyOperatorAndPunctuation(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///semantic-operators.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let x = (1 + 2);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	initAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialize),
		Params: mustJSON(t, lsp.InitializeParams{}),
	})
	if err != nil {
		t.Fatalf("initialize returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("initialize validity flags = method:%t params:%t", validMethod, validParams)
	}
	initResult, ok := initAny.(*lsp.InitializeResult)
	if !ok || initResult == nil || initResult.Capabilities.SemanticTokensProvider == nil {
		t.Fatalf("initialize result = %T, want semantic tokens capability", initAny)
	}
	semanticOpts, ok := initResult.Capabilities.SemanticTokensProvider.(*lsp.SemanticTokensOptions)
	if !ok || semanticOpts == nil {
		t.Fatalf("SemanticTokensProvider type = %T, want *SemanticTokensOptions", initResult.Capabilities.SemanticTokensProvider)
	}
	operatorTypeID := tokenTypeID(t, semanticOpts.Legend.TokenTypes, "operator")
	punctuationTypeID := tokenTypeID(t, semanticOpts.Legend.TokenTypes, "punctuation")

	tokensAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentSemanticTokensFull),
		Params: mustJSON(t, lsp.SemanticTokensParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///semantic-operators.mut"},
		}),
	})
	if err != nil {
		t.Fatalf("semanticTokens/full returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("semanticTokens/full validity flags = method:%t params:%t", validMethod, validParams)
	}
	tokens, ok := tokensAny.(*lsp.SemanticTokens)
	if !ok || tokens == nil {
		t.Fatalf("semanticTokens/full result type = %T, want *SemanticTokens", tokensAny)
	}

	decoded := decodeSemanticTokens(t, tokens.Data)
	assertSemanticToken(t, decoded, 0, 6, 1, operatorTypeID)     // =
	assertSemanticToken(t, decoded, 0, 11, 1, operatorTypeID)    // +
	assertSemanticToken(t, decoded, 0, 8, 1, punctuationTypeID)  // (
	assertSemanticToken(t, decoded, 0, 14, 1, punctuationTypeID) // )
	assertSemanticToken(t, decoded, 0, 15, 1, punctuationTypeID) // ;
}

func TestSignatureHelpForUserDefinedFunctionCall(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///signature-user.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let add = fn(a, b) { a + b; };\nadd(1, 2);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	helpAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentSignatureHelp),
		Params: mustJSON(t, lsp.SignatureHelpParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///signature-user.mut"},
				Position:     lsp.Position{Line: 1, Character: 7}, // second argument "2"
			},
		}),
	})
	if err != nil {
		t.Fatalf("signatureHelp returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("signatureHelp validity flags = method:%t params:%t", validMethod, validParams)
	}

	help, ok := helpAny.(*lsp.SignatureHelp)
	if !ok || help == nil {
		t.Fatalf("signatureHelp result type = %T, want *SignatureHelp", helpAny)
	}
	if len(help.Signatures) != 1 {
		t.Fatalf("signature count = %d, want 1", len(help.Signatures))
	}
	if help.Signatures[0].Label != "add(a, b)" {
		t.Fatalf("signature label = %q, want %q", help.Signatures[0].Label, "add(a, b)")
	}
	if len(help.Signatures[0].Parameters) != 2 {
		t.Fatalf("signature params = %d, want 2", len(help.Signatures[0].Parameters))
	}
	if help.ActiveParameter == nil || *help.ActiveParameter != 1 {
		t.Fatalf("active parameter = %#v, want 1", help.ActiveParameter)
	}
}

func TestSignatureHelpForBuiltinCall(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///signature-builtin.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "len([1, 2]);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	helpAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentSignatureHelp),
		Params: mustJSON(t, lsp.SignatureHelpParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///signature-builtin.mut"},
				Position:     lsp.Position{Line: 0, Character: 3},
			},
		}),
	})
	if err != nil {
		t.Fatalf("signatureHelp returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("signatureHelp validity flags = method:%t params:%t", validMethod, validParams)
	}

	help, ok := helpAny.(*lsp.SignatureHelp)
	if !ok || help == nil {
		t.Fatalf("signatureHelp result type = %T, want *SignatureHelp", helpAny)
	}
	if len(help.Signatures) != 1 {
		t.Fatalf("signature count = %d, want 1", len(help.Signatures))
	}
	if help.Signatures[0].Label != "len(value)" {
		t.Fatalf("signature label = %q, want %q", help.Signatures[0].Label, "len(value)")
	}
	if len(help.Signatures[0].Parameters) != 1 {
		t.Fatalf("signature params = %d, want 1", len(help.Signatures[0].Parameters))
	}
	if paramLabel, ok := help.Signatures[0].Parameters[0].Label.(string); !ok || paramLabel != "value" {
		t.Fatalf("signature param label = %#v, want %q", help.Signatures[0].Parameters[0].Label, "value")
	}
	if doc, ok := help.Signatures[0].Documentation.(lsp.MarkupContent); !ok || !strings.Contains(doc.Value, "Returns the length") {
		t.Fatalf("signature documentation = %#v, want builtin summary", help.Signatures[0].Documentation)
	}
}

func TestCodeActionQuickFixForDuplicateDeclaration(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	text := "let answer = 1;\nlet answer = 2;\n"
	openNotifications := make([]capturedNotification, 0, 1)
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///code-action-duplicate.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       text,
			},
		}),
		Notify: func(method string, params any) {
			openNotifications = append(openNotifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	diags := onlyDiagnosticsNotification(t, openNotifications).Diagnostics
	if len(diags) != 1 {
		t.Fatalf("diagnostic count = %d, want 1", len(diags))
	}

	actionsAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentCodeAction),
		Params: mustJSON(t, lsp.CodeActionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///code-action-duplicate.mut"},
			Range:        diags[0].Range,
			Context:      lsp.CodeActionContext{Diagnostics: diags},
		}),
	})
	if err != nil {
		t.Fatalf("codeAction returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("codeAction validity flags = method:%t params:%t", validMethod, validParams)
	}

	actions, ok := actionsAny.([]lsp.CodeAction)
	if !ok || len(actions) == 0 {
		t.Fatalf("codeAction result = %T (len=%d), want non-empty []CodeAction", actionsAny, len(actions))
	}
	if actions[0].Title != "Remove duplicate top-level declaration" {
		t.Fatalf("code action title = %q", actions[0].Title)
	}
	if actions[0].Edit == nil {
		t.Fatal("code action edit is nil")
	}
	edits := actions[0].Edit.Changes["file:///code-action-duplicate.mut"]
	if len(edits) == 0 {
		t.Fatal("expected code action text edits")
	}
	updated := applyTextEdits(t, text, edits)
	want := "let answer = 1;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestCodeActionQuickFixForUnusedDeclaration(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	text := "let orphan = 1;\nlet used = 2;\nused;\n"
	openNotifications := make([]capturedNotification, 0, 1)
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///code-action-unused.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       text,
			},
		}),
		Notify: func(method string, params any) {
			openNotifications = append(openNotifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	diags := onlyDiagnosticsNotification(t, openNotifications).Diagnostics
	if len(diags) != 1 {
		t.Fatalf("diagnostic count = %d, want 1", len(diags))
	}

	actionsAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentCodeAction),
		Params: mustJSON(t, lsp.CodeActionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///code-action-unused.mut"},
			Range:        diags[0].Range,
			Context:      lsp.CodeActionContext{Diagnostics: diags},
		}),
	})
	if err != nil {
		t.Fatalf("codeAction returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("codeAction validity flags = method:%t params:%t", validMethod, validParams)
	}

	actions, ok := actionsAny.([]lsp.CodeAction)
	if !ok || len(actions) == 0 {
		t.Fatalf("codeAction result = %T (len=%d), want non-empty []CodeAction", actionsAny, len(actions))
	}
	if actions[0].Title != "Remove unused declaration" {
		t.Fatalf("code action title = %q", actions[0].Title)
	}
	if actions[0].Edit == nil {
		t.Fatal("code action edit is nil")
	}
	edits := actions[0].Edit.Changes["file:///code-action-unused.mut"]
	if len(edits) == 0 {
		t.Fatal("expected code action text edits")
	}
	updated := applyTextEdits(t, text, edits)
	want := "let used = 2;\nused;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestCodeActionQuickFixForUndefinedIdentifierCreateDeclaration(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	text := "len(abc);\n"
	openNotifications := make([]capturedNotification, 0, 1)
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///code-action-undefined-create.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       text,
			},
		}),
		Notify: func(method string, params any) {
			openNotifications = append(openNotifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	allDiags := onlyDiagnosticsNotification(t, openNotifications).Diagnostics
	undefinedDiags := make([]lsp.Diagnostic, 0, len(allDiags))
	for _, d := range allDiags {
		if d.Message == "undefined identifier `abc`" {
			undefinedDiags = append(undefinedDiags, d)
		}
	}
	if len(undefinedDiags) == 0 {
		t.Fatalf("expected undefined identifier diagnostic, got messages: %#v", diagnosticMessages(allDiags))
	}

	actionsAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentCodeAction),
		Params: mustJSON(t, lsp.CodeActionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///code-action-undefined-create.mut"},
			Range:        undefinedDiags[0].Range,
			Context:      lsp.CodeActionContext{Diagnostics: undefinedDiags},
		}),
	})
	if err != nil {
		t.Fatalf("codeAction returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("codeAction validity flags = method:%t params:%t", validMethod, validParams)
	}

	actions, ok := actionsAny.([]lsp.CodeAction)
	if !ok || len(actions) == 0 {
		t.Fatalf("codeAction result = %T (len=%d), want non-empty []CodeAction", actionsAny, len(actions))
	}

	var createFix *lsp.CodeAction
	for i := range actions {
		if actions[i].Title == "Create declaration `abc`" {
			createFix = &actions[i]
			break
		}
	}
	if createFix == nil {
		t.Fatalf("expected create declaration quick fix, got %d action(s)", len(actions))
	}
	if createFix.Edit == nil {
		t.Fatal("create declaration quick fix edit is nil")
	}
	edits := createFix.Edit.Changes["file:///code-action-undefined-create.mut"]
	if len(edits) == 0 {
		t.Fatal("expected create declaration quick fix edits")
	}
	updated := applyTextEdits(t, text, edits)
	if updated != "let abc = 0;\nlen(abc);\n" {
		t.Fatalf("updated text = %q, want %q", updated, "let abc = 0;\\nlen(abc);\\n")
	}
}

func TestCodeActionQuickFixForUndefinedIdentifierReplaceNearest(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	text := "let abd = 1;\nlen(abc);\nabd;\n"
	openNotifications := make([]capturedNotification, 0, 1)
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///code-action-undefined-replace.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       text,
			},
		}),
		Notify: func(method string, params any) {
			openNotifications = append(openNotifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	allDiags := onlyDiagnosticsNotification(t, openNotifications).Diagnostics
	undefinedDiags := make([]lsp.Diagnostic, 0, len(allDiags))
	for _, d := range allDiags {
		if d.Message == "undefined identifier `abc`" {
			undefinedDiags = append(undefinedDiags, d)
		}
	}
	if len(undefinedDiags) == 0 {
		t.Fatalf("expected undefined identifier diagnostic, got messages: %#v", diagnosticMessages(allDiags))
	}

	actionsAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentCodeAction),
		Params: mustJSON(t, lsp.CodeActionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///code-action-undefined-replace.mut"},
			Range:        undefinedDiags[0].Range,
			Context:      lsp.CodeActionContext{Diagnostics: undefinedDiags},
		}),
	})
	if err != nil {
		t.Fatalf("codeAction returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("codeAction validity flags = method:%t params:%t", validMethod, validParams)
	}

	actions, ok := actionsAny.([]lsp.CodeAction)
	if !ok || len(actions) == 0 {
		t.Fatalf("codeAction result = %T (len=%d), want non-empty []CodeAction", actionsAny, len(actions))
	}

	var replaceFix *lsp.CodeAction
	for i := range actions {
		if actions[i].Title == "Replace with `abd`" {
			replaceFix = &actions[i]
			break
		}
	}
	if replaceFix == nil {
		t.Fatalf("expected replace quick fix, got %d action(s)", len(actions))
	}
	if replaceFix.Edit == nil {
		t.Fatal("replace quick fix edit is nil")
	}
	edits := replaceFix.Edit.Changes["file:///code-action-undefined-replace.mut"]
	if len(edits) == 0 {
		t.Fatal("expected replace quick fix edits")
	}
	updated := applyTextEdits(t, text, edits)
	if updated != "let abd = 1;\nlen(abd);\nabd;\n" {
		t.Fatalf("updated text = %q, want %q", updated, "let abd = 1;\\nlen(abd);\\nabd;\\n")
	}
}

func TestCodeActionQuickFixForUnexpectedToken(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	text := "let answer = ;\nlet next = 2;\n"
	openNotifications := make([]capturedNotification, 0, 1)
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///code-action-semicolon.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       text,
			},
		}),
		Notify: func(method string, params any) {
			openNotifications = append(openNotifications, capturedNotification{method: method, params: params})
		},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	allDiags := onlyDiagnosticsNotification(t, openNotifications).Diagnostics
	parserDiags := make([]lsp.Diagnostic, 0, len(allDiags))
	for _, diagnostic := range allDiags {
		if diagnostic.Source != nil && *diagnostic.Source == "mutant-parser" {
			parserDiags = append(parserDiags, diagnostic)
		}
	}
	if len(parserDiags) == 0 {
		t.Fatal("expected parser diagnostics for missing semicolon input")
	}

	actionsAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentCodeAction),
		Params: mustJSON(t, lsp.CodeActionParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///code-action-semicolon.mut"},
			Range:        parserDiags[0].Range,
			Context:      lsp.CodeActionContext{Diagnostics: parserDiags},
		}),
	})
	if err != nil {
		t.Fatalf("codeAction returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("codeAction validity flags = method:%t params:%t", validMethod, validParams)
	}

	actions, ok := actionsAny.([]lsp.CodeAction)
	if !ok {
		t.Fatalf("codeAction result type = %T, want []CodeAction", actionsAny)
	}

	var parserFix *lsp.CodeAction
	for i := range actions {
		if actions[i].Title == "Remove unexpected token" {
			parserFix = &actions[i]
			break
		}
	}
	if parserFix == nil {
		t.Fatalf("expected parser recovery quick fix, got %d action(s)", len(actions))
	}
	if parserFix.Edit == nil {
		t.Fatal("parser recovery quick fix edit is nil")
	}
	edits := parserFix.Edit.Changes["file:///code-action-semicolon.mut"]
	if len(edits) == 0 {
		t.Fatal("expected parser recovery quick fix edits")
	}
	updated := applyTextEdits(t, text, edits)
	if updated != "let answer = \nlet next = 2;\n" {
		t.Fatalf("updated text = %q, want %q", updated, "let answer = \\nlet next = 2;\\n")
	}
}

func TestDocumentHighlightsClassifyReadAndWrite(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///highlights.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let x = 1;\nx = x + 1;\nx;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	highlightsAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDocumentHighlight),
		Params: mustJSON(t, lsp.DocumentHighlightParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///highlights.mut"},
				Position:     lsp.Position{Line: 1, Character: 0},
			},
		}),
	})
	if err != nil {
		t.Fatalf("documentHighlight returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("documentHighlight validity flags = method:%t params:%t", validMethod, validParams)
	}

	highlights, ok := highlightsAny.([]lsp.DocumentHighlight)
	if !ok {
		t.Fatalf("documentHighlight result type = %T, want []DocumentHighlight", highlightsAny)
	}
	if len(highlights) < 4 {
		t.Fatalf("highlight count = %d, want at least 4", len(highlights))
	}

	assertDocumentHighlightKind(t, highlights, lsp.Range{Start: lsp.Position{Line: 0, Character: 4}, End: lsp.Position{Line: 0, Character: 5}}, lsp.DocumentHighlightKindWrite)
	assertDocumentHighlightKind(t, highlights, lsp.Range{Start: lsp.Position{Line: 1, Character: 0}, End: lsp.Position{Line: 1, Character: 1}}, lsp.DocumentHighlightKindWrite)
	assertDocumentHighlightKind(t, highlights, lsp.Range{Start: lsp.Position{Line: 1, Character: 4}, End: lsp.Position{Line: 1, Character: 5}}, lsp.DocumentHighlightKindRead)
	assertDocumentHighlightKind(t, highlights, lsp.Range{Start: lsp.Position{Line: 2, Character: 0}, End: lsp.Position{Line: 2, Character: 1}}, lsp.DocumentHighlightKindRead)
}

func TestWorkspaceSymbolsSearch(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	open := func(uri lsp.DocumentUri, text string) {
		t.Helper()
		_, _, _, err := s.handler.Handle(&glsp.Context{
			Method: string(lsp.MethodTextDocumentDidOpen),
			Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
				TextDocument: lsp.TextDocumentItem{
					URI:        uri,
					LanguageID: "mutant",
					Version:    1,
					Text:       text,
				},
			}),
			Notify: func(string, any) {},
		})
		if err != nil {
			t.Fatalf("didOpen %s returned error: %v", uri, err)
		}
	}

	open("file:///workspace-symbol-a.mut", "let alpha = 1;\nstruct Basket { id; }\n")
	open("file:///workspace-symbol-b.mut", "enum Better { One, Two }\nlet beta = 2;\n")

	allAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodWorkspaceSymbol),
		Params: mustJSON(t, lsp.WorkspaceSymbolParams{Query: ""}),
	})
	if err != nil {
		t.Fatalf("workspaceSymbol(all) returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("workspaceSymbol(all) validity flags = method:%t params:%t", validMethod, validParams)
	}
	all, ok := allAny.([]lsp.SymbolInformation)
	if !ok {
		t.Fatalf("workspaceSymbol(all) result type = %T, want []SymbolInformation", allAny)
	}
	if len(all) < 4 {
		t.Fatalf("workspaceSymbol(all) count = %d, want at least 4", len(all))
	}

	filteredAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodWorkspaceSymbol),
		Params: mustJSON(t, lsp.WorkspaceSymbolParams{Query: "be"}),
	})
	if err != nil {
		t.Fatalf("workspaceSymbol(filtered) returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("workspaceSymbol(filtered) validity flags = method:%t params:%t", validMethod, validParams)
	}
	filtered, ok := filteredAny.([]lsp.SymbolInformation)
	if !ok {
		t.Fatalf("workspaceSymbol(filtered) result type = %T, want []SymbolInformation", filteredAny)
	}
	if len(filtered) != 2 {
		t.Fatalf("workspaceSymbol(filtered) count = %d, want 2", len(filtered))
	}
	assertWorkspaceSymbol(t, filtered, "Better", lsp.SymbolKindEnum)
	assertWorkspaceSymbol(t, filtered, "beta", lsp.SymbolKindVariable)
}

func TestTypeDefinitionResolvesStructFromVariableUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///typedef-var.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "struct Point { x; y; }\nlet p = Point { x: 1, y: 2 };\np;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	typeAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentTypeDefinition),
		Params: mustJSON(t, lsp.TypeDefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///typedef-var.mut"},
				Position:     lsp.Position{Line: 2, Character: 0},
			},
		}),
	})
	if err != nil {
		t.Fatalf("typeDefinition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("typeDefinition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := typeAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("typeDefinition result type = %T, want *Location", typeAny)
	}
	if location.URI != "file:///typedef-var.mut" {
		t.Fatalf("typeDefinition URI = %q, want file:///typedef-var.mut", location.URI)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 7 {
		t.Fatalf("typeDefinition start = %+v, want line 0 char 7", location.Range.Start)
	}
}

func TestTypeDefinitionResolvesStructFromFieldUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///typedef-field.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "struct Point { x; y; }\nlet p = Point { x: 1, y: 2 };\np.x;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	typeAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentTypeDefinition),
		Params: mustJSON(t, lsp.TypeDefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///typedef-field.mut"},
				Position:     lsp.Position{Line: 2, Character: 2},
			},
		}),
	})
	if err != nil {
		t.Fatalf("typeDefinition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("typeDefinition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := typeAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("typeDefinition result type = %T, want *Location", typeAny)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 7 {
		t.Fatalf("typeDefinition start = %+v, want line 0 char 7", location.Range.Start)
	}
}

func TestDocumentFormattingNormalizesWhitespace(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let answer = 1;   \nanswer;   "
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok {
		t.Fatalf("formatting result type = %T, want []TextEdit", formatAny)
	}
	if len(edits) != 1 {
		t.Fatalf("formatting edit count = %d, want 1", len(edits))
	}

	updated := applyTextEdits(t, original, edits)
	want := "let answer = 1;\nanswer;\n"
	if updated != want {
		t.Fatalf("formatted text = %q, want %q", updated, want)
	}
}

func TestDocumentFormattingNoopReturnsNil(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let answer = 1;\n"
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format-noop.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format-noop.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	if formatAny != nil {
		if edits, ok := formatAny.([]lsp.TextEdit); ok && len(edits) == 0 {
			return
		}
		t.Fatalf("formatting result = %T, want nil/empty for noop", formatAny)
	}
}

func TestDocumentFormattingPreservesCommentsAndBlankLines(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "// header comment\n" +
		"let   answer=1;\n" +
		"\n" +
		"// keep this spacing\n" +
		"answer;    // inline comment\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format-comments-blanklines.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format-comments-blanklines.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	if formatAny == nil {
		return
	}
	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok {
		t.Fatalf("formatting result = %T, want []TextEdit or nil", formatAny)
	}
	if len(edits) == 0 {
		return
	}

	updated := applyTextEdits(t, original, edits)
	want := "// header comment\n" +
		"let answer = 1;\n" +
		"\n" +
		"// keep this spacing\n" +
		"answer; // inline comment\n"
	if updated != want {
		t.Fatalf("formatted text = %q, want %q", updated, want)
	}
}

func TestDocumentFormattingPreservesStringQuotes(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let msg=\"hello world\";\nmsg;"
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format-string.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format-string.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok || len(edits) != 1 {
		t.Fatalf("formatting result = %T (len=%d), want one edit", formatAny, len(edits))
	}

	updated := applyTextEdits(t, original, edits)
	want := "let msg = \"hello world\";\nmsg;\n"
	if updated != want {
		t.Fatalf("formatted text = %q, want %q", updated, want)
	}
}

func TestDocumentFormattingFormatsNestedBlocks(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let answer=fn(x){if (x > 0) {return x;} else {return 0;}};"
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format-nested.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format-nested.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok {
		t.Fatalf("formatting result type = %T, want []TextEdit", formatAny)
	}
	if len(edits) != 1 {
		t.Fatalf("formatting edit count = %d, want 1", len(edits))
	}

	updated := applyTextEdits(t, original, edits)
	want := "let answer = fn(x) {\n" +
		"  if (x > 0) {\n" +
		"    return x;\n" +
		"  } else {\n" +
		"    return 0;\n" +
		"  }\n" +
		"};\n"
	if updated != want {
		t.Fatalf("formatted nested text = %q, want %q", updated, want)
	}
}

func TestDocumentFormattingHonorsTabSizeOption(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let answer=fn(x){if (x > 0) {return x;} else {return 0;}};"
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format-tabsize.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format-tabsize.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 4, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok || len(edits) != 1 {
		t.Fatalf("formatting result = %T (len=%d), want one edit", formatAny, len(edits))
	}

	updated := applyTextEdits(t, original, edits)
	want := "let answer = fn(x) {\n" +
		"    if (x > 0) {\n" +
		"        return x;\n" +
		"    } else {\n" +
		"        return 0;\n" +
		"    }\n" +
		"};\n"
	if updated != want {
		t.Fatalf("formatted tabSize text = %q, want %q", updated, want)
	}
}

func TestDocumentFormattingHonorsTabsOption(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let answer=fn(x){if (x > 0) {return x;} else {return 0;}};"
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format-tabs.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format-tabs.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 8, "insertSpaces": false},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok || len(edits) != 1 {
		t.Fatalf("formatting result = %T (len=%d), want one edit", formatAny, len(edits))
	}

	updated := applyTextEdits(t, original, edits)
	want := "let answer = fn(x) {\n" +
		"\tif (x > 0) {\n" +
		"\t\treturn x;\n" +
		"\t} else {\n" +
		"\t\treturn 0;\n" +
		"\t}\n" +
		"};\n"
	if updated != want {
		t.Fatalf("formatted tabs text = %q, want %q", updated, want)
	}
}

func TestDocumentFormattingCanonicalizesCommentedBlocks(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let answer=fn(x){\n" +
		"// keep comment\n" +
		"if(x>0){\n" +
		"return x; // inline\n" +
		"}\n" +
		"\n" +
		"else{\n" +
		"return 0;\n" +
		"}\n" +
		"};"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format-commented-blocks.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format-commented-blocks.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok || len(edits) != 1 {
		t.Fatalf("formatting result = %T (len=%d), want one edit", formatAny, len(edits))
	}

	updated := applyTextEdits(t, original, edits)
	want := "let answer = fn(x) {\n" +
		"  // keep comment\n" +
		"  if (x > 0) {\n" +
		"    return x; // inline\n" +
		"  }\n" +
		"\n" +
		"  else {\n" +
		"    return 0;\n" +
		"  }\n" +
		"};\n"
	if updated != want {
		t.Fatalf("formatted commented block text = %q, want %q", updated, want)
	}
}

func TestDocumentFormattingCanonicalizesStyleTwoOpeningBraces(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "// style-two braces input\n" +
		"let run = fn(x)\n" +
		"{\n" +
		"if(x > 0)\n" +
		"{\n" +
		"return x;\n" +
		"}\n" +
		"else\n" +
		"{\n" +
		"return 0;\n" +
		"}\n" +
		"};\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///format-style-two-braces.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentFormatting),
		Params: mustJSON(t, lsp.DocumentFormattingParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///format-style-two-braces.mut"},
			Options:      lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("formatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("formatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok || len(edits) != 1 {
		t.Fatalf("formatting result = %T (len=%d), want one edit", formatAny, len(edits))
	}

	updated := applyTextEdits(t, original, edits)
	want := "// style-two braces input\n" +
		"let run = fn(x) {\n" +
		"  if (x > 0) {\n" +
		"    return x;\n" +
		"  }\n" +
		"  else {\n" +
		"    return 0;\n" +
		"  }\n" +
		"};\n"
	if updated != want {
		t.Fatalf("formatted style-two text = %q, want %q", updated, want)
	}
}

func TestDocumentOnTypeFormattingFormatsOnSupportedTrigger(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let run = fn(x)\n{\nif(x > 0)\n{\nreturn x;\n}\n};\n"
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///on-type-format.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentOnTypeFormatting),
		Params: mustJSON(t, lsp.DocumentOnTypeFormattingParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///on-type-format.mut"},
				Position:     lsp.Position{Line: 5, Character: 1},
			},
			Ch:      "}",
			Options: lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("onTypeFormatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("onTypeFormatting validity flags = method:%t params:%t", validMethod, validParams)
	}

	edits, ok := formatAny.([]lsp.TextEdit)
	if !ok || len(edits) != 1 {
		t.Fatalf("onTypeFormatting result = %T (len=%d), want one edit", formatAny, len(edits))
	}

	updated := applyTextEdits(t, original, edits)
	want := "let run = fn(x) {\n" +
		"  if (x > 0) {\n" +
		"    return x;\n" +
		"  }\n" +
		"};\n"
	if updated != want {
		t.Fatalf("on-type formatted text = %q, want %q", updated, want)
	}
}

func TestDocumentOnTypeFormattingIgnoresUnsupportedTrigger(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let answer = 1;\n"
	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///on-type-format-unsupported.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	formatAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentOnTypeFormatting),
		Params: mustJSON(t, lsp.DocumentOnTypeFormattingParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///on-type-format-unsupported.mut"},
				Position:     lsp.Position{Line: 0, Character: 3},
			},
			Ch:      "a",
			Options: lsp.FormattingOptions{"tabSize": 2, "insertSpaces": true},
		}),
	})
	if err != nil {
		t.Fatalf("onTypeFormatting returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("onTypeFormatting validity flags = method:%t params:%t", validMethod, validParams)
	}
	if formatAny != nil {
		if edits, ok := formatAny.([]lsp.TextEdit); ok && len(edits) == 0 {
			return
		}
		t.Fatalf("onTypeFormatting result = %T, want nil/empty for unsupported trigger", formatAny)
	}
}

func TestHoverCompletionAndDocumentSymbols(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///mvp.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let answer = fn(x) { x; };\n" +
					"struct Point { x; y; }\n" +
					"enum Color { Red, Blue }\n" +
					"answer(1);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	hoverAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentHover),
		Params: mustJSON(t, lsp.HoverParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///mvp.mut"},
				Position:     lsp.Position{Line: 0, Character: 4},
			},
		}),
	})
	if err != nil {
		t.Fatalf("hover returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("hover validity flags = method:%t params:%t", validMethod, validParams)
	}
	hover, ok := hoverAny.(*lsp.Hover)
	if !ok || hover == nil {
		t.Fatalf("hover result type = %T, want *Hover", hoverAny)
	}
	contents, ok := hover.Contents.(lsp.MarkupContent)
	if !ok {
		t.Fatalf("hover contents type = %T, want MarkupContent", hover.Contents)
	}
	if !strings.Contains(contents.Value, "function `answer(x)`") {
		t.Fatalf("hover contents = %q, want function signature hover for answer", contents.Value)
	}

	completionAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentCompletion),
		Params: mustJSON(t, lsp.CompletionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///mvp.mut"},
				Position:     lsp.Position{Line: 3, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("completion returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("completion validity flags = method:%t params:%t", validMethod, validParams)
	}
	completionList, ok := completionAny.(*lsp.CompletionList)
	if !ok {
		t.Fatalf("completion result type = %T, want *CompletionList", completionAny)
	}
	assertCompletionLabel(t, completionList.Items, "fn")
	assertCompletionLabel(t, completionList.Items, "len")
	assertCompletionLabel(t, completionList.Items, "answer")
	assertCompletionLabel(t, completionList.Items, "Point")
	assertCompletionLabel(t, completionList.Items, "for loop")
	assertCompletionLabel(t, completionList.Items, "function declaration")
	assertCompletionLabel(t, completionList.Items, "if guard return")
	assertCompletionLabel(t, completionList.Items, "for loop over array")
	assertCompletionLabel(t, completionList.Items, "function declaration with docs")
	assertCompletionLabel(t, completionList.Items, "struct value")
	assertCompletionLabel(t, completionList.Items, "enum variant usage")
	assertCompletionSnippet(t, completionList.Items, "for loop")
	assertCompletionSnippet(t, completionList.Items, "function declaration with docs")

	symbolsAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDocumentSymbol),
		Params: mustJSON(t, lsp.DocumentSymbolParams{
			TextDocument: lsp.TextDocumentIdentifier{URI: "file:///mvp.mut"},
		}),
	})
	if err != nil {
		t.Fatalf("documentSymbol returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("documentSymbol validity flags = method:%t params:%t", validMethod, validParams)
	}
	symbols, ok := symbolsAny.([]lsp.DocumentSymbol)
	if !ok {
		t.Fatalf("documentSymbol result type = %T, want []DocumentSymbol", symbolsAny)
	}
	if len(symbols) != 3 {
		t.Fatalf("document symbols = %d, want 3", len(symbols))
	}
	assertSymbol(t, symbols, "answer", lsp.SymbolKindFunction)
	assertSymbol(t, symbols, "Point", lsp.SymbolKindStruct)
	assertSymbol(t, symbols, "Color", lsp.SymbolKindEnum)
	point := findSymbol(t, symbols, "Point")
	if len(point.Children) != 2 {
		t.Fatalf("Point children = %d, want 2", len(point.Children))
	}
	color := findSymbol(t, symbols, "Color")
	if len(color.Children) != 2 {
		t.Fatalf("Color children = %d, want 2", len(color.Children))
	}
}

func TestHoverOnUnresolvedFieldUsageFallsBackToIdentifier(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///hover-field-fallback.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let p = makePoint();\np.x;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	hoverAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentHover),
		Params: mustJSON(t, lsp.HoverParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///hover-field-fallback.mut"},
				Position:     lsp.Position{Line: 1, Character: 2},
			},
		}),
	})
	if err != nil {
		t.Fatalf("hover returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("hover validity flags = method:%t params:%t", validMethod, validParams)
	}
	hover, ok := hoverAny.(*lsp.Hover)
	if !ok || hover == nil {
		t.Fatalf("hover result type = %T, want *Hover", hoverAny)
	}
	contents, ok := hover.Contents.(lsp.MarkupContent)
	if !ok {
		t.Fatalf("hover contents type = %T, want MarkupContent", hover.Contents)
	}
	if contents.Value != "identifier `x`" {
		t.Fatalf("hover contents = %q, want identifier hover for unresolved field usage", contents.Value)
	}
}

func TestHoverOnResolvedStructFieldUsageShowsField(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///hover-field-resolved.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "struct Point { x; y; }\n" +
					"let p = Point { x: 1, y: 2 };\n" +
					"p.x;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	hoverAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentHover),
		Params: mustJSON(t, lsp.HoverParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///hover-field-resolved.mut"},
				Position:     lsp.Position{Line: 2, Character: 2},
			},
		}),
	})
	if err != nil {
		t.Fatalf("hover returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("hover validity flags = method:%t params:%t", validMethod, validParams)
	}
	hover, ok := hoverAny.(*lsp.Hover)
	if !ok || hover == nil {
		t.Fatalf("hover result type = %T, want *Hover", hoverAny)
	}
	contents, ok := hover.Contents.(lsp.MarkupContent)
	if !ok {
		t.Fatalf("hover contents type = %T, want MarkupContent", hover.Contents)
	}
	if contents.Value != "field `x`" {
		t.Fatalf("hover contents = %q, want field hover for resolved struct field usage", contents.Value)
	}
}

func TestHoverOnFunctionIdentifierIncludesSignatureAndDocComment(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///hover-func-doc.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "// Adds two numbers together\n" +
					"let add = fn(a, b) { a + b; };\n" +
					"add(1, 2);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	hoverAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentHover),
		Params: mustJSON(t, lsp.HoverParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///hover-func-doc.mut"},
				Position:     lsp.Position{Line: 2, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("hover returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("hover validity flags = method:%t params:%t", validMethod, validParams)
	}
	hover, ok := hoverAny.(*lsp.Hover)
	if !ok || hover == nil {
		t.Fatalf("hover result type = %T, want *Hover", hoverAny)
	}
	contents, ok := hover.Contents.(lsp.MarkupContent)
	if !ok {
		t.Fatalf("hover contents type = %T, want MarkupContent", hover.Contents)
	}
	if !strings.Contains(contents.Value, "function `add(a, b)`") {
		t.Fatalf("hover contents = %q, want function signature", contents.Value)
	}
	if !strings.Contains(contents.Value, "params: `a`, `b`") {
		t.Fatalf("hover contents = %q, want parameter list", contents.Value)
	}
	if !strings.Contains(contents.Value, "Adds two numbers together") {
		t.Fatalf("hover contents = %q, want doc comment", contents.Value)
	}
}

func TestHoverOnBuiltinIdentifierIncludesTeachingInfo(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///hover-builtin.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let xs = [1, 2, 3];\nlen(xs);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	hoverAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentHover),
		Params: mustJSON(t, lsp.HoverParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///hover-builtin.mut"},
				Position:     lsp.Position{Line: 1, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("hover returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("hover validity flags = method:%t params:%t", validMethod, validParams)
	}
	hover, ok := hoverAny.(*lsp.Hover)
	if !ok || hover == nil {
		t.Fatalf("hover result type = %T, want *Hover", hoverAny)
	}
	contents, ok := hover.Contents.(lsp.MarkupContent)
	if !ok {
		t.Fatalf("hover contents type = %T, want MarkupContent", hover.Contents)
	}
	if !strings.Contains(contents.Value, "builtin `len(value)`") {
		t.Fatalf("hover contents = %q, want builtin signature", contents.Value)
	}
	if !strings.Contains(contents.Value, "Returns the length") {
		t.Fatalf("hover contents = %q, want builtin teaching summary", contents.Value)
	}
}

func TestHoverOnIfKeywordIncludesTeachingInfo(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///hover-if.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "if (true) { 1; } else { 0; }\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	hoverAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentHover),
		Params: mustJSON(t, lsp.HoverParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///hover-if.mut"},
				Position:     lsp.Position{Line: 0, Character: 0},
			},
		}),
	})
	if err != nil {
		t.Fatalf("hover returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("hover validity flags = method:%t params:%t", validMethod, validParams)
	}
	hover, ok := hoverAny.(*lsp.Hover)
	if !ok || hover == nil {
		t.Fatalf("hover result type = %T, want *Hover", hoverAny)
	}
	contents, ok := hover.Contents.(lsp.MarkupContent)
	if !ok {
		t.Fatalf("hover contents type = %T, want MarkupContent", hover.Contents)
	}
	if !strings.Contains(contents.Value, "keyword `if`") {
		t.Fatalf("hover contents = %q, want if keyword heading", contents.Value)
	}
	if !strings.Contains(contents.Value, "Conditional expression") {
		t.Fatalf("hover contents = %q, want if keyword teaching summary", contents.Value)
	}
}

func TestHoverOnResolvedEnumMemberUsageShowsEnumMember(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///hover-enum-member-resolved.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "enum Color { Red, Blue }\n" +
					"let c = Color.Red;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	hoverAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentHover),
		Params: mustJSON(t, lsp.HoverParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///hover-enum-member-resolved.mut"},
				Position:     lsp.Position{Line: 1, Character: 14},
			},
		}),
	})
	if err != nil {
		t.Fatalf("hover returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("hover validity flags = method:%t params:%t", validMethod, validParams)
	}
	hover, ok := hoverAny.(*lsp.Hover)
	if !ok || hover == nil {
		t.Fatalf("hover result type = %T, want *Hover", hoverAny)
	}
	contents, ok := hover.Contents.(lsp.MarkupContent)
	if !ok {
		t.Fatalf("hover contents type = %T, want MarkupContent", hover.Contents)
	}
	if contents.Value != "enum member `Red`" {
		t.Fatalf("hover contents = %q, want enum member hover for resolved enum usage", contents.Value)
	}
}

func TestDefinitionResolvesTopLevelAndParameterBindings(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///def.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let answer = fn(x) { x; };\n" +
					"answer(1);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///def.mut"},
				Position:     lsp.Position{Line: 1, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := defAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", defAny)
	}
	if location.URI != "file:///def.mut" {
		t.Fatalf("definition URI = %q, want file:///def.mut", location.URI)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 4 {
		t.Fatalf("top-level definition start = %+v, want line 0 char 4", location.Range.Start)
	}

	paramAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///def.mut"},
				Position:     lsp.Position{Line: 0, Character: 21},
			},
		}),
	})
	if err != nil {
		t.Fatalf("parameter definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("parameter definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	paramLocation, ok := paramAny.(*lsp.Location)
	if !ok || paramLocation == nil {
		t.Fatalf("parameter definition result type = %T, want *Location", paramAny)
	}
	if paramLocation.Range.Start.Line != 0 || paramLocation.Range.Start.Character != 16 {
		t.Fatalf("parameter definition start = %+v, want line 0 char 16", paramLocation.Range.Start)
	}
}

func TestDefinitionResolvesWorkspaceTopLevelBindingAcrossFiles(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///defs.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///usage.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "shared;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///usage.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := defAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", defAny)
	}
	if location.URI != "file:///defs.mut" {
		t.Fatalf("definition URI = %q, want file:///defs.mut", location.URI)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 4 {
		t.Fatalf("definition start = %+v, want line 0 char 4", location.Range.Start)
	}
}

func TestDefinitionWorkspaceFallbackSkipsAmbiguousTopLevelBindings(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///defs-a.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs-a returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///defs-b.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 2;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs-b returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///usage-ambiguous.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "shared;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///usage-ambiguous.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	if defAny != nil {
		t.Fatalf("definition result = %T, want nil for ambiguous workspace symbol", defAny)
	}
}

func TestDefinitionResolvesEnumMemberUsageToDeclaration(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///def-enum-member.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "enum Color { Red, Blue }\n" +
					"let c = Color.Red;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///def-enum-member.mut"},
				Position:     lsp.Position{Line: 1, Character: 14},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := defAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", defAny)
	}
	if location.URI != "file:///def-enum-member.mut" {
		t.Fatalf("definition URI = %q, want file:///def-enum-member.mut", location.URI)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 13 {
		t.Fatalf("enum member definition start = %+v, want line 0 char 13", location.Range.Start)
	}
}

func TestDefinitionResolvesEnumMemberDeclarationToItself(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///def-enum-member-decl.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "enum Color { Red, Blue }\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///def-enum-member-decl.mut"},
				Position:     lsp.Position{Line: 0, Character: 14},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := defAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", defAny)
	}
	if location.URI != "file:///def-enum-member-decl.mut" {
		t.Fatalf("definition URI = %q, want file:///def-enum-member-decl.mut", location.URI)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 13 {
		t.Fatalf("enum member declaration definition start = %+v, want line 0 char 13", location.Range.Start)
	}
}

func TestDefinitionResolvesStructLiteralKeyToFieldDeclaration(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///def-struct-key.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "struct Point { x; y; }\n" +
					"let p = Point { x: 1, y: 2 };\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///def-struct-key.mut"},
				Position:     lsp.Position{Line: 1, Character: 16},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := defAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", defAny)
	}
	if location.URI != "file:///def-struct-key.mut" {
		t.Fatalf("definition URI = %q, want file:///def-struct-key.mut", location.URI)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 15 {
		t.Fatalf("struct field definition start = %+v, want line 0 char 15", location.Range.Start)
	}
}

func TestDefinitionDisambiguatesStructFieldByType(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///def-field-disambiguation.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "struct Point { x; y; }\n" +
					"struct Vector { x; y; }\n" +
					"let p = Point { x: 1, y: 2 };\n" +
					"let v = Vector { x: 3, y: 4 };\n" +
					"p.x;\n" +
					"v.x;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///def-field-disambiguation.mut"},
				Position:     lsp.Position{Line: 4, Character: 2},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := defAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", defAny)
	}
	if location.URI != "file:///def-field-disambiguation.mut" {
		t.Fatalf("definition URI = %q, want file:///def-field-disambiguation.mut", location.URI)
	}
	if location.Range.Start.Line != 0 || location.Range.Start.Character != 15 {
		t.Fatalf("p.x definition start = %+v, want line 0 char 15 (Point.x)", location.Range.Start)
	}
}

func TestDefinitionDisambiguatesStructFieldByTypeForVector(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///def-field-disambiguation-vector.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "struct Point { x; y; }\n" +
					"struct Vector { x; y; }\n" +
					"let p = Point { x: 1, y: 2 };\n" +
					"let v = Vector { x: 3, y: 4 };\n" +
					"p.x;\n" +
					"v.x;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///def-field-disambiguation-vector.mut"},
				Position:     lsp.Position{Line: 5, Character: 2},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := defAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", defAny)
	}
	if location.URI != "file:///def-field-disambiguation-vector.mut" {
		t.Fatalf("definition URI = %q, want file:///def-field-disambiguation-vector.mut", location.URI)
	}
	if location.Range.Start.Line != 1 || location.Range.Start.Character != 16 {
		t.Fatalf("v.x definition start = %+v, want line 1 char 16 (Vector.x)", location.Range.Start)
	}
}

func TestCompletionIncludesVisibleScopeBindings(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///scope.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let answer = fn(x) {\n" +
					"  let inner = x;\n" +
					"  inner;\n" +
					"};\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	completionAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentCompletion),
		Params: mustJSON(t, lsp.CompletionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///scope.mut"},
				Position:     lsp.Position{Line: 2, Character: 4},
			},
		}),
	})
	if err != nil {
		t.Fatalf("completion returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("completion validity flags = method:%t params:%t", validMethod, validParams)
	}
	completionList, ok := completionAny.(*lsp.CompletionList)
	if !ok {
		t.Fatalf("completion result type = %T, want *CompletionList", completionAny)
	}
	assertCompletionLabel(t, completionList.Items, "answer")
	assertCompletionLabel(t, completionList.Items, "x")
	assertCompletionLabel(t, completionList.Items, "inner")
	if indexCompletionLabel(t, completionList.Items, "inner") >= indexCompletionLabel(t, completionList.Items, "fn") {
		t.Fatalf("expected local binding %q before keyword %q", "inner", "fn")
	}
	if indexCompletionLabel(t, completionList.Items, "inner") >= indexCompletionLabel(t, completionList.Items, "len") {
		t.Fatalf("expected local binding %q before builtin %q", "inner", "len")
	}
}

func TestCompletionIsDeterministicAcrossRepeatedRequests(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///completion-deterministic.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let zebra = 1;\n" +
					"let alpha = 2;\n" +
					"struct Point { x; y; }\n" +
					"enum Color { Red, Blue }\n" +
					"let answer = fn(x) {\n" +
					"  let inner = x;\n" +
					"  inn\n" +
					"};\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	requestCompletion := func() []string {
		t.Helper()
		completionAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
			Method: string(lsp.MethodTextDocumentCompletion),
			Params: mustJSON(t, lsp.CompletionParams{
				TextDocumentPositionParams: lsp.TextDocumentPositionParams{
					TextDocument: lsp.TextDocumentIdentifier{URI: "file:///completion-deterministic.mut"},
					Position:     lsp.Position{Line: 6, Character: 4},
				},
			}),
		})
		if err != nil {
			t.Fatalf("completion returned error: %v", err)
		}
		if !validMethod || !validParams {
			t.Fatalf("completion validity flags = method:%t params:%t", validMethod, validParams)
		}
		completionList, ok := completionAny.(*lsp.CompletionList)
		if !ok {
			t.Fatalf("completion result type = %T, want *CompletionList", completionAny)
		}

		out := make([]string, 0, len(completionList.Items))
		for _, item := range completionList.Items {
			sortText := ""
			if item.SortText != nil {
				sortText = *item.SortText
			}
			out = append(out, item.Label+"|"+sortText)
		}
		return out
	}

	first := requestCompletion()
	second := requestCompletion()

	if len(first) != len(second) {
		t.Fatalf("completion item count differs between runs: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("completion mismatch at index %d: %q vs %q", i, first[i], second[i])
		}
	}
}

func TestReferencesResolveLexicalBindings(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let answer = fn(x) {\n" +
					"  let inner = x;\n" +
					"  inner + x;\n" +
					"};\n" +
					"answer(1);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs.mut"},
				Position:     lsp.Position{Line: 2, Character: 4},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2", len(locations))
	}
	assertLocationStart(t, locations, 1, 6)
	assertLocationStart(t, locations, 2, 2)

	referencesAny, validMethod, validParams, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs.mut"},
				Position:     lsp.Position{Line: 2, Character: 4},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: false},
		}),
	})
	if err != nil {
		t.Fatalf("references without declaration returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references without declaration validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok = referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references without declaration result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 1 {
		t.Fatalf("reference count without declaration = %d, want 1", len(locations))
	}
	assertLocationStart(t, locations, 2, 2)
}

func TestReferencesResolveWorkspaceTopLevelBindingAcrossFiles(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-defs.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-usage.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "shared + 1;\nshared;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs-usage.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 3 {
		t.Fatalf("reference count = %d, want 3", len(locations))
	}
	assertLocationURIStart(t, locations, "file:///refs-defs.mut", 0, 4)
	assertLocationURIStart(t, locations, "file:///refs-usage.mut", 0, 0)
	assertLocationURIStart(t, locations, "file:///refs-usage.mut", 1, 0)

	referencesAny, validMethod, validParams, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs-usage.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: false},
		}),
	})
	if err != nil {
		t.Fatalf("references without declaration returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references without declaration validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok = referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references without declaration result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 2 {
		t.Fatalf("reference count without declaration = %d, want 2", len(locations))
	}
	assertLocationURIStart(t, locations, "file:///refs-usage.mut", 0, 0)
	assertLocationURIStart(t, locations, "file:///refs-usage.mut", 1, 0)
}

func TestReferencesWorkspaceFallbackSkipsAmbiguousTopLevelBindings(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-defs-a.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs-a returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-defs-b.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 2;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs-b returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-usage-ambiguous.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "shared;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs-usage-ambiguous.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	if referencesAny != nil {
		if locations, ok := referencesAny.([]lsp.Location); ok && len(locations) == 0 {
			return
		}
		t.Fatalf("references result = %T, want nil/empty for ambiguous workspace symbol", referencesAny)
	}
}

func TestPrepareRenameAndRenameWorkspaceEdit(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename.mut",
				LanguageID: "mutant",
				Version:    1,
				Text: "let answer = fn(x) {\n" +
					"  let inner = x;\n" +
					"  inner + x;\n" +
					"};\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename.mut"},
				Position:     lsp.Position{Line: 2, Character: 4},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename validity flags = method:%t params:%t", validMethod, validParams)
	}
	rangeWithPlaceholder, ok := prepareAny.(*lsp.RangeWithPlaceholder)
	if !ok || rangeWithPlaceholder == nil {
		t.Fatalf("prepareRename result type = %T, want *RangeWithPlaceholder", prepareAny)
	}
	if rangeWithPlaceholder.Placeholder != "inner" {
		t.Fatalf("prepareRename placeholder = %q, want inner", rangeWithPlaceholder.Placeholder)
	}
	if rangeWithPlaceholder.Range.Start.Line != 2 || rangeWithPlaceholder.Range.Start.Character != 2 {
		t.Fatalf("prepareRename start = %+v, want line 2 char 2", rangeWithPlaceholder.Range.Start)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename.mut"},
				Position:     lsp.Position{Line: 2, Character: 4},
			},
			NewName: "value",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///rename.mut"]
	if len(changes) != 2 {
		t.Fatalf("rename edit count = %d, want 2", len(changes))
	}
	assertTextEdit(t, changes, 1, 6, "value")
	assertTextEdit(t, changes, 2, 2, "value")
}

func TestPrepareRenameResolvesWorkspaceTopLevelBindingAcrossFiles(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-defs.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-usage.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "shared;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-usage.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename validity flags = method:%t params:%t", validMethod, validParams)
	}
	rangeWithPlaceholder, ok := prepareAny.(*lsp.RangeWithPlaceholder)
	if !ok || rangeWithPlaceholder == nil {
		t.Fatalf("prepareRename result type = %T, want *RangeWithPlaceholder", prepareAny)
	}
	if rangeWithPlaceholder.Placeholder != "shared" {
		t.Fatalf("prepareRename placeholder = %q, want shared", rangeWithPlaceholder.Placeholder)
	}
	if rangeWithPlaceholder.Range.Start.Line != 0 || rangeWithPlaceholder.Range.Start.Character != 0 {
		t.Fatalf("prepareRename start = %+v, want line 0 char 0", rangeWithPlaceholder.Range.Start)
	}
}

func TestPrepareRenameWorkspaceFallbackSkipsAmbiguousTopLevelBindings(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-defs-a.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs-a returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-defs-b.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 2;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs-b returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-usage-ambiguous.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "shared;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-usage-ambiguous.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename validity flags = method:%t params:%t", validMethod, validParams)
	}
	if prepareAny != nil {
		t.Fatalf("prepareRename result = %T, want nil for ambiguous workspace symbol", prepareAny)
	}
}

func TestRenameResolvesWorkspaceTopLevelBindingAcrossFiles(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-defs.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-usage.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "shared + 1;\nshared;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-usage.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
			NewName: "value",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	defsChanges := edit.Changes["file:///rename-defs.mut"]
	usageChanges := edit.Changes["file:///rename-usage.mut"]
	if len(defsChanges) != 1 {
		t.Fatalf("defs rename edit count = %d, want 1", len(defsChanges))
	}
	if len(usageChanges) != 2 {
		t.Fatalf("usage rename edit count = %d, want 2", len(usageChanges))
	}
	assertTextEdit(t, defsChanges, 0, 4, "value")
	assertTextEdit(t, usageChanges, 0, 0, "value")
	assertTextEdit(t, usageChanges, 1, 0, "value")
}

func TestRenameWorkspaceFallbackSkipsAmbiguousTopLevelBindings(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-defs-a.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 1;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs-a returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-defs-b.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let shared = 2;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen defs-b returned error: %v", err)
	}

	_, _, _, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-usage-ambiguous.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "shared;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen usage returned error: %v", err)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-usage-ambiguous.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
			NewName: "value",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	if renameAny != nil {
		if edit, ok := renameAny.(*lsp.WorkspaceEdit); ok && edit == nil {
			return
		}
		t.Fatalf("rename result = %T, want nil/empty for ambiguous workspace symbol", renameAny)
	}
}

func TestPrepareRenameRejectsNonIdentifierPosition(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-invalid.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let answer = 1;\nanswer;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-invalid.mut"},
				Position:     lsp.Position{Line: 0, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename validity flags = method:%t params:%t", validMethod, validParams)
	}
	if prepareAny != nil {
		t.Fatalf("prepareRename result = %T, want nil for non-identifier position", prepareAny)
	}
}

func TestRenameRejectsInvalidNewName(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-invalid.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let answer = 1;\nanswer;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-invalid.mut"},
				Position:     lsp.Position{Line: 1, Character: 1},
			},
			NewName: "1value",
		}),
	})
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	if err == nil {
		t.Fatal("rename expected error for invalid newName, got nil")
	}
}

func TestRenameRejectsKeywordNewName(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-keyword.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let answer = 1;\nanswer;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-keyword.mut"},
				Position:     lsp.Position{Line: 1, Character: 1},
			},
			NewName: "let",
		}),
	})
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	if err == nil {
		t.Fatal("rename expected error for keyword newName, got nil")
	}
}

func TestRenameWorkspaceEditAppliesToDocumentText(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let answer = fn(x) {\n" +
		"  let inner = x;\n" +
		"  inner + x;\n" +
		"};\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-apply.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-apply.mut"},
				Position:     lsp.Position{Line: 2, Character: 4},
			},
			NewName: "value",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///rename-apply.mut"]
	if len(changes) != 2 {
		t.Fatalf("rename edit count = %d, want 2", len(changes))
	}

	updated := applyTextEdits(t, original, changes)
	want := "let answer = fn(x) {\n" +
		"  let value = x;\n" +
		"  value + x;\n" +
		"};\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestPrepareRenameRejectsBuiltinUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-builtin.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let xs = [1, 2];\nlen(xs);\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-builtin.mut"},
				Position:     lsp.Position{Line: 1, Character: 1},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename validity flags = method:%t params:%t", validMethod, validParams)
	}
	if prepareAny != nil {
		t.Fatalf("prepareRename result = %T, want nil for builtin usage", prepareAny)
	}
}

func TestRenameRespectsLexicalShadowing(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let x = 1;\n" +
		"let f = fn() {\n" +
		"  let x = 2;\n" +
		"  x;\n" +
		"};\n" +
		"x;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-shadow.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-shadow.mut"},
				Position:     lsp.Position{Line: 3, Character: 2},
			},
			NewName: "inner",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///rename-shadow.mut"]
	if len(changes) != 2 {
		t.Fatalf("rename edit count = %d, want 2", len(changes))
	}
	assertTextEdit(t, changes, 2, 6, "inner")
	assertTextEdit(t, changes, 3, 2, "inner")

	updated := applyTextEdits(t, original, changes)
	want := "let x = 1;\n" +
		"let f = fn() {\n" +
		"  let inner = 2;\n" +
		"  inner;\n" +
		"};\n" +
		"x;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestRenameOuterBindingDoesNotRenameShadowedInner(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let x = 1;\n" +
		"let f = fn() {\n" +
		"  let x = 2;\n" +
		"  x;\n" +
		"};\n" +
		"x;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-shadow-outer.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-shadow-outer.mut"},
				Position:     lsp.Position{Line: 5, Character: 0},
			},
			NewName: "outer",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///rename-shadow-outer.mut"]
	if len(changes) != 2 {
		t.Fatalf("rename edit count = %d, want 2", len(changes))
	}
	assertTextEdit(t, changes, 0, 4, "outer")
	assertTextEdit(t, changes, 5, 0, "outer")

	updated := applyTextEdits(t, original, changes)
	want := "let outer = 1;\n" +
		"let f = fn() {\n" +
		"  let x = 2;\n" +
		"  x;\n" +
		"};\n" +
		"outer;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestPrepareRenameAndRenameSupportStructFieldUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "struct Point { x; y; }\n" +
		"let p = Point { x: 1, y: 2 };\n" +
		"p.x;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-field.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-field.mut"},
				Position:     lsp.Position{Line: 2, Character: 3},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename validity flags = method:%t params:%t", validMethod, validParams)
	}
	fieldRange, ok := prepareAny.(*lsp.RangeWithPlaceholder)
	if !ok || fieldRange == nil {
		t.Fatalf("prepareRename result type = %T, want *RangeWithPlaceholder", prepareAny)
	}
	if fieldRange.Placeholder != "x" {
		t.Fatalf("prepareRename placeholder = %q, want x", fieldRange.Placeholder)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-field.mut"},
				Position:     lsp.Position{Line: 2, Character: 3},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 3 {
		t.Fatalf("reference count = %d, want 3", len(locations))
	}
	assertLocationStart(t, locations, 0, 15)
	assertLocationStart(t, locations, 1, 16)
	assertLocationStart(t, locations, 2, 2)

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-field.mut"},
				Position:     lsp.Position{Line: 2, Character: 3},
			},
			NewName: "xcoord",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///prepare-field.mut"]
	if len(changes) != 3 {
		t.Fatalf("rename edit count = %d, want 3", len(changes))
	}
	assertTextEdit(t, changes, 0, 15, "xcoord")
	assertTextEdit(t, changes, 1, 16, "xcoord")
	assertTextEdit(t, changes, 2, 2, "xcoord")

	updated := applyTextEdits(t, original, changes)
	want := "struct Point { xcoord; y; }\n" +
		"let p = Point { xcoord: 1, y: 2 };\n" +
		"p.xcoord;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestStructFieldResolutionDisambiguatesByStructType(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "struct Point { x; y; }\n" +
		"struct Vector { x; y; }\n" +
		"let p = Point { x: 1, y: 2 };\n" +
		"let v = Vector { x: 3, y: 4 };\n" +
		"p.x;\n" +
		"v.x;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///field-disambiguation.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///field-disambiguation.mut"},
				Position:     lsp.Position{Line: 4, Character: 2},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 3 {
		t.Fatalf("reference count = %d, want 3", len(locations))
	}
	assertLocationStart(t, locations, 0, 15)
	assertLocationStart(t, locations, 2, 16)
	assertLocationStart(t, locations, 4, 2)
	assertLocationNotStart(t, locations, 1, 16)
	assertLocationNotStart(t, locations, 3, 17)
	assertLocationNotStart(t, locations, 5, 2)

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///field-disambiguation.mut"},
				Position:     lsp.Position{Line: 4, Character: 2},
			},
			NewName: "xcoord",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///field-disambiguation.mut"]
	if len(changes) != 3 {
		t.Fatalf("rename edit count = %d, want 3", len(changes))
	}
	assertTextEdit(t, changes, 0, 15, "xcoord")
	assertTextEdit(t, changes, 2, 16, "xcoord")
	assertTextEdit(t, changes, 4, 2, "xcoord")

	updated := applyTextEdits(t, original, changes)
	want := "struct Point { xcoord; y; }\n" +
		"struct Vector { x; y; }\n" +
		"let p = Point { xcoord: 1, y: 2 };\n" +
		"let v = Vector { x: 3, y: 4 };\n" +
		"p.xcoord;\n" +
		"v.x;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestStructFieldUsageWithoutTypeInferenceFallsBackSafely(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///field-unknown-type.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "let p = makePoint();\np.x;\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	defAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDefinition),
		Params: mustJSON(t, lsp.DefinitionParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///field-unknown-type.mut"},
				Position:     lsp.Position{Line: 1, Character: 2},
			},
		}),
	})
	if err != nil {
		t.Fatalf("definition returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("definition validity flags = method:%t params:%t", validMethod, validParams)
	}
	location, ok := defAny.(*lsp.Location)
	if !ok || location == nil {
		t.Fatalf("definition result type = %T, want *Location", defAny)
	}
	if location.Range.Start.Line != 1 || location.Range.Start.Character != 2 {
		t.Fatalf("definition start = %+v, want line 1 char 2 (usage fallback)", location.Range.Start)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///field-unknown-type.mut"},
				Position:     lsp.Position{Line: 1, Character: 2},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	if referencesAny != nil {
		if locations, ok := referencesAny.([]lsp.Location); ok && len(locations) == 0 {
			// typed nil/empty slice is acceptable fallback for no references
		} else {
			t.Fatalf("references result = %T, want nil/empty when field declaration cannot be inferred", referencesAny)
		}
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///field-unknown-type.mut"},
				Position:     lsp.Position{Line: 1, Character: 2},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename validity flags = method:%t params:%t", validMethod, validParams)
	}
	if prepareAny != nil {
		t.Fatalf("prepareRename result = %T, want nil when field declaration cannot be inferred", prepareAny)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///field-unknown-type.mut"},
				Position:     lsp.Position{Line: 1, Character: 2},
			},
			NewName: "field",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	if renameAny != nil {
		if edit, ok := renameAny.(*lsp.WorkspaceEdit); ok && edit == nil {
			// typed nil pointer is acceptable fallback for no workspace edit
		} else {
			t.Fatalf("rename result = %T, want nil when field declaration cannot be inferred", renameAny)
		}
	}
}

func TestReferencesRespectLexicalShadowingInnerBinding(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let x = 1;\n" +
		"let f = fn() {\n" +
		"  let x = 2;\n" +
		"  x;\n" +
		"};\n" +
		"x;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-shadow-inner.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs-shadow-inner.mut"},
				Position:     lsp.Position{Line: 3, Character: 2},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2", len(locations))
	}
	assertLocationStart(t, locations, 2, 6)
	assertLocationStart(t, locations, 3, 2)
	assertLocationNotStart(t, locations, 0, 4)
	assertLocationNotStart(t, locations, 5, 0)
}

func TestReferencesRespectLexicalShadowingOuterBinding(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let x = 1;\n" +
		"let f = fn() {\n" +
		"  let x = 2;\n" +
		"  x;\n" +
		"};\n" +
		"x;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-shadow-outer.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs-shadow-outer.mut"},
				Position:     lsp.Position{Line: 5, Character: 0},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2", len(locations))
	}
	assertLocationStart(t, locations, 0, 4)
	assertLocationStart(t, locations, 5, 0)
	assertLocationNotStart(t, locations, 2, 6)
	assertLocationNotStart(t, locations, 3, 2)
}

func TestPrepareRenameSupportsStructAndEnumDeclarations(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-types.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       "struct Point { x; y; }\nenum Color { Red, Blue }\n",
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-types.mut"},
				Position:     lsp.Position{Line: 0, Character: 8},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename on struct returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename struct validity flags = method:%t params:%t", validMethod, validParams)
	}
	structRange, ok := prepareAny.(*lsp.RangeWithPlaceholder)
	if !ok || structRange == nil {
		t.Fatalf("prepareRename struct result type = %T, want *RangeWithPlaceholder", prepareAny)
	}
	if structRange.Placeholder != "Point" {
		t.Fatalf("prepareRename struct placeholder = %q, want Point", structRange.Placeholder)
	}

	prepareAny, validMethod, validParams, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-types.mut"},
				Position:     lsp.Position{Line: 1, Character: 6},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename on enum returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename enum validity flags = method:%t params:%t", validMethod, validParams)
	}
	enumRange, ok := prepareAny.(*lsp.RangeWithPlaceholder)
	if !ok || enumRange == nil {
		t.Fatalf("prepareRename enum result type = %T, want *RangeWithPlaceholder", prepareAny)
	}
	if enumRange.Placeholder != "Color" {
		t.Fatalf("prepareRename enum placeholder = %q, want Color", enumRange.Placeholder)
	}
}

func TestRenameStructDeclarationAndUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "struct Point { x; y; }\n" +
		"let p = Point { x: 1, y: 2 };\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-struct.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-struct.mut"},
				Position:     lsp.Position{Line: 1, Character: 8},
			},
			NewName: "Coord",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///rename-struct.mut"]
	if len(changes) != 2 {
		t.Fatalf("rename edit count = %d, want 2", len(changes))
	}
	assertTextEdit(t, changes, 0, 7, "Coord")
	assertTextEdit(t, changes, 1, 8, "Coord")

	updated := applyTextEdits(t, original, changes)
	want := "struct Coord { x; y; }\n" +
		"let p = Coord { x: 1, y: 2 };\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestRenameEnumDeclarationAndUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "enum Color { Red, Blue }\n" +
		"let c = Color.Red;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///rename-enum.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///rename-enum.mut"},
				Position:     lsp.Position{Line: 1, Character: 8},
			},
			NewName: "Shade",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///rename-enum.mut"]
	if len(changes) != 2 {
		t.Fatalf("rename edit count = %d, want 2", len(changes))
	}
	assertTextEdit(t, changes, 0, 5, "Shade")
	assertTextEdit(t, changes, 1, 8, "Shade")

	updated := applyTextEdits(t, original, changes)
	want := "enum Shade { Red, Blue }\n" +
		"let c = Shade.Red;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestReferencesAndRenameForMultiNameLetBinding(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "let a, b = 1;\n" +
		"a;\n" +
		"b;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///multiname.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///multiname.mut"},
				Position:     lsp.Position{Line: 2, Character: 0},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2", len(locations))
	}
	assertLocationStart(t, locations, 0, 7)
	assertLocationStart(t, locations, 2, 0)
	assertLocationNotStart(t, locations, 0, 4)
	assertLocationNotStart(t, locations, 1, 0)

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///multiname.mut"},
				Position:     lsp.Position{Line: 2, Character: 0},
			},
			NewName: "second",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///multiname.mut"]
	if len(changes) != 2 {
		t.Fatalf("rename edit count = %d, want 2", len(changes))
	}
	assertTextEdit(t, changes, 0, 7, "second")
	assertTextEdit(t, changes, 2, 0, "second")

	updated := applyTextEdits(t, original, changes)
	want := "let a, second = 1;\n" +
		"a;\n" +
		"second;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

func TestReferencesForStructDeclarationAndUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "struct Point { x; y; }\n" +
		"let p = Point { x: 1, y: 2 };\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-struct.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs-struct.mut"},
				Position:     lsp.Position{Line: 1, Character: 8},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2", len(locations))
	}
	assertLocationStart(t, locations, 0, 7)
	assertLocationStart(t, locations, 1, 8)
}

func TestReferencesForEnumDeclarationAndUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "enum Color { Red, Blue }\n" +
		"let c = Color.Red;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///refs-enum.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///refs-enum.mut"},
				Position:     lsp.Position{Line: 1, Character: 8},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2", len(locations))
	}
	assertLocationStart(t, locations, 0, 5)
	assertLocationStart(t, locations, 1, 8)
}

func TestPrepareRenameAndRenameSupportEnumMemberUsage(t *testing.T) {
	s := New(false)
	initializeServer(t, s)

	original := "enum Color { Red, Blue }\n" +
		"let c = Color.Red;\n"

	_, _, _, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentDidOpen),
		Params: mustJSON(t, lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{
				URI:        "file:///prepare-enum-member.mut",
				LanguageID: "mutant",
				Version:    1,
				Text:       original,
			},
		}),
		Notify: func(string, any) {},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	prepareAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentPrepareRename),
		Params: mustJSON(t, lsp.PrepareRenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-enum-member.mut"},
				Position:     lsp.Position{Line: 1, Character: 14},
			},
		}),
	})
	if err != nil {
		t.Fatalf("prepareRename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("prepareRename validity flags = method:%t params:%t", validMethod, validParams)
	}
	memberRange, ok := prepareAny.(*lsp.RangeWithPlaceholder)
	if !ok || memberRange == nil {
		t.Fatalf("prepareRename result type = %T, want *RangeWithPlaceholder", prepareAny)
	}
	if memberRange.Placeholder != "Red" {
		t.Fatalf("prepareRename placeholder = %q, want Red", memberRange.Placeholder)
	}

	referencesAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentReferences),
		Params: mustJSON(t, lsp.ReferenceParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-enum-member.mut"},
				Position:     lsp.Position{Line: 1, Character: 14},
			},
			Context: lsp.ReferenceContext{IncludeDeclaration: true},
		}),
	})
	if err != nil {
		t.Fatalf("references returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("references validity flags = method:%t params:%t", validMethod, validParams)
	}
	locations, ok := referencesAny.([]lsp.Location)
	if !ok {
		t.Fatalf("references result type = %T, want []Location", referencesAny)
	}
	if len(locations) != 2 {
		t.Fatalf("reference count = %d, want 2", len(locations))
	}
	assertLocationStart(t, locations, 0, 13)
	assertLocationStart(t, locations, 1, 14)

	renameAny, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodTextDocumentRename),
		Params: mustJSON(t, lsp.RenameParams{
			TextDocumentPositionParams: lsp.TextDocumentPositionParams{
				TextDocument: lsp.TextDocumentIdentifier{URI: "file:///prepare-enum-member.mut"},
				Position:     lsp.Position{Line: 1, Character: 14},
			},
			NewName: "Crimson",
		}),
	})
	if err != nil {
		t.Fatalf("rename returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("rename validity flags = method:%t params:%t", validMethod, validParams)
	}
	edit, ok := renameAny.(*lsp.WorkspaceEdit)
	if !ok || edit == nil {
		t.Fatalf("rename result type = %T, want *WorkspaceEdit", renameAny)
	}
	changes := edit.Changes["file:///prepare-enum-member.mut"]
	if len(changes) != 2 {
		t.Fatalf("rename edit count = %d, want 2", len(changes))
	}
	assertTextEdit(t, changes, 0, 13, "Crimson")
	assertTextEdit(t, changes, 1, 14, "Crimson")

	updated := applyTextEdits(t, original, changes)
	want := "enum Color { Crimson, Blue }\n" +
		"let c = Color.Crimson;\n"
	if updated != want {
		t.Fatalf("updated text = %q, want %q", updated, want)
	}
}

type capturedNotification struct {
	method string
	params any
}

func initializeServer(t *testing.T, s *Server) {
	t.Helper()
	_, validMethod, validParams, err := s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialize),
		Params: mustJSON(t, lsp.InitializeParams{}),
	})
	if err != nil {
		t.Fatalf("initialize returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("initialize validity flags = method:%t params:%t", validMethod, validParams)
	}

	_, validMethod, validParams, err = s.handler.Handle(&glsp.Context{
		Method: string(lsp.MethodInitialized),
		Params: mustJSON(t, lsp.InitializedParams{}),
	})
	if err != nil {
		t.Fatalf("initialized returned error: %v", err)
	}
	if !validMethod || !validParams {
		t.Fatalf("initialized validity flags = method:%t params:%t", validMethod, validParams)
	}
}

func onlyDiagnosticsNotification(t *testing.T, notifications []capturedNotification) lsp.PublishDiagnosticsParams {
	t.Helper()
	if len(notifications) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(notifications))
	}
	if notifications[0].method != string(lsp.ServerTextDocumentPublishDiagnostics) {
		t.Fatalf("notification method = %q, want %q", notifications[0].method, lsp.ServerTextDocumentPublishDiagnostics)
	}
	params, ok := notifications[0].params.(lsp.PublishDiagnosticsParams)
	if !ok {
		t.Fatalf("notification params type = %T, want PublishDiagnosticsParams", notifications[0].params)
	}
	return params
}

func assertCompletionLabel(t *testing.T, items []lsp.CompletionItem, want string) {
	t.Helper()
	for _, item := range items {
		if item.Label == want {
			return
		}
	}
	t.Fatalf("completion item %q not found", want)
}

func assertCompletionSnippet(t *testing.T, items []lsp.CompletionItem, want string) {
	t.Helper()
	for _, item := range items {
		if item.Label != want {
			continue
		}
		if item.InsertTextFormat == nil || *item.InsertTextFormat != lsp.InsertTextFormatSnippet {
			t.Fatalf("completion item %q insert format = %#v, want snippet", want, item.InsertTextFormat)
		}
		if item.InsertText == nil || *item.InsertText == "" {
			t.Fatalf("completion item %q insert text is empty", want)
		}
		return
	}
	t.Fatalf("completion snippet %q not found", want)
}

func indexCompletionLabel(t *testing.T, items []lsp.CompletionItem, want string) int {
	t.Helper()
	for idx, item := range items {
		if item.Label == want {
			return idx
		}
	}
	t.Fatalf("completion item %q not found", want)
	return -1
}

func assertSymbol(t *testing.T, symbols []lsp.DocumentSymbol, wantName string, wantKind lsp.SymbolKind) {
	t.Helper()
	symbol := findSymbol(t, symbols, wantName)
	if symbol.Kind != wantKind {
		t.Fatalf("symbol %q kind = %v, want %v", wantName, symbol.Kind, wantKind)
	}
}

func findSymbol(t *testing.T, symbols []lsp.DocumentSymbol, wantName string) lsp.DocumentSymbol {
	t.Helper()
	for _, symbol := range symbols {
		if symbol.Name == wantName {
			return symbol
		}
	}
	t.Fatalf("symbol %q not found", wantName)
	return lsp.DocumentSymbol{}
}

func assertLocationStart(t *testing.T, locations []lsp.Location, wantLine, wantCharacter uint32) {
	t.Helper()
	for _, location := range locations {
		if location.Range.Start.Line == wantLine && location.Range.Start.Character == wantCharacter {
			return
		}
	}
	t.Fatalf("location line=%d char=%d not found", wantLine, wantCharacter)
}

func assertLocationURIStart(t *testing.T, locations []lsp.Location, wantURI lsp.DocumentUri, wantLine, wantCharacter uint32) {
	t.Helper()
	for _, location := range locations {
		if location.URI == wantURI && location.Range.Start.Line == wantLine && location.Range.Start.Character == wantCharacter {
			return
		}
	}
	t.Fatalf("location uri=%q line=%d char=%d not found", wantURI, wantLine, wantCharacter)
}

func assertLocationNotStart(t *testing.T, locations []lsp.Location, line, character uint32) {
	t.Helper()
	for _, location := range locations {
		if location.Range.Start.Line == line && location.Range.Start.Character == character {
			t.Fatalf("unexpected location line=%d char=%d present", line, character)
		}
	}
}

func assertTextEdit(t *testing.T, edits []lsp.TextEdit, wantLine, wantCharacter uint32, wantNewText string) {
	t.Helper()
	for _, edit := range edits {
		if edit.Range.Start.Line == wantLine && edit.Range.Start.Character == wantCharacter && edit.NewText == wantNewText {
			return
		}
	}
	t.Fatalf("text edit line=%d char=%d newText=%q not found", wantLine, wantCharacter, wantNewText)
}

func applyTextEdits(t *testing.T, current string, edits []lsp.TextEdit) string {
	t.Helper()
	ordered := make([]lsp.TextEdit, len(edits))
	copy(ordered, edits)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Range.Start.Line != ordered[j].Range.Start.Line {
			return ordered[i].Range.Start.Line > ordered[j].Range.Start.Line
		}
		return ordered[i].Range.Start.Character > ordered[j].Range.Start.Character
	})

	updated := current
	for _, edit := range ordered {
		start, end := edit.Range.IndexesIn(updated)
		if start < 0 || end < start || end > len(updated) {
			t.Fatalf("invalid text edit range: %d..%d", start, end)
		}
		updated = updated[:start] + edit.NewText + updated[end:]
	}
	return updated
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return b
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func diagnosticMessages(diagnostics []lsp.Diagnostic) []string {
	messages := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		messages = append(messages, diagnostic.Message)
	}
	return messages
}

type decodedSemanticToken struct {
	line   uint32
	start  uint32
	length uint32
	typeID uint32
	mod    uint32
}

func decodeSemanticTokens(t *testing.T, data []lsp.UInteger) []decodedSemanticToken {
	t.Helper()
	if len(data)%5 != 0 {
		t.Fatalf("semantic tokens data length = %d, want multiple of 5", len(data))
	}

	tokens := make([]decodedSemanticToken, 0, len(data)/5)
	var line uint32
	var start uint32
	for i := 0; i < len(data); i += 5 {
		deltaLine := uint32(data[i])
		deltaStart := uint32(data[i+1])
		length := uint32(data[i+2])
		typeID := uint32(data[i+3])
		mod := uint32(data[i+4])

		if deltaLine == 0 {
			start += deltaStart
		} else {
			line += deltaLine
			start = deltaStart
		}

		tokens = append(tokens, decodedSemanticToken{
			line:   line,
			start:  start,
			length: length,
			typeID: typeID,
			mod:    mod,
		})
	}

	return tokens
}

func tokenTypeID(t *testing.T, tokenTypes []string, name string) uint32 {
	t.Helper()
	for i, tokenType := range tokenTypes {
		if tokenType == name {
			return uint32(i)
		}
	}
	t.Fatalf("semantic token type %q not found in legend %#v", name, tokenTypes)
	return 0
}

func tokenModifierBit(t *testing.T, tokenModifiers []string, name string) uint32 {
	t.Helper()
	for i, tokenModifier := range tokenModifiers {
		if tokenModifier == name {
			return 1 << uint32(i)
		}
	}
	t.Fatalf("semantic token modifier %q not found in legend %#v", name, tokenModifiers)
	return 0
}

func assertSemanticToken(t *testing.T, tokens []decodedSemanticToken, line, start, length, typeID uint32) {
	t.Helper()
	for _, token := range tokens {
		if token.line == line && token.start == start && token.length == length && token.typeID == typeID {
			return
		}
	}
	t.Fatalf("semantic token not found: line=%d start=%d length=%d typeID=%d", line, start, length, typeID)
}

func assertSemanticTokenWithModifier(t *testing.T, tokens []decodedSemanticToken, line, start, length, typeID, modifierBit uint32) {
	t.Helper()
	for _, token := range tokens {
		if token.line == line && token.start == start && token.length == length && token.typeID == typeID && token.mod&modifierBit != 0 {
			return
		}
	}
	t.Fatalf("semantic token with modifier not found: line=%d start=%d length=%d typeID=%d modifierBit=%d", line, start, length, typeID, modifierBit)
}

func assertDocumentHighlightKind(t *testing.T, highlights []lsp.DocumentHighlight, rng lsp.Range, wantKind lsp.DocumentHighlightKind) {
	t.Helper()
	for _, highlight := range highlights {
		if highlight.Range != rng {
			continue
		}
		if highlight.Kind == nil {
			t.Fatalf("document highlight kind is nil for range %+v", rng)
		}
		if *highlight.Kind != wantKind {
			t.Fatalf("document highlight kind for range %+v = %d, want %d", rng, *highlight.Kind, wantKind)
		}
		return
	}
	t.Fatalf("document highlight not found for range %+v", rng)
}

func assertWorkspaceSymbol(t *testing.T, symbols []lsp.SymbolInformation, wantName string, wantKind lsp.SymbolKind) {
	t.Helper()
	for _, symbol := range symbols {
		if symbol.Name == wantName && symbol.Kind == wantKind {
			return
		}
	}
	t.Fatalf("workspace symbol not found: name=%q kind=%d", wantName, wantKind)
}
