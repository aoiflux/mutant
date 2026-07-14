package analyzer

import (
	mast "mutant/ast"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func (s *Snapshot) TypeDefinitionLocation(uri lsp.DocumentUri, pos lsp.Position) (*lsp.Location, bool) {
	if s == nil || s.Program == nil {
		return nil, false
	}

	resolved, ok := s.resolveDefinition(pos)
	if !ok || resolved.ident == nil {
		return nil, false
	}

	if resolved.kind == lsp.CompletionItemKindStruct || resolved.kind == lsp.CompletionItemKindEnum {
		return &lsp.Location{URI: uri, Range: localprotocol.ToLSPRange(resolved.rng)}, true
	}

	if typeName, ok := s.structTypeNameForBinding(resolved); ok {
		if loc, ok := s.structDefinitionLocation(uri, typeName); ok {
			return loc, true
		}
	}

	if resolved.kind == lsp.CompletionItemKindField {
		if loc, ok := s.structDefinitionLocationForField(uri, resolved.ident); ok {
			return loc, true
		}
	}

	if resolved.kind == lsp.CompletionItemKindEnumMember {
		if loc, ok := s.enumDefinitionLocationForVariant(uri, resolved.ident); ok {
			return loc, true
		}
	}

	return nil, false
}

func (s *Snapshot) structDefinitionLocation(uri lsp.DocumentUri, typeName string) (*lsp.Location, bool) {
	if s == nil || s.Program == nil || typeName == "" {
		return nil, false
	}
	for _, stmt := range s.Program.Statements {
		structStmt, ok := stmt.(*mast.StructStatement)
		if !ok || structStmt == nil || structStmt.Name == nil || structStmt.Name.Value != typeName {
			continue
		}
		rng, ok := s.identifierRange(structStmt.Name)
		if !ok {
			return nil, false
		}
		return &lsp.Location{URI: uri, Range: localprotocol.ToLSPRange(rng)}, true
	}
	return nil, false
}

func (s *Snapshot) structDefinitionLocationForField(uri lsp.DocumentUri, fieldIdent *mast.Identifier) (*lsp.Location, bool) {
	if s == nil || s.Program == nil || fieldIdent == nil {
		return nil, false
	}
	for _, stmt := range s.Program.Statements {
		structStmt, ok := stmt.(*mast.StructStatement)
		if !ok || structStmt == nil || structStmt.Name == nil {
			continue
		}
		for _, field := range structStmt.Fields {
			if field != fieldIdent {
				continue
			}
			rng, ok := s.identifierRange(structStmt.Name)
			if !ok {
				return nil, false
			}
			return &lsp.Location{URI: uri, Range: localprotocol.ToLSPRange(rng)}, true
		}
	}
	return nil, false
}

func (s *Snapshot) enumDefinitionLocationForVariant(uri lsp.DocumentUri, variantIdent *mast.Identifier) (*lsp.Location, bool) {
	if s == nil || s.Program == nil || variantIdent == nil {
		return nil, false
	}
	for _, stmt := range s.Program.Statements {
		enumStmt, ok := stmt.(*mast.EnumStatement)
		if !ok || enumStmt == nil || enumStmt.Name == nil {
			continue
		}
		for _, variant := range enumStmt.Variants {
			if variant != variantIdent {
				continue
			}
			rng, ok := s.identifierRange(enumStmt.Name)
			if !ok {
				return nil, false
			}
			return &lsp.Location{URI: uri, Range: localprotocol.ToLSPRange(rng)}, true
		}
	}
	return nil, false
}
