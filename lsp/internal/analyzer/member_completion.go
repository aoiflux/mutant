package analyzer

import (
	"strings"

	mast "mutant/ast"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// MemberCompletionsAt returns member completions when the cursor sits directly
// after a `receiver.` accessor: the variants of an enum type name, or the fields
// of a struct-typed variable. The boolean is false when the cursor is not in a
// member-access position, in which case the caller falls back to ordinary
// completion.
//
// Receiver detection is textual (the parser produces no node for the incomplete
// `x.` form); only type resolution uses the AST. Chained receivers (`a.b.c`) and
// struct-literal receivers (`Point{...}.`) are intentionally out of scope for
// this first version because field types are not tracked in a dynamically typed
// language.
func (s *Snapshot) MemberCompletionsAt(pos lsp.Position) ([]lsp.CompletionItem, bool) {
	if s == nil || s.Program == nil {
		return nil, false
	}
	offset, ok := offsetForPosition(s.Source, pos)
	if !ok {
		return nil, false
	}
	receiver, prefix, ok := memberAccessAt(s.Source, offset)
	if !ok {
		return nil, false
	}

	// 1. Enum type name receiver -> its variants.
	if variants, ok := s.enumVariantNames(receiver); ok {
		return memberCompletionItems(variants, lsp.CompletionItemKindEnumMember, prefix, pos), true
	}

	// 2. Struct-typed local receiver -> the struct's fields.
	for _, b := range s.VisibleBindingsAt(pos) {
		if b.ident == nil || b.ident.Value != receiver {
			continue
		}
		if typeName, ok := s.structTypeNameForBinding(b); ok {
			if fields, ok := s.structFieldNames(typeName); ok {
				return memberCompletionItems(fields, lsp.CompletionItemKindField, prefix, pos), true
			}
		}
		break
	}

	return nil, false
}

// offsetForPosition converts a zero-based (line, character) position to a byte
// offset in src. Characters are treated as bytes, matching the rest of the
// analyzer's ASCII-oriented position handling.
func offsetForPosition(src string, pos lsp.Position) (int, bool) {
	i := 0
	for line := 0; line < int(pos.Line); line++ {
		nl := strings.IndexByte(src[i:], '\n')
		if nl < 0 {
			return 0, false
		}
		i += nl + 1
	}
	target := i + int(pos.Character)
	if target > len(src) {
		target = len(src)
	}
	if target < 0 {
		return 0, false
	}
	return target, true
}

// memberAccessAt inspects src ending at offset and, if it is a `receiver.prefix`
// member access, returns the receiver identifier and the already-typed field
// prefix.
func memberAccessAt(src string, offset int) (receiver, prefix string, ok bool) {
	if offset > len(src) {
		offset = len(src)
	}
	// Trailing partial field name (may be empty).
	i := offset
	for i > 0 && isIdentByte(src[i-1]) {
		i--
	}
	prefix = src[i:offset]

	// The character immediately before the prefix must be the accessor dot.
	if i == 0 || src[i-1] != '.' {
		return "", "", false
	}
	dot := i - 1

	// Receiver identifier immediately before the dot.
	k := dot
	for k > 0 && isIdentByte(src[k-1]) {
		k--
	}
	receiver = src[k:dot]
	if receiver == "" || isDigitByte(receiver[0]) {
		return "", "", false
	}
	// Reject chained access (`a.b.`): we cannot resolve the type of `b`.
	if k > 0 && src[k-1] == '.' {
		return "", "", false
	}
	return receiver, prefix, true
}

func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

func (s *Snapshot) enumVariantNames(typeName string) ([]string, bool) {
	for _, stmt := range s.Program.Statements {
		enum, ok := stmt.(*mast.EnumStatement)
		if !ok || enum.Name == nil || enum.Name.Value != typeName {
			continue
		}
		names := make([]string, 0, len(enum.Variants))
		for _, v := range enum.Variants {
			if v != nil {
				names = append(names, v.Value)
			}
		}
		return names, true
	}
	return nil, false
}

func (s *Snapshot) structFieldNames(typeName string) ([]string, bool) {
	for _, stmt := range s.Program.Statements {
		st, ok := stmt.(*mast.StructStatement)
		if !ok || st.Name == nil || st.Name.Value != typeName {
			continue
		}
		names := make([]string, 0, len(st.Fields))
		for _, f := range st.Fields {
			if f != nil {
				names = append(names, f.Value)
			}
		}
		return names, true
	}
	return nil, false
}

// memberCompletionItems builds prefix-filtered items that replace the typed
// field prefix via a TextEdit so the client does not double-insert it.
func memberCompletionItems(names []string, kind lsp.CompletionItemKind, prefix string, pos lsp.Position) []lsp.CompletionItem {
	lowerPrefix := strings.ToLower(prefix)
	start := pos
	if lsp.UInteger(len(prefix)) <= pos.Character {
		start.Character = pos.Character - lsp.UInteger(len(prefix))
	}
	editRange := lsp.Range{Start: start, End: pos}

	items := make([]lsp.CompletionItem, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		if prefix != "" && !strings.HasPrefix(strings.ToLower(name), lowerPrefix) {
			continue
		}
		k := kind
		items = append(items, lsp.CompletionItem{
			Label:    name,
			Kind:     &k,
			TextEdit: &lsp.TextEdit{Range: editRange, NewText: name},
		})
	}
	return items
}
