package token

import "sort"

// Position identifies a location in source code.
//
// Line and Column are 1-based (LSP-friendly) and count runes, not bytes.
// Offset is a 0-based byte offset into the source input.
//
// A zero-value Position (Line == 0) means "unknown position" and is used
// by hand-constructed tokens (e.g. in tests) that pre-date position tracking.
// Consumers that require positions should treat Line == 0 as absent.
type Position struct {
	Line   int
	Column int
	Offset int
}

// IsValid reports whether p carries meaningful position information.
func (p Position) IsValid() bool { return p.Line > 0 }

type TokenType string

// Token is a lexed piece of source text.
//
// Start is the position of the first byte of the token.
// End is the position immediately after the last byte of the token
// (LSP-exclusive semantics), so a single-character token at line 1
// column 5 has Start={1,5,4} and End={1,6,5}.
type Token struct {
	Type    TokenType
	Literal string
	Start   Position
	End     Position
}

const (
	ILLEGAL = "ILLEGAL"
	EOF     = "EOF"

	// Identifiers + Literals
	// ex: add, foobar, x, y, ....
	IDENT  = "IDENT"
	INT    = "INT"
	FLOAT  = "FLOAT"
	STRING = "STRING"

	// Operators
	ASSIGN     = "="
	PLUS       = "+"
	MINUS      = "-"
	ASTERISK   = "*"
	FSLASH     = "/"
	MODULO     = "%"
	BSLASH     = "\\"
	DOT        = "."
	LT         = "<"
	GT         = ">"
	BANG       = "!"
	EQUALITY   = "=="
	INEQUALITY = "!="
	COLON      = ":"

	// Delimiters
	COMMA     = ","
	SEMICOLON = ";"
	LPAREN    = "("
	RPAREN    = ")"
	LBRACE    = "{"
	RBRACE    = "}"
	LSQUARE   = "["
	RSQUARE   = "]"

	// Keywords
	FUNCTION = "FUNCTION"
	LET      = "LET"
	TRUE     = "TRUE"
	FALSE    = "FALSE"
	IF       = "IF"
	ELSE     = "ELSE"
	RETURN   = "RETURN"
	MACRO    = "MACRO"
	FOR      = "FOR"
	BREAK    = "BREAK"
	CONTINUE = "CONTINUE"
	STRUCT   = "STRUCT"
	ENUM     = "ENUM"
)

var keywords = map[string]TokenType{
	"fn":       FUNCTION,
	"let":      LET,
	"true":     TRUE,
	"false":    FALSE,
	"if":       IF,
	"else":     ELSE,
	"return":   RETURN,
	"macro":    MACRO,
	"for":      FOR,
	"break":    BREAK,
	"continue": CONTINUE,
	"struct":   STRUCT,
	"enum":     ENUM,
}

// LookupIdent function takes in an identifier(string)
// and then returns whether that identifier is a keyword
// or a user defined identifier
func LookupIdent(ident string) TokenType {
	if tok, ok := keywords[ident]; ok {
		return tok
	}
	return IDENT
}

// KeywordLiterals returns all language keyword spellings in sorted order.
func KeywordLiterals() []string {
	items := make([]string, 0, len(keywords))
	for keyword := range keywords {
		items = append(items, keyword)
	}
	sort.Strings(items)
	return items
}
