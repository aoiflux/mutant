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

// CommentKind distinguishes the comment syntaxes the lexer recognises.
// Mutant currently only has line comments, but the kind is recorded
// explicitly so the formatter does not have to re-inspect the text and so
// block comments can be added later without changing consumers.
type CommentKind string

const (
	// LineComment is a `// ...` comment running to the end of the line.
	LineComment CommentKind = "line"
)

// Comment is a piece of comment trivia captured by the lexer.
//
// Comments are not emitted as tokens (the parser never sees them); they are
// collected on the side and published on ast.Program so that the formatter
// can re-attach them to the nodes they document. Text holds the comment
// exactly as authored, including the leading `//` and excluding the
// terminating newline.
//
// Start/End follow the same convention as Token: Start is the position of
// the first byte, End is one past the last byte.
type Comment struct {
	Kind  CommentKind
	Text  string
	Start Position
	End   Position
}

// IsTrailing reports whether the comment begins on the same line as, and
// after, the token ending at prev. A trailing comment belongs to the
// statement it follows; a non-trailing one leads the statement below it.
func (c Comment) IsTrailing(prev Position) bool {
	if !prev.IsValid() || !c.Start.IsValid() {
		return false
	}
	return prev.Line == c.Start.Line && c.Start.Offset >= prev.Offset
}

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
	LTE        = "<="
	GTE        = ">="
	BANG       = "!"
	EQUALITY   = "=="
	INEQUALITY = "!="
	AND        = "&&"
	OR         = "||"
	COLON      = ":"

	// Compound assignment and increment/decrement. These are pure syntactic
	// sugar: the parser desugars each to a plain assignment over the matching
	// binary operator (e.g. `x += 1` -> `x = x + 1`, `x++` -> `x = x + 1`).
	PLUS_ASSIGN     = "+="
	MINUS_ASSIGN    = "-="
	ASTERISK_ASSIGN = "*="
	SLASH_ASSIGN    = "/="
	MODULO_ASSIGN   = "%="
	INCREMENT       = "++"
	DECREMENT       = "--"

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
