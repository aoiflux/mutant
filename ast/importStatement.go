package ast

import (
	"bytes"
	"path"
	"strconv"
	"strings"

	"mutant/token"
)

// ImportStatement brings another source file into scope under a namespace.
//
//	import "forensics/ntfs.mut";          // namespace derived from the file name
//	import ntfs "forensics/ntfs.mut";     // namespace named explicitly
//
// Path is a string literal and never an arbitrary expression: an import is
// resolved before anything runs, so there is no moment at which a computed path
// could be evaluated.
//
// Alias is nil for the first form, in which case the namespace is Namespace()'s
// derivation from the file name.
type ImportStatement struct {
	Token token.Token // the IMPORT token
	Alias *Identifier
	Path  *StringLiteral
}

func (is *ImportStatement) statementNode()          {}
func (is *ImportStatement) RequiresSemicolon() bool { return true }
func (is *ImportStatement) TokenLiteral() string    { return is.Token.Literal }

func (is *ImportStatement) String() string {
	var out bytes.Buffer
	out.WriteString(is.TokenLiteral())
	if is.Alias != nil {
		out.WriteString(" ")
		out.WriteString(is.Alias.String())
	}
	out.WriteString(" ")
	if is.Path != nil {
		out.WriteString(strconv.Quote(is.Path.Value))
	}
	out.WriteString(";")
	return out.String()
}

// Namespace is the name this import binds in the importing file: the alias when
// one was written, and otherwise the file name with its directories and `.mut`
// suffix removed, so `import "forensics/ntfs.mut";` binds `ntfs`.
//
// It returns "" when no usable name can be derived, which the compiler reports
// as an import that must be given an explicit alias rather than guessing. A
// derived name is not validated as an identifier here -- that check belongs with
// the error message, which needs to name the file.
func (is *ImportStatement) Namespace() string {
	if is.Alias != nil {
		return is.Alias.Value
	}
	if is.Path == nil {
		return ""
	}

	// Both separators, deliberately: an import path is written with forward
	// slashes by convention but a Windows author may well type a backslash, and
	// the namespace should not depend on which.
	raw := strings.ReplaceAll(is.Path.Value, "\\", "/")
	base := path.Base(raw)
	return strings.TrimSuffix(base, ".mut")
}
