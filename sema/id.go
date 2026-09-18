package sema

import (
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// CanonicalKey returns the identity of a file: the value two spellings of the
// same file must share, so a diamond import compiles it once and so the editor
// recognises a disk-indexed file and a later-opened editor document as one
// thing.
//
// Case is folded on Windows and only on Windows. Folding everywhere would merge
// `Util.mut` and `util.mut` on a case-sensitive filesystem, where they are
// genuinely two files; folding nowhere would compile the same Windows file
// twice when two imports disagree about capitalisation, giving duplicate
// definitions for code that is correct on the platform it was written for.
//
// The argument must already be absolute. Making it absolute is the caller's
// business because the callers disagree about what to do when that fails: the
// loader has a path it resolved itself and can trust, while the language server
// is handed URIs by an editor and must degrade rather than refuse.
//
// It lives here, rather than in module where it was written, because module
// imports compiler and compiler imports this package. That is not merely a
// build constraint: a module key is what ScopeCtx.Module holds and what every
// fact in this package is filed under, so the rule that decides when two paths
// are one module belongs with the rules that decide what names mean.
// module.canonicalKey and server.canonicalPath both forward here.
func CanonicalKey(absolutePath string) string {
	key := filepath.Clean(absolutePath)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}

// ModuleSeparator joins a module key to a top-level name. NUL is used because
// it is the one byte that can appear in neither an identifier nor a path, so a
// qualified key can never collide with an unqualified one.
//
// It is exported because DeclID.String must produce exactly the key the
// compiler's symbol table already uses; see the identity note on DeclID.
const ModuleSeparator = "\x00"

// ScopePath names the scope a declaration lives in, "" at a module's top level.
//
// Segments are joined with "/" and rooted at a reserved word where the kind of
// declaration would otherwise be ambiguous, so that two different kinds of
// binding can never be handed the same identity:
//
//	top-level let or function    ScopeTopLevel        the name
//	param, local let, loop bind  "collect"            the name
//	import namespace             ScopeImport          the alias
//	struct or enum name          ScopeType            the type name
//	struct field, enum variant   ScopeType + "/Point" the field or variant
//
// `import util` and `let util` are genuinely different bindings under Mutant's
// rules -- the compiler tries the namespace first -- so they must not collapse
// to one ID.
//
// A segment is its owner's name where there is one and an ordinal otherwise:
// the scope of `let collect = fn(a) { ... }` is `collect`, and the scope of an
// unnamed `fn` passed as an argument is `fn#0`, numbered within its parent.
// Only a function or macro literal opens a scope, so there is no segment for a
// block. Positions are deliberately absent: a position-based path changes on
// every keystroke above it, which would make rename wrong mid-edit.
type ScopePath string

// Reserved scope roots.
//
// Each carries a leading NUL, for the same reason ModuleSeparator is NUL: it is
// the one byte that can appear in no identifier, so a root can never be the
// name of a scope the author opened. Spelling them as the bare words would have
// been enough for `import`, which is a keyword, and wrong for `type`, which is
// not -- `let type = fn() { let Point = 1; };` opens a scope called `type`, and
// its local `Point` would then have had the very same identity as the field of
// a `struct Point`. Renaming one would have renamed the other.
const (
	ScopeTopLevel ScopePath = ""
	ScopeImport   ScopePath = ScopePath(ModuleSeparator + "import")
	ScopeType     ScopePath = ScopePath(ModuleSeparator + "type")
)

// Child returns the scope nested inside p under segment.
func (p ScopePath) Child(segment string) ScopePath {
	if p == "" {
		return ScopePath(segment)
	}
	return p + "/" + ScopePath(segment)
}

// DeclID identifies one declaration.
//
// Identity note, and it is load-bearing: when Scope is ScopeTopLevel and Seq is
// 0, String returns exactly module + NUL + name -- byte-identical to the key
// compiler.qualify builds and the symbol table stores under. That is what lets
// a parity test compare the two directly instead of through a translation
// layer, and a translation layer is where two notions of identity would drift
// apart.
//
// Stability contract: a DeclID is stable across any edit that does not add,
// remove or reorder a declaration or a nested scope earlier in the same
// enclosing scope. It is valid only within the Graph that produced it. It must
// not be persisted, cached across analyses, or used as a key in any store that
// outlives one query -- the graph export mints its own identity for exactly
// this reason.
type DeclID struct {
	// Module is the CanonicalKey of the declaring file, "" for a scratch
	// buffer or the REPL.
	Module string

	// Scope is "" at the module top level.
	Scope ScopePath

	// Name is the declared identifier.
	Name string

	// Seq distinguishes repeat declarations of Name in one Scope, 0 for the
	// first. Mutant permits `let x = 1; let x = 2;` in a block, and go-to
	// definition on the second use must not land on the first declaration.
	Seq uint16
}

// IsZero reports whether d identifies nothing. A zero DeclID is what an
// unresolved reference carries.
func (d DeclID) IsZero() bool {
	return d.Module == "" && d.Scope == "" && d.Name == "" && d.Seq == 0
}

// String renders the identity. See the identity note on DeclID: the top-level,
// first-declaration case is the symbol table's own key, unchanged.
func (d DeclID) String() string {
	qualified := d.Name
	if d.Module != "" {
		qualified = d.Module + ModuleSeparator + d.Name
	}

	switch {
	case d.Scope == ScopeTopLevel && d.Seq == 0:
		return qualified
	case d.Seq == 0:
		return string(d.Scope) + ModuleSeparator + qualified
	case d.Scope == ScopeTopLevel:
		return qualified + "#" + strconv.FormatUint(uint64(d.Seq), 10)
	default:
		return string(d.Scope) + ModuleSeparator + qualified + "#" + strconv.FormatUint(uint64(d.Seq), 10)
	}
}

// TopLevelID is the identity of name at the top level of the module filed under
// key. It is the only DeclID constructor the cross-module paths need, because
// the top level is the only part of a module another module can reach.
func TopLevelID(moduleKey, name string) DeclID {
	return DeclID{Module: moduleKey, Name: name}
}
