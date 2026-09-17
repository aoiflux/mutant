// Package sema decides what a name in a Mutant program refers to.
//
// It exists because that decision was being made four times, independently: by
// the compiler's symbol table, by the tree-walking evaluator's environment
// (which is also the macro expander, so it runs on every compile), by the
// language server's scope walk, and by the workspace index's cross-document
// name matching. Four implementations of one rule is four chances to disagree,
// and they did: rand.int, sort.by, five assert.* and gunzip.* folded in the
// evaluator, were recommended by the editor, and failed under the compiler,
// because each asked "is this name already taken?" of a different thing. See
// parity/namespace_fold_parity_test.go, which tells that story in full.
//
// The package has two layers, and conflating them is the mistake it is built
// to avoid:
//
//   - Layer 1, this file: a pure, total decision procedure over strings. It
//     takes a ScopeCtx -- a bundle of predicates the caller supplies from
//     whatever it already has -- and answers what a name means. It holds no
//     AST, so it works for macro-expanded nodes, for a REPL line, and for a
//     half-typed buffer alike.
//   - Layer 2: an indexed artifact over declarations and references, built once
//     per module closure. Consumed by tooling, never by codegen.
//
// Nothing here returns error. A resolution is a decision, and a decision may
// carry a *Refusal; whether that becomes a compile error or a squiggle is the
// caller's policy.
package sema

import (
	"strings"

	"mutant/builtin"
)

// Confidence says whether an answer can still change when more code is seen.
//
// It is how one implementation serves a caller that must refuse (the compiler,
// which always has a complete module closure) and one that must tolerate (the
// editor, which sees half-typed code and unindexed files). Tolerance is a
// property of the answer, not a second code path.
type Confidence uint8

const (
	// Certain means the answer cannot change when more code is seen.
	Certain Confidence = iota

	// Provisional means this is the best answer available from an incomplete
	// closure. An editor should render it as nothing rather than as a wrong
	// jump; the compiler should never see one.
	Provisional
)

// ScopeCtx is everything a name decision depends on.
//
// It is function-valued on purpose. The compiler builds one from its symbol
// table, the evaluator from its environment, the language server from a parsed
// file plus a Workspace. None of them has to hand over its internals, and none
// of them has to grow a second notion of scope. That is what lets one
// implementation serve all of them.
//
// Every field may be nil; a nil predicate means "nothing of this kind is
// bound", which is what a REPL, a scratch buffer and a single-file compile all
// want.
type ScopeCtx struct {
	// Module is the canonical key of the file being resolved in. The empty
	// string means "no modules" -- the REPL, the playground, a single file --
	// and is not an error.
	Module string

	// Enums reports whether name is an enum type declared in this program.
	// Enum names are checked before anything else because Colour.Red was a
	// namespace-shaped thing before modules existed.
	Enums func(name string) bool

	// Namespace reports which module an import bound alias to.
	Namespace func(alias string) (moduleKey string, bound bool)

	// Bound reports whether name is taken by something the author bound: a let,
	// a parameter, an import namespace, a struct or enum name.
	//
	// It must NOT report true for a bare builtin. That distinction is the whole
	// of commit a901ce4: the compiler asked its symbol table, DefineBuiltin
	// writes every builtin into the very store that lookup reads, so for the
	// four families whose own name is also a registered builtin -- rand, sort,
	// assert, gunzip -- the answer came back "taken", the fold was skipped, and
	// nine builtins became unreachable from one engine while the other two
	// offered them happily. A bare builtin is not a binding.
	Bound func(name string) bool

	// Exports reports whether the module filed under moduleKey declares name at
	// its top level. It is only ever asked about a module ModuleKnown vouches
	// for.
	Exports func(moduleKey, name string) (ExportFact, bool)

	// ModuleKnown reports whether moduleKey's declarations are actually loaded.
	// A nil ModuleKnown means every module is loaded, which is true by
	// construction on the compile path: module.Load succeeded or nothing got
	// this far. The editor supplies a real one, because a file it has not
	// indexed yet must produce silence rather than a false "declares no such
	// name".
	ModuleKnown func(moduleKey string) bool

	// ModuleName renders a module key for a human, for message text only.
	ModuleName func(moduleKey string) string
}

// moduleName mirrors the compiler's own fallback: a real path beats something
// evasive, and a program with no modules is "this program".
func (c *ScopeCtx) moduleName(key string) string {
	if c.ModuleName != nil {
		if display := c.ModuleName(key); display != "" {
			return display
		}
	}
	if key == "" {
		return "this program"
	}
	return key
}

func (c *ScopeCtx) bound(name string) bool {
	return c.Bound != nil && c.Bound(name)
}

func (c *ScopeCtx) moduleKnown(key string) bool {
	return c.ModuleKnown == nil || c.ModuleKnown(key)
}

// FieldKind is what a.b turned out to be.
type FieldKind uint8

const (
	// FieldEnumValue is Colour.Red.
	FieldEnumValue FieldKind = iota

	// FieldModuleMember is stats.mean -- a reach into another module's top
	// level through an import namespace.
	FieldModuleMember

	// FieldBuiltinFold is fs.read, which IS fs_read. A spelling, not a binding:
	// fs alone names nothing.
	FieldBuiltinFold

	// FieldValueAccess is an ordinary field read on a value, point.x. It is
	// also the answer for anything unrecognised, which is what keeps a
	// half-typed buffer from producing refusals.
	FieldValueAccess

	// FieldRefused is a spelling the language does not permit. Refusal is
	// non-nil exactly here.
	FieldRefused
)

// FieldResolution is what a.b means.
type FieldResolution struct {
	Kind FieldKind

	// Builtin is the folded flat name, set only for FieldBuiltinFold.
	Builtin string

	// ModuleKey and Member are set for FieldModuleMember, and for the refusals
	// that arise while resolving one.
	ModuleKey string
	Member    string

	// Refusal is non-nil if and only if Kind is FieldRefused.
	Refusal *Refusal

	Confidence Confidence
}

// Resolver is the decision procedure. It holds no state today; it is a type
// rather than a set of functions so that a future cache has somewhere to live
// without changing a single call site.
type Resolver struct{}

func NewResolver() *Resolver { return &Resolver{} }

// ResolveField decides what left.field refers to.
//
// The order of the arms is the language's precedence and is not adjustable:
// enum, then import namespace, then builtin fold, then field access on a value.
// It is the order compiler.compileFieldExpression has always used, and the
// reason for each step is preserved from there:
//
//   - An enum comes first because Colour.Red predates modules.
//   - An import namespace comes before an ordinary variable of the same name
//     because the import is a declaration in this very file.
//   - The builtin fold comes last, so a variable, parameter or struct called
//     fs still wins and no existing program changes meaning.
func (r *Resolver) ResolveField(ctx ScopeCtx, left, field string) FieldResolution {
	if left == "" || field == "" {
		return FieldResolution{Kind: FieldValueAccess, Confidence: Certain}
	}

	if ctx.Enums != nil && ctx.Enums(left) {
		return FieldResolution{Kind: FieldEnumValue, Member: field, Confidence: Certain}
	}

	if ctx.Namespace != nil {
		if key, isImport := ctx.Namespace(left); isImport {
			return r.resolveModuleMember(&ctx, left, key, field)
		}
	}

	if !ctx.bound(left) {
		if flat := left + "_" + field; builtin.GetBuiltinByName(flat) != nil {
			return FieldResolution{Kind: FieldBuiltinFold, Builtin: flat, Confidence: Certain}
		}
	}

	return FieldResolution{Kind: FieldValueAccess, Confidence: Certain}
}

// resolveModuleMember resolves name at the top level of the module bound to
// alias.
//
// The private check comes before the existence check, and deliberately: the
// underscore is a rule about the name itself, so it holds whether or not the
// module has been loaded. That is what lets the editor squiggle stats._total
// the moment it is typed, in a file whose imports it has not finished reading.
func (r *Resolver) resolveModuleMember(ctx *ScopeCtx, alias, key, name string) FieldResolution {
	if IsModulePrivate(name) {
		return FieldResolution{
			Kind:       FieldRefused,
			ModuleKey:  key,
			Member:     name,
			Refusal:    privateMemberRefusal(alias, name, ctx.moduleName(key)),
			Confidence: Certain,
		}
	}

	resolved := FieldResolution{Kind: FieldModuleMember, ModuleKey: key, Member: name, Confidence: Certain}

	if !ctx.moduleKnown(key) || ctx.Exports == nil {
		// The module is real -- an import bound this alias to it -- but its
		// declarations are not in hand. Saying "declares no such name" here
		// would be a refusal invented out of ignorance.
		resolved.Confidence = Provisional
		return resolved
	}

	if _, declared := ctx.Exports(key, name); !declared {
		return FieldResolution{
			Kind:       FieldRefused,
			ModuleKey:  key,
			Member:     name,
			Refusal:    noSuchMemberRefusal(alias, name, ctx.moduleName(key)),
			Confidence: Certain,
		}
	}

	return resolved
}

// IsModulePrivate reports whether a top-level name is visible only inside the
// module that declares it. A leading underscore is the entire rule: there is no
// export list to keep in step with the code, and the mark travels with every
// mention of the name rather than living in one place far away from it.
//
// It lives here rather than in the compiler because the editor has to apply the
// same rule and cannot import the compiler. compiler.IsModulePrivate forwards
// to this.
func IsModulePrivate(name string) bool {
	return strings.HasPrefix(name, "_")
}
