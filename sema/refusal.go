package sema

import (
	"fmt"
	"strings"
)

// RefusalCode names what was refused, for callers that have to branch on the
// kind rather than on the words.
type RefusalCode uint8

const (
	// RefusePrivateMember is `ns.name` where name is private to the module ns
	// names. The underscore is the whole export rule, so this is decidable from
	// the name alone -- the module itself need not be loaded.
	RefusePrivateMember RefusalCode = iota

	// RefuseNoSuchMember is `ns.name` where the module ns names is loaded and
	// declares no name.
	RefuseNoSuchMember

	// RefuseDuplicateTypeName is two modules declaring one struct or enum
	// name. It is the one refusal here that is about a whole program rather
	// than about one expression, because a type name is the one thing in
	// Mutant that is not module-scoped.
	RefuseDuplicateTypeName
)

// Refusal is a resolution the language does not permit.
//
// It is a value, not a raised error, because the two callers that matter have
// opposite postures: the compiler turns one into a compile error and stops, the
// editor turns one into a squiggle and carries on. What is refusable, and in
// what words, is decided here so that the two cannot drift into two phrasings
// of one rule. Who refuses is left to the caller.
//
// It implements error so the compiler can return it unchanged.
type Refusal struct {
	Code    RefusalCode
	Message string
}

func (r *Refusal) Error() string {
	if r == nil {
		return ""
	}
	return r.Message
}

// privateMemberRefusal is the sentence the compiler has always printed for a
// reach into another module's private name. It names both sides -- the spelling
// the reader wrote and the file that owns the name -- because the reader is
// looking at one of those and needs the other.
func privateMemberRefusal(alias, name, moduleName string) *Refusal {
	return &Refusal{
		Code: RefusePrivateMember,
		Message: fmt.Sprintf(
			"%s.%s is private to %s: a top-level name beginning with _ is visible only inside the module that declares it",
			alias, name, moduleName,
		),
	}
}

// noSuchMemberRefusal names the module rather than leaving the reader to guess
// which file was supposed to have the name.
func noSuchMemberRefusal(alias, name, moduleName string) *Refusal {
	return &Refusal{
		Code: RefuseNoSuchMember,
		Message: fmt.Sprintf(
			"%s declares no %s, so %s.%s has nothing to refer to",
			moduleName, name, alias, name,
		),
	}
}

// The sentences below are the editor's half of errors the module loader
// already raises. They are written here, beside the refusals, for the reason
// this package exists at all: a rule stated in two places is a rule that will
// come to be stated two ways. Where module/errors.go has a phrasing, these
// match it -- see importCycleMessage against module.CycleError.

// importCycleMessage names the whole chain rather than just the offending file.
// Reconstructing the path is the actual difficulty when a cycle appears, and
// the chain repeats the file at both ends so the loop is visible.
func importCycleMessage(chain []string) string {
	return "import cycle: " + strings.Join(chain, " -> ")
}

// duplicateNamespaceMessage matches module.DuplicateNamespaceError. The
// collision is usually invisible in the source -- an unaliased import takes its
// namespace from the file's base name, so two imports of different `util.mut`
// files look like two unrelated lines -- so both spellings are named.
func duplicateNamespaceMessage(importer, namespace, first, second string) string {
	return fmt.Sprintf(
		"%s: two imports bind the name %q: %q and %q; give one an alias, as in `import other %q`",
		importer, namespace, first, second, second,
	)
}

// unresolvedImportMessage is deliberately not module.NotFoundError's sentence.
//
// That one lists every directory searched and tells the reader to pass
// --module-path, which is right for a build that has finished looking. The
// editor has not finished looking: the file may simply not be scanned yet, and
// telling someone their import is missing while it is being indexed is worse
// than saying nothing precise. Callers are expected to suppress this entirely
// until a scan completes.
func unresolvedImportMessage(spelling string) string {
	return fmt.Sprintf("no indexed file matches the import %q", spelling)
}

// duplicateTypeNameRefusal is the sentence compiler.claimTypeName raises,
// moved here so there is one of it.
//
// Struct and enum names are claimed program-wide: ByteCode.StructDefs is a flat
// map, so two modules declaring Point would compile to one definition and the
// second would quietly win. Naming both files is the whole value of the
// message, because the reader is looking at one of them.
func duplicateTypeNameRefusal(kind, name, first, second string) *Refusal {
	return &Refusal{
		Code: RefuseDuplicateTypeName,
		Message: fmt.Sprintf(
			"%s %s is declared in both %s and %s: struct and enum names are shared across the whole program, so one of them has to be renamed",
			kind, name, first, second,
		),
	}
}
