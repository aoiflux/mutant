package sema

import "fmt"

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
