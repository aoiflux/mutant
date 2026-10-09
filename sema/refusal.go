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

	// RefuseDuplicateDeclaration is a declaration that declares nothing its
	// own scope did not already hold: a second `let` of one name, or a
	// parameter list that names one parameter twice.
	//
	// Appended rather than inserted. The codes are an iota and a caller may
	// have one stored, so the order is append-only for the same reason the
	// builtin ordinals are.
	RefuseDuplicateDeclaration

	// RefuseLoopControlOutsideLoop is a `break` or a `continue` with no loop in
	// its own function to act on.
	//
	// "In its own function" is the part that was not being said. A function
	// body is a loop boundary in both engines now, so a break inside a closure
	// has no loop even when the call sits inside one.
	RefuseLoopControlOutsideLoop

	// RefuseContinueInLoopStep is a `continue` reached while evaluating a for
	// loop's post section -- the step that advances it.
	//
	// Appended, as every code here is.
	RefuseContinueInLoopStep
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

// DuplicateDeclarationRefusal is the sentence for a `let` that declares nothing
// new in the scope it is written in.
//
// The rule it reports is Go's rule for a short variable declaration, measured
// against the Go compiler rather than taken from the spec: a declaration may
// reuse names the same block already declared as long as at least one non-blank
// name is new, and is refused when none is. So `let a, err = first(); let b, err
// = second();` is two declarations of err and is allowed, because b is new --
// which is the whole (value, err) idiom and 633 occurrences of it in the shipped
// examples -- while `let x = 1; let x = 2;` is refused, because nothing is.
//
// One deviation from Go, and the compiler's refuseIfNothingIsNew has the whole
// reason beside the code: a blank on the left counts as new, because Mutant has
// no `_, err = f()` to offer as the remedy Go offers.
//
// The message names the already-declared names rather than saying "a name",
// because with several on the left the reader needs to know which one is the
// objection. The remedy is spelled out for the single-name case, which is the
// one somebody reaches by mistake rather than by habit: assignment is what they
// meant, and it is a different keyword, not a different spelling.
func DuplicateDeclarationRefusal(already []string) *Refusal {
	if len(already) == 1 {
		name := already[0]
		return &Refusal{
			Code: RefuseDuplicateDeclaration,
			Message: fmt.Sprintf(
				"%s is already declared in this scope: a let declares a new variable, so to change this one write %s = ... instead, or move the declaration into a block of its own",
				name, name,
			),
		}
	}
	return &Refusal{
		Code: RefuseDuplicateDeclaration,
		Message: fmt.Sprintf(
			"this let declares nothing new: %s are all already declared in this scope, and a let needs at least one new name",
			strings.Join(already, ", "),
		),
	}
}

// LoopControlRefusal is the sentence for a `break` or a `continue` that has no
// loop to act on. keyword is the one written, so the reader is told about the
// word they typed.
//
// It lives here because two engines raise it and they must not phrase it two
// ways. That is not a tidiness argument: M26-EVL-023 is what the absence of a
// shared rule cost. The compiler refused the shape and the tree-walking engine
// ran it, letting the signal escape the call and drive the caller's loop -- and
// since `mutant gen` expands macros unconditionally, a macro whose `unquote`
// argument ran that shape spliced the wrong answer into the program with no
// diagnostic, and in one shape crashed the built program at its first
// instruction. One sentence in one place is how the two are kept from drifting
// again.
//
// The wording is the compiler's existing sentence, unchanged. It could be more
// precise about a `while` -- it says "for loop" -- but changing it would reach
// into compiler/loop_boundary_test.go, which belongs to the M26-CMP-002 kit,
// and composing the two matters more than the adjective. Rewording is separate
// work, and now it is work in one place.
func LoopControlRefusal(keyword string) *Refusal {
	return &Refusal{
		Code:    RefuseLoopControlOutsideLoop,
		Message: keyword + " used outside of for loop",
	}
}

// ContinueInLoopStepRefusal is the sentence for a `continue` reached while a
// for loop's post section is being evaluated.
//
// It is refused rather than given a meaning because it has no terminating one.
// The post section is the step that advances the loop, and a `continue` in it
// can only be read two ways: re-run the section from the start, which is what
// the compiler's jump target says and which re-reaches the same `continue`; or
// abandon it and go to the condition, which skips the advance. Both loop for
// ever on a program the author plainly meant to terminate, and the second is
// what the tree-walker did while this was being written -- measured as a hang,
// from a program the compiler accepted and answered a boolean for.
//
// A `break` in a post section is not refused. It has exactly one meaning, the
// loop ends, and both engines agree on it.
//
// Lives here, like LoopControlRefusal, so the two engines cannot phrase it two
// ways. The tree-walker raises it today; the compiler accepts the shape and
// leaves a half-built operand on the stack, which is M26-CMP-003's work.
func ContinueInLoopStepRefusal() *Refusal {
	return &Refusal{
		Code: RefuseContinueInLoopStep,
		Message: "continue in a for loop's post section would skip the step that advances the loop, " +
			"so the loop could never end; write it in the body instead",
	}
}

// DuplicateParameterRefusal is a parameter list naming one parameter twice.
//
// Separate from DuplicateDeclarationRefusal because the remedy is not the same
// sentence: there is no assignment that would have been meant, and the second
// parameter is unreachable rather than merely redundant -- every mention of the
// name inside the body resolves to one of the two, and which one is not
// something the reader can see. Go refuses it as `a redeclared in this block`.
func DuplicateParameterRefusal(name string) *Refusal {
	return &Refusal{
		Code: RefuseDuplicateDeclaration,
		Message: fmt.Sprintf(
			"parameter %s is declared twice: the second one could never be read, because every mention of %s in the body means the first",
			name, name,
		),
	}
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
