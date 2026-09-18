package sema

import (
	"path/filepath"
	"sort"
	"sync"

	"mutant/ast"
)

// DiagCode names a thing the graph noticed. It is not a severity: whether a
// code becomes an error, a warning or nothing at all is the caller's policy,
// exactly as with Refusal.
type DiagCode uint8

const (
	// DiagUnresolvedImport is an import whose target is not indexed. In an
	// editor it means "not read yet" at least as often as it means "missing",
	// so a caller that has not finished scanning the workspace should hold it
	// back rather than show it.
	DiagUnresolvedImport DiagCode = iota

	// DiagImportCycle is a module reachable from itself. module.Load refuses
	// this; the editor reports it and carries on, because a cycle is something
	// an author creates for a few seconds at a time while moving code.
	DiagImportCycle

	// DiagDuplicateNamespace is two imports in one file binding one alias. The
	// second cannot be referred to at all.
	DiagDuplicateNamespace
)

// Diagnostic is something worth saying about a file, with the range in that
// file to say it at.
//
// Module is the file the range belongs to, and is not always the file that was
// asked about: a cycle is reported at the import statement that closes it.
type Diagnostic struct {
	Module  string
	Range   ast.Range
	Code    DiagCode
	Message string
}

// Workspace holds what is known about every indexed file, and answers the
// cross-file questions a single parsed document cannot.
//
// It is owned by the language server and shared by every open document, which
// is the opposite of where per-document analysis state lives. That placement is
// deliberate: facts about a file are read by every file that imports it, so
// hanging them off a per-URI snapshot would rebuild one module's exports once
// per importer, per keystroke.
//
// The zero value is not usable; call NewWorkspace.
type Workspace struct {
	mu sync.RWMutex

	// facts is keyed by CanonicalKey, byURI maps the editor's name for a file
	// to that key. Two maps rather than one because an import names a path and
	// a client names a URI, and neither can be derived from the other without
	// the rule CanonicalKey owns.
	facts map[string]*ModuleFacts
	byURI map[string]string

	// searchPaths mirrors module.Resolver's --module-path list, in order.
	searchPaths []string

	// gen is bumped only when some file's Hash changes, never merely because a
	// file was re-parsed. Consumers cache against it; see ModuleFacts.Hash for
	// what is deliberately excluded.
	gen uint64

	res *Resolver
}

// NewWorkspace returns an empty workspace that resolves imports relative to the
// importing file first and then through searchPaths in order -- the same
// candidate order module.Resolver uses, because an editor that resolved imports
// differently from the build would confidently point at the wrong file.
func NewWorkspace(searchPaths []string) *Workspace {
	w := &Workspace{
		facts: make(map[string]*ModuleFacts, 32),
		byURI: make(map[string]string, 32),
		res:   NewResolver(),
	}
	w.SetSearchPaths(searchPaths)
	return w
}

// SetSearchPaths replaces the --module-path list. It bumps the generation,
// because every unresolved import in the workspace may now resolve.
func (w *Workspace) SetSearchPaths(paths []string) {
	cleaned := make([]string, 0, len(paths))
	for _, dir := range paths {
		if dir == "" {
			continue
		}
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
		cleaned = append(cleaned, filepath.Clean(dir))
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.searchPaths = cleaned
	w.gen++
}

// PutFile records what path declares, and reports whether that changed anything
// another file could see.
//
// It must never touch the filesystem and never walk a function body: it is on
// the keystroke path. A false return means every cache keyed on Generation is
// still good, which is the common case -- almost all typing happens inside a
// function, and none of it changes a fact.
//
// path is the file's location on disk and uri is what the client calls it. Both
// are needed: the first is what an import resolves to, the second is what a
// resolution has to be turned back into.
func (w *Workspace) PutFile(uri, path string, program *ast.Program) (changed bool) {
	key := CanonicalKey(path)
	facts := FactsOf(key, uri, path, program)

	w.mu.Lock()
	defer w.mu.Unlock()

	previous, known := w.facts[key]
	w.facts[key] = facts
	w.byURI[uri] = key

	if known && previous.Hash == facts.Hash {
		// Ranges may well have moved, and the new facts carry them. Nothing
		// outside this file depends on where a name sits, so no generation
		// bump: see ModuleFacts.Hash.
		return false
	}
	w.gen++
	return true
}

// RemoveFile forgets a file, as when it is deleted or closed without ever
// having been on disk.
func (w *Workspace) RemoveFile(uri string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	key, known := w.byURI[uri]
	if !known {
		return
	}
	delete(w.byURI, uri)

	// The facts go only if this URI is the one that filed them. One file can be
	// known by two URIs -- the background scan indexes a path, then the editor
	// opens the same file under a differently-cased URI -- and both map to one
	// key. Forgetting the closed one must not take the live one's declarations
	// with it, which would empty every importer's completion list.
	if facts, filed := w.facts[key]; filed && facts.URI == uri {
		delete(w.facts, key)
	}
	w.gen++
}

// Generation is the counter a cache should key on. It changes only when some
// file's declarations changed.
func (w *Workspace) Generation() uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.gen
}

// KeyForURI returns the module key the client's URI names.
func (w *Workspace) KeyForURI(uri string) (string, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	key, known := w.byURI[uri]
	return key, known
}

// Facts returns what is known about one module. The result is read-only: it is
// shared with every caller and replaced wholesale by PutFile rather than
// mutated, which is what lets readers hold it without the lock.
func (w *Workspace) Facts(key string) (*ModuleFacts, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	facts, known := w.facts[key]
	return facts, known
}

// URIOf returns the client's name for a module key, so a resolution can be
// turned back into a location the editor can open.
func (w *Workspace) URIOf(key string) (string, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	facts, known := w.facts[key]
	if !known {
		return "", false
	}
	return facts.URI, facts.URI != ""
}

// resolveImport walks the same candidates module.Resolver walks, in the same
// order -- the importing file's own directory, then each search path -- and
// substitutes "is this file indexed?" for "does this file exist?".
//
// That substitution is the whole of the editor's honesty. It never stats, so it
// is safe on the keystroke path, and it can only ever resolve to a file the
// workspace has actually read. An import to a file not yet scanned comes back
// unresolved, which surfaces as Provisional and renders as nothing -- rather
// than as a jump into a file chosen by name.
//
// The caller must hold at least a read lock.
func (w *Workspace) resolveImport(fromKey, spelling string) (string, bool) {
	if spelling == "" {
		return "", false
	}
	local := filepath.FromSlash(spelling)

	indexed := func(candidate string) (string, bool) {
		key := CanonicalKey(candidate)
		if _, known := w.facts[key]; known {
			return key, true
		}
		return "", false
	}

	// An absolute import bypasses the search entirely: there is exactly one
	// file it could mean.
	if filepath.IsAbs(local) {
		return indexed(local)
	}

	if dir := filepath.Dir(fromKey); dir != "" && dir != "." {
		if key, ok := indexed(filepath.Join(dir, local)); ok {
			return key, true
		}
	}
	for _, dir := range w.searchPaths {
		if key, ok := indexed(filepath.Join(dir, local)); ok {
			return key, true
		}
	}
	return "", false
}

// Namespaces returns the aliases the module filed under key binds, each mapped
// to the key of the module it names.
//
// Only imports that resolved to an indexed file appear, because every caller of
// this wants a module key it can then look something up in. An alias whose
// target has not been read is a different situation, and bindingsLocked is
// where it is handled.
func (w *Workspace) Namespaces(key string) map[string]string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	bound := make(map[string]string, 4)
	for alias, target := range w.bindingsLocked(key) {
		if target != "" {
			bound[alias] = target
		}
	}
	return bound
}

// bindingsLocked returns every alias an import binds, including those whose
// target has not been indexed -- those map to "".
//
// The distinction is the point. An `import stats "lib/stats.mut";` binds the
// name `stats` whether or not the workspace has got round to reading that file.
// Dropping the alias until the file is read would make `stats.mean` an ordinary
// field read on a value called `stats`, which invites the undefined-identifier
// rule to squiggle `stats` and the completion to offer a value's members. What
// is unknown is the module's contents, not the fact that it is a module -- so
// the alias stays bound, ScopeCtx.ModuleKnown reports false, and the resolution
// comes back Provisional, which renders as nothing.
//
// The caller must hold at least a read lock.
func (w *Workspace) bindingsLocked(key string) map[string]string {
	facts, known := w.facts[key]
	if !known {
		return nil
	}
	bound := make(map[string]string, len(facts.Imports))
	for _, imported := range facts.Imports {
		if imported.Alias == "" {
			continue
		}
		if _, already := bound[imported.Alias]; already {
			// Two imports, one alias. The first wins, matching the compiler,
			// and Diagnostics reports the second.
			continue
		}
		target, _ := w.resolveImport(key, imported.Spelling)
		bound[imported.Alias] = target
	}
	return bound
}

// Closure returns every module reachable from key by imports, key included,
// in a deterministic order.
//
// It does not refuse a cycle. An author creates cycles constantly while moving
// code between files, and an editor that stopped answering until the cycle was
// resolved would be useless exactly when it is most needed. The cycle is
// recorded as a Diagnostic and the walk continues -- the same fact
// module.Load raises as a CycleError, in the posture this caller needs.
func (w *Workspace) Closure(key string) ([]string, []Diagnostic) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var (
		reached = make(map[string]bool, 8)
		diags   []Diagnostic
		// stack is the current DFS path, which is what distinguishes a cycle
		// from a diamond: a diamond revisits a module that is already finished,
		// a cycle revisits one still on the stack. It is kept as a slice rather
		// than a set because the message names the whole chain.
		stack  []string
		onPath = make(map[string]bool, 8)
	)

	var walk func(string)
	walk = func(current string) {
		if reached[current] {
			return
		}
		reached[current] = true
		onPath[current] = true
		stack = append(stack, current)
		defer func() {
			delete(onPath, current)
			stack = stack[:len(stack)-1]
		}()

		facts, known := w.facts[current]
		if !known {
			return
		}
		for _, imported := range facts.Imports {
			target, ok := w.resolveImport(current, imported.Spelling)
			if !ok {
				continue
			}
			if onPath[target] {
				diags = append(diags, Diagnostic{
					Module:  current,
					Range:   imported.Range,
					Code:    DiagImportCycle,
					Message: importCycleMessage(cycleChain(stack, target)),
				})
				continue
			}
			walk(target)
		}
	}
	walk(key)

	keys := make([]string, 0, len(reached))
	for reachedKey := range reached {
		keys = append(keys, reachedKey)
	}
	sort.Strings(keys)
	return keys, diags
}

// cycleChain renders the loop the way module.CycleError does: from the module
// the cycle re-enters, round to the import that closed it, with the repeated
// file appearing at both ends.
func cycleChain(stack []string, target string) []string {
	start := 0
	for i, entry := range stack {
		if entry == target {
			start = i
			break
		}
	}
	chain := make([]string, 0, len(stack)-start+1)
	chain = append(chain, stack[start:]...)
	return append(chain, target)
}

// Diagnostics reports what is wrong with one file's imports.
//
// It is separate from Closure because these are facts about the file being
// edited, reported at ranges inside it, while a closure walk reports at ranges
// in whichever file closed a cycle.
//
// An import that binds no name gets nothing said about it. The loader does not
// refuse one either -- it binds the empty namespace, and a second such import
// collides with the first like any other duplicate. Inventing a diagnostic for
// a program the language accepts is exactly the temptation having the facts
// creates, and this package does not take it.
func (w *Workspace) Diagnostics(key string) []Diagnostic {
	w.mu.RLock()
	defer w.mu.RUnlock()

	facts, known := w.facts[key]
	if !known {
		return nil
	}

	var (
		diags []Diagnostic
		// boundBy maps an alias to the spelling that first bound it, which is
		// what the duplicate message has to name alongside the second.
		boundBy = make(map[string]string, len(facts.Imports))
	)
	for _, imported := range facts.Imports {
		if first, taken := boundBy[imported.Alias]; taken {
			diags = append(diags, Diagnostic{
				Module: key,
				Range:  imported.Range,
				Code:   DiagDuplicateNamespace,
				Message: duplicateNamespaceMessage(
					w.displayName(key), imported.Alias, first, imported.Spelling,
				),
			})
		} else {
			boundBy[imported.Alias] = imported.Spelling
		}

		if _, ok := w.resolveImport(key, imported.Spelling); !ok {
			diags = append(diags, Diagnostic{
				Module:  key,
				Range:   imported.Range,
				Code:    DiagUnresolvedImport,
				Message: unresolvedImportMessage(imported.Spelling),
			})
		}
	}
	return diags
}

// displayName renders a module for a human: the path as it was spelled, never
// the canonical key. See ModuleFacts.Path.
//
// The caller must hold the lock.
func (w *Workspace) displayName(key string) string {
	if facts, known := w.facts[key]; known && facts.Path != "" {
		return facts.Path
	}
	if key == "" {
		return "this program"
	}
	return key
}

// LocalScope is what the caller knows about the file being resolved that the
// workspace cannot know: which names are bound at the position in question, and
// which enums are in scope.
//
// It is a parameter rather than something Workspace derives because binding is
// position-dependent inside a function body, and the workspace deliberately
// never walks one.
type LocalScope struct {
	Bound func(name string) bool
	Enums func(name string) bool
}

// ScopeCtxFor builds the context for resolving names inside the module filed
// under key.
//
// This is the seam the language server has been missing. Everything
// cross-module in the returned context -- which aliases are bound, what each
// target declares, whether it has been read at all -- comes from the workspace;
// everything file-local comes from the caller's own scope walk. One resolver
// then answers, with the same precedence the compiler uses.
func (w *Workspace) ScopeCtxFor(key string, local LocalScope) ScopeCtx {
	w.mu.RLock()
	namespaces := w.bindingsLocked(key)
	w.mu.RUnlock()

	return ScopeCtx{
		Module: key,
		Enums:  local.Enums,
		Bound:  local.Bound,
		Namespace: func(alias string) (string, bool) {
			target, bound := namespaces[alias]
			return target, bound
		},
		Exports: func(moduleKey, name string) (ExportFact, bool) {
			facts, known := w.Facts(moduleKey)
			if !known {
				return ExportFact{}, false
			}
			export, declared := facts.Exports[name]
			return export, declared
		},
		// A module is known when its facts are in hand. Namespaces already
		// drops aliases that did not resolve, so this reports false only in the
		// window where a file was forgotten between the two calls -- in which
		// case hedging is exactly right.
		ModuleKnown: func(moduleKey string) bool {
			_, known := w.Facts(moduleKey)
			return known
		},
		ModuleName: func(moduleKey string) string {
			w.mu.RLock()
			defer w.mu.RUnlock()
			return w.displayName(moduleKey)
		},
	}
}

// ResolveField answers what left.field means inside the module filed under key.
// It is ScopeCtxFor plus the resolver, which is what almost every caller wants.
func (w *Workspace) ResolveField(key string, local LocalScope, left, field string) FieldResolution {
	return w.res.ResolveField(w.ScopeCtxFor(key, local), left, field)
}

// MembersOf returns the declarations reachable through alias from the module
// filed under key: the completion list behind `ns.`.
//
// Private names are filtered, because offering one is offering a name the build
// will refuse. Types are absent, and that is not an oversight -- struct and enum
// names are program-global in Mutant and written bare, so `ns.Colour` is a
// spelling the compiler does not accept. See TypeFact.
//
// A nil result means "nothing to say": the alias is not an import, or its target
// has not been read. Both must render as no completions rather than as an empty
// list presented with confidence.
func (w *Workspace) MembersOf(key string, alias string) []ExportFact {
	w.mu.RLock()
	target, bound := w.bindingsLocked(key)[alias]
	w.mu.RUnlock()
	if !bound || target == "" {
		return nil
	}

	facts, known := w.Facts(target)
	if !known {
		return nil
	}

	members := make([]ExportFact, 0, len(facts.Exports))
	for _, export := range facts.Exports {
		if export.Private {
			continue
		}
		members = append(members, export)
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	return members
}

// MemberFact returns the declaration left.field refers to, when it certainly
// refers to one. It is DefinitionOf's answer with the fact attached, for a
// caller that wants to describe the declaration rather than jump to it.
func (w *Workspace) MemberFact(key string, local LocalScope, left, field string) (ExportFact, string, bool) {
	resolved := w.ResolveField(key, local, left, field)
	if resolved.Kind != FieldModuleMember || resolved.Confidence != Certain {
		return ExportFact{}, "", false
	}
	facts, known := w.Facts(resolved.ModuleKey)
	if !known {
		return ExportFact{}, "", false
	}
	export, declared := facts.Exports[resolved.Member]
	if !declared {
		return ExportFact{}, "", false
	}
	return export, facts.Path, true
}

// DefinitionOf locates the declaration left.field refers to, for go-to-definition
// and hover.
//
// It returns the declaring module's key, the URI the client can open it by, and
// the file-local range of the declared identifier.
//
// The Confidence check is a guard, not the operative test. Today a Provisional
// answer always carries an empty ModuleKey -- an alias whose target is unread
// resolves to "" -- so the exports lookup below would decline anyway. It is
// written explicitly because the rule is "never act on a guess", and a later
// source of Provisional would otherwise turn a hedge into a jump with nothing
// standing in the way.
func (w *Workspace) DefinitionOf(key string, local LocalScope, left, field string) (moduleKey, uri string, declRange ast.Range, found bool) {
	resolved := w.ResolveField(key, local, left, field)
	if resolved.Kind != FieldModuleMember || resolved.Confidence != Certain {
		return "", "", ast.Range{}, false
	}

	facts, known := w.Facts(resolved.ModuleKey)
	if !known {
		return "", "", ast.Range{}, false
	}
	export, declared := facts.Exports[resolved.Member]
	if !declared {
		return "", "", ast.Range{}, false
	}
	return resolved.ModuleKey, facts.URI, export.DeclRange, true
}
