package cli

// `mutant graph query` reads back a store that `mutant graph export` wrote.
//
// # Why there is no query language here either
//
// graphene v0.9.0 has no query language, and this does not invent one. What it
// offers is a fixed set of named questions -- summary, modules, where, callers,
// callees, outline, exported -- each of which is a shape the export's index was
// designed to answer. A question the schema cannot answer truthfully is not
// offered at all, and the ones that are carry, beside the answer, what the
// answer does not cover.
//
// That is the whole design rule, and it comes from measurement rather than
// taste. Every shortcut a general query surface would have to take is a silent
// wrong answer in this engine:
//
//   - A property filter on a key that was never indexed matches nothing and
//     returns no error. Worse, the planner costs it at zero and picks it as the
//     driver, so ANDing it onto a correct filter turns a right answer into an
//     empty one, and ORing it drops the disjunct with no trace in the plan.
//     Eight of a declaration's twelve fields are in the blob and not the index.
//     So no user-supplied string ever reaches a PropertyFilter.Key here: every
//     filter below names a key this package wrote, and the blob fields are read
//     by decoding records rather than by asking the index about them.
//
//   - BFS and DFS deduplicate by neighbour rather than by edge, so a walk over
//     a graph whose REFERENCES run parallel to its DECLARES loses most of the
//     edges. On one real export, 586 of 967. Nothing below enumerates edges
//     with a traversal.
//
//   - ShortestPath, ShortestWeightedPath and IsConnected ignore direction: they
//     will walk an IMPORTS edge backwards and report a path. No question here
//     is built on them.
//
//   - A Limit is a silent truncation with no marker, so none is passed. Answers
//     are whole, and a large one is large.
//
// # Reading a store without changing what it says
//
// graphene.Open CREATES a store for any path that does not hold one, so a query
// built on it would answer "0 modules, 0 declarations" for a mistyped --store
// while writing two files into whatever directory was actually named. The store
// is therefore identified before it is opened, by its own label table, and then
// opened by graphstore.OpenForReading, which never creates a store, never takes
// a writer's lock, and says when it had to read without any lock at all. Its
// header has the three ways in and why each is sound.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mutant/graphstore"
	"mutant/sema"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"
)

// QueryOptions is what `mutant graph query` was asked for.
type QueryOptions struct {
	// Store is the directory `mutant graph export --out` wrote.
	Store string

	// Question is one of the names QueryQuestions reports. There is no free
	// text: see the file header.
	Question string

	// Argument is the question's subject, empty for the questions that take
	// none.
	Argument string
}

// QueryQuestion is one question the store can be asked.
type QueryQuestion struct {
	// Name is the word on the command line.
	Name string

	// Argument names what the question takes, and is empty when it takes
	// nothing.
	Argument string

	// Blurb is the one-line description in the help.
	Blurb string

	// Cost says how the answer is found, because the difference is visible:
	// an index lookup is immediate and a scan reads every declaration record.
	// One question is both, and says so, rather than being filed under the
	// cheaper of its two costs.
	Cost string
}

// Scans reports whether answering this question can read every declaration
// record. It is derived from Cost rather than stored beside it, because two
// fields that have to agree are two fields that eventually will not -- and the
// one that drifted here put "Two of the questions" above a list of one in the
// shipped help.
func (q QueryQuestion) Scans() bool { return q.Cost != costIndex }

// The three costs. `where` is the only question that is both: it is an index
// lookup, and on a miss it reads every record to find out whether the name was
// spelled differently rather than absent.
const (
	costIndex     = "an index lookup"
	costScan      = "every declaration record"
	costIndexThen = "an index lookup, then every declaration record when the name misses"
)

// QueryQuestions is the fixed set, in the order the help lists them. The CLI
// builds its usage from this, so a question cannot be added without appearing
// there.
//
// callers and callees are costIndexThen for the reason where is: on a name the
// index does not hold, each reads every record to find the casings that do
// exist. They were listed as index lookups while doing it, so the help's list
// of the questions that scan was two short of the truth. type looks for other
// casings too, but among the structs and enums alone, which their kind labels
// find without reading anything else.
func QueryQuestions() []QueryQuestion {
	return []QueryQuestion{
		{"summary", "", "What this store holds: the counts, by label.", costIndex},
		{"modules", "", "Every module, what it declares, and what it imports.", costIndex},
		{"where", "<name>", "Every declaration of a name, and where it is.", costIndexThen},
		{"callers", "<name>", "Every recorded use of a name, and where it is used from.", costIndexThen},
		{"callees", "<name>", "Every name a declaration uses.", costIndexThen},
		{"outline", "<module>", "The declarations of one module, nested as they are written.", costIndex},
		{"exported", "", "Every declaration another module could name.", costScan},
		{"types", "", "Every struct and enum, and how often each is built, matched and used.", costIndex},
		{"type", "<name>", "One struct or enum: its members, and where it is built, matched and used.", costIndex},
		{"deps", "<module>", "Every module one module imports, directly or through another.", costIndex},
		{"rdeps", "<module>", "Every module that imports one module, directly or through another.", costIndex},
	}
}

// AnswerSection is one titled block of an answer. Rows are already rendered:
// the questions differ enough that a common row type would describe none of
// them, and the caller's job is to print, not to decide.
type AnswerSection struct {
	Title string
	Rows  []string

	// Empty is what to say instead when there are no rows. An empty section is
	// an answer -- "nothing uses this" -- and it needs to read as one rather
	// than as a blank.
	Empty string
}

// QueryAnswer is one question's answer.
type QueryAnswer struct {
	Question string
	Store    string

	// Headline is the one line that answers the question.
	Headline string

	Sections []AnswerSection

	// Notes are what this answer does not cover. They are part of the answer
	// and not decoration: several of the questions below are complete only for
	// one module, and an answer that did not say so would be read as complete
	// for the program.
	Notes []string

	// Warnings are how the store was read, when it was not read the usual way.
	Warnings []string
}

// QueryGraph answers one question about one store.
func QueryGraph(opts QueryOptions) (QueryAnswer, error) {
	answer := QueryAnswer{Question: opts.Question, Store: opts.Store}

	question, known := findQuestion(opts.Question)
	if !known {
		return answer, fmt.Errorf("graph query: %q is not a question this store can be asked; try one of %s",
			opts.Question, strings.Join(questionNames(), ", "))
	}
	if question.Argument == "" && opts.Argument != "" {
		return answer, fmt.Errorf("graph query %s: takes no argument, got %q",
			question.Name, opts.Argument)
	}
	if question.Argument != "" && opts.Argument == "" {
		return answer, fmt.Errorf("graph query %s: needs %s", question.Name, question.Argument)
	}
	if opts.Store == "" {
		return answer, fmt.Errorf("graph query: a store directory is required")
	}

	extras, roles, err := requireSymbolGraph(opts.Store)
	if err != nil {
		return answer, err
	}
	if extras > 0 {
		answer.Warnings = append(answer.Warnings, fmt.Sprintf(
			"this store names %d label(s) this build does not know, so it was written by a "+
				"later version of `mutant graph export`; the questions below only use the labels "+
				"both versions agree on", extras))
	}

	g, lockFree, err := graphstore.OpenForReading(opts.Store)
	if err != nil {
		return answer, fmt.Errorf("graph query: %w", err)
	}
	defer func() { _ = g.Close() }()
	if lockFree != "" {
		answer.Warnings = append(answer.Warnings, lockFree)
	}

	if err := requireWrittenIndex(g); err != nil {
		return answer, err
	}

	switch question.Name {
	case "summary":
		err = answerSummary(g, &answer)
	case "modules":
		err = answerModules(g, &answer)
	case "where":
		err = answerWhere(g, opts.Argument, &answer)
	case "callers":
		err = answerUses(g, opts.Argument, store.DirectionInbound, &answer)
	case "callees":
		err = answerUses(g, opts.Argument, store.DirectionOutbound, &answer)
	case "outline":
		err = answerOutline(g, opts.Argument, &answer)
	case "exported":
		err = answerExported(g, &answer)
	case "types":
		err = answerTypes(g, roles, &answer)
	case "type":
		err = answerType(g, opts.Argument, roles, &answer)
	case "deps":
		err = answerDeps(g, opts.Argument, true, &answer)
	case "rdeps":
		err = answerDeps(g, opts.Argument, false, &answer)
	}
	if err != nil {
		return answer, err
	}
	return answer, nil
}

func findQuestion(name string) (QueryQuestion, bool) {
	for _, q := range QueryQuestions() {
		if q.Name == name {
			return q, true
		}
	}
	return QueryQuestion{}, false
}

func questionNames() []string {
	out := make([]string, 0, len(QueryQuestions()))
	for _, q := range QueryQuestions() {
		out = append(out, q.Name)
	}
	return out
}

// requireSymbolGraph refuses a directory that is not one of this program's
// exports, before anything opens it.
//
// The check is the store's own label table, read and compared against the
// constants this file was compiled with. That is the only thing on disk that
// distinguishes a mutant symbol graph from any other graphene store, and it has
// to be done here rather than through the engine for two reasons.
//
// The first is that graphene's type-name registry is process-global. It is
// filled by whichever store opened first and is never scoped to a handle or
// released on Close, so a store carrying no label table -- or an incomplete one
// from an older export -- renders its numbers with names it never declared.
// Reading the file per store is the only per-store vocabulary there is.
//
// The second is that every open mode accepts an existing directory that holds
// no store at all, reports zero nodes, and OpenReadOnly leaves a zero-byte
// graphene.lock behind in it. Refusing before the open is what keeps a mistyped
// --store from both answering confidently and littering.
//
// It returns the number of labels the table declares that this build does not
// know, which is what a store from a later export looks like, and whether the
// store names the two labels 2.6.0 added -- CONSTRUCTS and MATCHES -- which is
// what tells an export from before them. Such a store is read, not refused:
// everything it holds means what it always did, and the questions that need
// the newer labels say the store predates them rather than answering zero.
func requireSymbolGraph(dir string) (int, bool, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, false, fmt.Errorf("graph query: %s does not exist", dir)
		}
		return 0, false, fmt.Errorf("graph query: %s: %w", dir, err)
	}
	if !info.IsDir() {
		return 0, false, fmt.Errorf("graph query: %s is a file; a graph store is a directory", dir)
	}

	nodes, edges, err := graphstore.ReadLabelTable(filepath.Join(dir, graphstore.LabelTableName))
	if err != nil {
		return 0, false, fmt.Errorf("graph query: %s is not a symbol graph: %w", dir, err)
	}

	// Both tables are walked in label order rather than in map order. A store
	// that disagrees about two labels disagrees about two labels whichever is
	// named first, but a refusal an examiner might quote should be the same
	// sentence every time it is produced, and ranging a Go map made it a coin
	// toss between them.
	wantNodes, wantEdges := baseLabelNames()
	for _, label := range sortedLabels(wantNodes) {
		name := wantNodes[store.NodeType(label)]
		got, named := nodes[label]
		if !named {
			return 0, false, fmt.Errorf("graph query: %s is not a symbol graph: its labels do not name %s", dir, name)
		}
		if got != name {
			return 0, false, fmt.Errorf("graph query: %s is not a symbol graph: it calls label %d %q, "+
				"where this program calls it %q", dir, label, got, name)
		}
	}
	for _, label := range sortedLabels(wantEdges) {
		name := wantEdges[store.EdgeType(label)]
		got, named := edges[label]
		if !named {
			return 0, false, fmt.Errorf("graph query: %s is not a symbol graph: its labels do not name %s", dir, name)
		}
		if got != name {
			return 0, false, fmt.Errorf("graph query: %s is not a symbol graph: it calls edge label %d %q, "+
				"where this program calls it %q", dir, label, got, name)
		}
	}

	// The 2.6.0 labels come as a pair or not at all: every export since has
	// written both, and none before wrote either. One without the other is a
	// table somebody edited, and reading it would answer about constructions
	// with half the vocabulary for them.
	roleLabels := roleLabelNames()
	named := 0
	for _, label := range sortedLabels(roleLabels) {
		name := roleLabels[store.EdgeType(label)]
		got, present := edges[label]
		if !present {
			continue
		}
		if got != name {
			return 0, false, fmt.Errorf("graph query: %s is not a symbol graph: it calls edge label %d %q, "+
				"where this program calls it %q", dir, label, got, name)
		}
		named++
	}
	switch named {
	case 0:
		return (len(nodes) - len(wantNodes)) + (len(edges) - len(wantEdges)), false, nil
	case len(roleLabels):
		return (len(nodes) - len(wantNodes)) + (len(edges) - len(wantEdges) - named), true, nil
	}
	return 0, false, fmt.Errorf("graph query: %s is not a symbol graph as any export writes one: its "+
		"labels name one of CONSTRUCTS and MATCHES and not the other, and every export names both or neither", dir)
}

// preRolesNote is what a question about types owes the reader of a store
// written before 2.6.0: the store is readable, and what it cannot say is
// exactly the part of the answer they asked for.
const preRolesNote = "this store was exported before 2.6.0, which recorded neither which uses of " +
	"a type build it or match it nor any use of a type declared in another module. Every use " +
	"shown is one it did record. Re-export the program to see constructions and matches"

// sortedLabels is the label numbers of either table, ascending. It is generic
// over the two label types because they are distinct named integer types and
// the alternative is this function twice.
func sortedLabels[T ~uint16](table map[T]string) []uint16 {
	out := make([]uint16, 0, len(table))
	for label := range table {
		out = append(out, uint16(label))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// requireWrittenIndex refuses a store this program cannot read the way it
// expects to, rather than letting the difference show up as an empty answer.
//
// Two things are checked. A store with no nodes passed the label check and is
// still not an export -- an export always writes at least the module it was
// given -- which is what a store whose image has been removed looks like, and
// what an empty directory carrying only a label table looks like.
//
// The other is the index. Every filter in this file names a key the export
// declared, and a key that is absent from the index matches nothing and returns
// no error. NodePropKeys is an upper bound rather than an exact set, so a key
// it names may still project nothing -- refusing on absence and never on
// presence is the direction that cannot produce a false refusal.
//
// Which keys are required depends on what the store holds, and getting that
// wrong produced the worst kind of refusal this file can make. A module node
// writes `key` and `name`; `id`, `kind` and `module` come from declaration
// nodes alone. Demanding all five unconditionally refused every store written
// for a program that declares nothing -- a hello-world, an empty file, a file
// of comments -- and refused it with a message blaming a different version of
// `mutant graph export` for a store this same build had written seconds
// earlier. So the three declaration keys are required only once a declaration
// exists to have written them.
func requireWrittenIndex(g *graphene.Graph) error {
	stats, err := g.Stats()
	if err != nil {
		return fmt.Errorf("graph query: %w", err)
	}
	if stats.NodeCount == 0 {
		return errors.New("graph query: this store declares the symbol-graph labels but holds no " +
			"nodes. An export writes at least one module node, so its image is missing rather " +
			"than its program being empty")
	}

	need := []string{"key", "name"}
	declarations, err := g.QueryNodeIDs(store.NodeQuery{Types: []store.NodeType{nodeDeclaration}})
	if err != nil {
		return fmt.Errorf("graph query: %w", err)
	}
	if len(declarations) > 0 {
		need = append(need, "id", "kind", "module")
	}
	missing, known := graphstore.UnindexedKeys(g, need)
	if !known || len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("graph query: this store does not index %q, so a lookup by it would "+
		"match nothing and report no error. It was written by a different version of "+
		"`mutant graph export`", missing[0])
}

// --- the modules, which every other answer renders through ---

// moduleIndex is every module node, decoded once. There is one per file, so
// reading them all is cheap, and it is what lets a declaration's `module` --
// which is a canonical key, lowercased and absolute -- be printed as the name
// somebody would recognise.
type moduleIndex struct {
	byKey   map[string]moduleProps
	byID    map[store.NodeID]moduleProps
	keyByID map[store.NodeID]string
	idByKey map[string]store.NodeID
	ordered []moduleProps

	// root is the directory every module in this store is under, and short
	// names are relative to it. See commonRoot.
	root string
}

func loadModules(g *graphene.Graph) (*moduleIndex, error) {
	ids, err := g.QueryNodeIDs(store.NodeQuery{Types: []store.NodeType{nodeModule}})
	if err != nil {
		return nil, fmt.Errorf("graph query: reading the modules: %w", err)
	}
	found, _, err := g.GetNodes(ids)
	if err != nil {
		return nil, fmt.Errorf("graph query: reading the modules: %w", err)
	}

	index := &moduleIndex{
		byKey:   make(map[string]moduleProps, len(found)),
		byID:    make(map[store.NodeID]moduleProps, len(found)),
		keyByID: make(map[store.NodeID]string, len(found)),
		idByKey: make(map[string]store.NodeID, len(found)),
	}
	for _, node := range found {
		var props moduleProps
		if err := json.Unmarshal(node.Properties, &props); err != nil {
			return nil, fmt.Errorf("graph query: module node %d is not readable: %w", node.ID, err)
		}
		index.byKey[props.Key] = props
		index.byID[node.ID] = props
		index.keyByID[node.ID] = props.Key
		index.idByKey[props.Key] = node.ID
		index.ordered = append(index.ordered, props)
	}
	index.root = commonRoot(index.ordered)
	sort.Slice(index.ordered, func(i, j int) bool {
		return index.shortPath(index.ordered[i]) < index.shortPath(index.ordered[j])
	})
	return index, nil
}

// commonRoot is the deepest directory every module is under.
//
// It exists because the name the export indexed is not one a reader can use.
// moduleName writes Display, which is the path relative to the directory the
// export was run from -- so the same two files exported from two places carry
// two different names under one index key, and exported from anywhere but their
// own tree they carry absolute paths. Rendering those is a wall of prefix.
//
// Relative to a root computed from the store itself, the names are short, and
// they are the same short names whoever ran the export and from wherever. The
// root is printed once, so nothing is hidden by shortening it.
//
// Empty when the modules share no directory -- separate drives on Windows, say
// -- in which case the full path is what there is.
//
// Segments are compared byte for byte and not folded. Folding looks like the
// friendly choice on Windows and is the wrong one here: the store may have been
// written on a filesystem where Lib and lib are two directories, the reader's
// platform does not decide what the exporter's filesystem did, and a root that
// matches neither spelling exactly makes shortPath give up and print both
// modules in full. Worse, two files with the same basename under directories
// differing only in case then render as the same row, and `outline` refuses
// them by printing one name twice.
func commonRoot(modules []moduleProps) string {
	if len(modules) == 0 {
		return ""
	}
	split := func(path string) []string {
		return strings.Split(filepath.ToSlash(filepath.Dir(path)), "/")
	}
	shared := split(modules[0].Path)
	for _, props := range modules[1:] {
		segments := split(props.Path)
		limit := len(shared)
		if len(segments) < limit {
			limit = len(segments)
		}
		cut := 0
		for cut < limit && shared[cut] == segments[cut] {
			cut++
		}
		shared = shared[:cut]
	}
	if len(shared) == 0 || (len(shared) == 1 && shared[0] == "") {
		return ""
	}
	// A volume root already ends in a separator -- "X:\", "//server/share/",
	// and "/" all do -- so filepath.Dir returns it with one and the Join leaves
	// a doubled separator that matches no module's path. Trim it, and give up
	// on a root that is nothing but separator.
	root := strings.TrimRight(strings.Join(shared, "/"), "/")
	if root == "" {
		return ""
	}
	return root
}

// shortPath is a module's path relative to the store's common root.
//
// Byte-exact, for the reason commonRoot is: the root was computed from these
// same paths, so an exact match is what a correct root produces, and a folded
// one would strip a prefix the path does not actually carry.
func (m *moduleIndex) shortPath(props moduleProps) string {
	full := filepath.ToSlash(props.Path)
	if m.root == "" {
		return full
	}
	if len(full) > len(m.root)+1 && full[:len(m.root)] == m.root &&
		full[len(m.root)] == '/' {
		return full[len(m.root)+1:]
	}
	return full
}

// name renders a module key as something short enough to read, falling back to
// the key. A key is a canonical absolute path: right for looking up, wrong for
// reading, and on Windows lowercased as well.
func (m *moduleIndex) name(key string) string {
	if props, known := m.byKey[key]; known {
		return m.shortPath(props)
	}
	return key
}

// resolve turns what somebody typed into a module key.
//
// The indexed value is sema.CanonicalKey of an absolute path, which on Windows
// is lowercased; a filter is byte-exact and does no folding, so the path a user
// copies out of the export's own banner matches nothing and reports no error.
// Rather than filter, this reads the modules -- there are as many as there are
// files -- and matches on the whole key, then on a path-boundary suffix. A
// suffix that matches more than one module is refused by name, because picking
// one would be picking which file the answer is about.
//
// It returns the key and the name to print. Both branches print the short path,
// which is what the sibling questions print: the first returned nothing at all,
// so `outline` typed as a path that filepath.Abs happened to resolve -- which
// includes an ordinary relative name typed from the store's own root -- printed
// a headline with no module in it. The second returned the absolute Path, which
// no other answer here does.
func (m *moduleIndex) resolve(argument string) (string, string, error) {
	if len(m.ordered) == 0 {
		return "", "", errors.New("graph query: this store holds no modules")
	}

	if absolute, err := filepath.Abs(argument); err == nil {
		if props, known := m.byKey[sema.CanonicalKey(absolute)]; known {
			return props.Key, m.shortPath(props), nil
		}
	}

	wanted := strings.ToLower(filepath.ToSlash(filepath.Clean(argument)))
	var matched []moduleProps
	for _, props := range m.ordered {
		candidate := strings.ToLower(filepath.ToSlash(props.Key))
		if candidate == wanted ||
			strings.HasSuffix(candidate, "/"+wanted) ||
			strings.ToLower(m.shortPath(props)) == wanted ||
			strings.ToLower(filepath.ToSlash(props.Name)) == wanted {
			matched = append(matched, props)
		}
	}

	switch len(matched) {
	case 1:
		return matched[0].Key, m.shortPath(matched[0]), nil
	case 0:
		names := make([]string, 0, len(m.ordered))
		for _, props := range m.ordered {
			names = append(names, m.shortPath(props))
		}
		return "", "", fmt.Errorf("graph query: no module here is called %q. This store holds: %s",
			argument, strings.Join(names, ", "))
	default:
		paths := make([]string, 0, len(matched))
		for _, props := range matched {
			paths = append(paths, props.Path)
		}
		return "", "", fmt.Errorf("graph query: %q names %d of this store's modules -- %s. "+
			"Say which", argument, len(matched), strings.Join(paths, ", "))
	}
}

// --- declarations ---

// declaration is a node and its decoded blob, together, because every renderer
// wants both: the id to follow edges from and the fields to print.
type declaration struct {
	id    store.NodeID
	props declProps
}

func decodeDeclarations(g *graphene.Graph, ids []store.NodeID) ([]declaration, error) {
	found, _, err := g.GetNodes(ids)
	if err != nil {
		return nil, fmt.Errorf("graph query: reading declarations: %w", err)
	}
	out := make([]declaration, 0, len(found))
	for _, node := range found {
		var props declProps
		if err := json.Unmarshal(node.Properties, &props); err != nil {
			return nil, fmt.Errorf("graph query: declaration node %d is not readable: %w", node.ID, err)
		}
		out = append(out, declaration{id: node.ID, props: props})
	}
	return out, nil
}

// allDeclarations reads every declaration record in the store.
//
// This is the scan the blob-only fields need. It is named rather than inlined
// so that the two questions which pay for it -- `exported`, and a `where` that
// found nothing exactly -- are the only ones that can, and so that the help can
// say which those are.
func allDeclarations(g *graphene.Graph) ([]declaration, error) {
	ids, err := g.QueryNodeIDs(store.NodeQuery{Types: []store.NodeType{nodeDeclaration}})
	if err != nil {
		return nil, fmt.Errorf("graph query: reading declarations: %w", err)
	}
	return decodeDeclarations(g, ids)
}

// declarationsNamed is the indexed lookup: `name` is written to the index by
// the export, and the value is the identifier exactly as the source spells it.
//
// Types is not decoration. `name` is one keyspace shared by modules and
// declarations, so a lookup without it would list files among symbols.
func declarationsNamed(g *graphene.Graph, name string) ([]declaration, error) {
	ids, err := g.QueryNodeIDs(store.NodeQuery{
		Types: []store.NodeType{nodeDeclaration},
		Filters: []store.PropertyFilter{
			{Key: "name", Op: store.PropertyOpEqual, Value: []byte(name)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("graph query: looking up %q: %w", name, err)
	}
	return decodeDeclarations(g, ids)
}

func sortDeclarations(decls []declaration, modules *moduleIndex) {
	sort.Slice(decls, func(i, j int) bool {
		left, right := decls[i].props, decls[j].props
		if leftName, rightName := modules.name(left.Module), modules.name(right.Module); leftName != rightName {
			return leftName < rightName
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.Column != right.Column {
			return left.Column < right.Column
		}
		return left.Name < right.Name
	})
}

// at renders a declaration's place: the module somebody would recognise, and
// the line and column that open the file there.
func at(modules *moduleIndex, props declProps) string {
	return fmt.Sprintf("%s:%d:%d", modules.name(props.Module), props.Line, props.Column)
}

// describe renders a declaration for a list.
//
// markExported is false where the section is already only exported names, and
// true where the list is mixed and the distinction is the reader's to make.
func describe(modules *moduleIndex, props declProps, markExported bool) string {
	description := fmt.Sprintf("%-28s %-10s %s", props.Name, props.Kind, at(modules, props))
	if props.Scope != "" {
		description += "  in " + props.Scope
	}
	if markExported && props.Exported {
		description += "  exported"
	}
	if !props.Written {
		description += "  (the name is not written in the file)"
	}
	return description
}

// --- summary ---

func answerSummary(g *graphene.Graph, answer *QueryAnswer) error {
	stats, err := g.Stats()
	if err != nil {
		return fmt.Errorf("graph query: %w", err)
	}
	nodeNames, edgeNames := labelNames()

	answer.Headline = fmt.Sprintf("%d nodes, %d edges", stats.NodeCount, stats.EdgeCount)
	if !stats.HasTypeCounts {
		answer.Notes = append(answer.Notes,
			"this store cannot break its totals down by label, so only the totals are shown")
		return nil
	}

	nodes := AnswerSection{Title: "Nodes, by label", Empty: "none"}
	for _, label := range orderedNodeLabels() {
		if count := stats.NodesByType[label]; count > 0 {
			nodes.Rows = append(nodes.Rows, fmt.Sprintf("  %-14s %d", nodeNames[label], count))
		}
	}
	edges := AnswerSection{Title: "Edges, by label", Empty: "none"}
	for _, label := range orderedEdgeLabels() {
		if count := stats.EdgesByType[label]; count > 0 {
			edges.Rows = append(edges.Rows, fmt.Sprintf("  %-14s %d", edgeNames[label], count))
		}
	}
	answer.Sections = append(answer.Sections, nodes, edges)

	answer.Notes = append(answer.Notes,
		"these do not add up to the totals, and are not meant to. Every declaration carries "+
			"Declaration and its kind, so it is counted twice; a USES_TYPE, CONSTRUCTS or MATCHES "+
			"edge is a REFERENCES edge carrying a further label, so it is too")
	return nil
}

func orderedNodeLabels() []store.NodeType {
	return []store.NodeType{
		nodeModule, nodeDeclaration, nodeFunction, nodeValue, nodeParam,
		nodeLoopBind, nodeNamespace, nodeStruct, nodeEnum, nodeField, nodeVariant,
	}
}

func orderedEdgeLabels() []store.EdgeType {
	return []store.EdgeType{
		edgeDeclares, edgeEncloses, edgeReferences, edgeImports, edgeUsesType,
		edgeConstructs, edgeMatches,
	}
}

// --- modules ---

func answerModules(g *graphene.Graph, answer *QueryAnswer) error {
	modules, err := loadModules(g)
	if err != nil {
		return err
	}

	// One call, and it is the index rather than the records: `module` is
	// written as an index entry on every declaration and on nothing else.
	counts, err := g.CountNodesByProperty("module")
	if err != nil {
		return fmt.Errorf("graph query: counting declarations per module: %w", err)
	}

	importIDs, err := g.QueryEdgeIDs(store.EdgeQuery{Types: []store.EdgeType{edgeImports}})
	if err != nil {
		return fmt.Errorf("graph query: reading the imports: %w", err)
	}
	importEdges, _, err := g.GetEdges(importIDs)
	if err != nil {
		return fmt.Errorf("graph query: reading the imports: %w", err)
	}

	importsOf := make(map[string][]string, len(modules.ordered))
	imported := make(map[string]bool, len(modules.ordered))
	for _, edge := range importEdges {
		var props importProps
		_ = json.Unmarshal(edge.Properties, &props)
		from, known := modules.keyByID[edge.Src]
		to, toKnown := modules.keyByID[edge.Dst]
		if !known || !toKnown {
			continue
		}
		imported[to] = true
		importsOf[from] = append(importsOf[from], fmt.Sprintf("%s -> %s", props.Alias, modules.name(to)))
	}

	listing := AnswerSection{Title: "Modules", Empty: "none"}
	entry := AnswerSection{
		Title: "Imported by nothing here",
		Empty: "none -- every module in this store is imported by another",
	}
	for _, props := range modules.ordered {
		row := fmt.Sprintf("  %-34s %d declaration(s)", modules.shortPath(props), counts[props.Key])
		if edges := importsOf[props.Key]; len(edges) > 0 {
			sort.Strings(edges)
			row += "\n      imports " + strings.Join(edges, ", ")
		}
		listing.Rows = append(listing.Rows, row)
		if !imported[props.Key] {
			entry.Rows = append(entry.Rows, "  "+modules.shortPath(props))
		}
	}

	answer.Headline = fmt.Sprintf("%d module(s)", len(modules.ordered))
	if modules.root != "" {
		answer.Headline += " under " + filepath.FromSlash(modules.root)
	}
	answer.Sections = append(answer.Sections, listing, entry)
	answer.Notes = append(answer.Notes,
		"the import graph is the one part of this store that is complete: the export refuses "+
			"to write an edge for an import that did not resolve, so an import shown here "+
			"resolved to a file that is also here",
		"a module imported by nothing is the program's entry, or a file the entry does not "+
			"reach and that was exported alongside it")
	return nil
}

// --- where ---

func answerWhere(g *graphene.Graph, name string, answer *QueryAnswer) error {
	modules, err := loadModules(g)
	if err != nil {
		return err
	}
	decls, err := declarationsNamed(g, name)
	if err != nil {
		return err
	}

	if len(decls) == 0 {
		// An exact lookup found nothing, which in this engine is also what a
		// lookup with the wrong casing looks like. Saying which it was costs
		// one scan and turns a confident nothing into an answer.
		all, scanErr := allDeclarations(g)
		if scanErr != nil {
			return scanErr
		}
		var folded []declaration
		for _, decl := range all {
			if strings.EqualFold(decl.props.Name, name) {
				folded = append(folded, decl)
			}
		}
		if len(folded) > 0 {
			sortDeclarations(folded, modules)
			section := AnswerSection{Title: "Declared, but spelled differently"}
			for _, decl := range folded {
				section.Rows = append(section.Rows, "  "+describe(modules, decl.props, true))
			}
			answer.Headline = fmt.Sprintf("nothing is called %q, but %d declaration(s) differ from it only in case",
				name, len(folded))
			answer.Sections = append(answer.Sections, section)
			answer.Notes = append(answer.Notes, missScanned)
			return nil
		}
		answer.Headline = fmt.Sprintf("nothing in this store is called %q", name)
		answer.Notes = append(answer.Notes,
			"a name is matched exactly, as the source spells it. This store was searched for "+
				"other casings too, and there are none",
			missScanned)
		return nil
	}

	sortDeclarations(decls, modules)
	section := AnswerSection{Title: "Declared at"}
	for _, decl := range decls {
		section.Rows = append(section.Rows, "  "+describe(modules, decl.props, true))
	}

	answer.Headline = fmt.Sprintf("%d declaration(s) called %q", len(decls), name)
	answer.Sections = append(answer.Sections, section)
	if len(decls) > 1 {
		answer.Notes = append(answer.Notes,
			"more than one declaration carries this name. Identity here is positional, so a name "+
				"shadowed in an inner scope, or declared in two modules, is two declarations and "+
				"both are listed")
	}
	answer.Notes = append(answer.Notes,
		"`exported` is Mutant's own rule -- a top-level value or function whose name does not "+
			"begin with an underscore. A struct, enum, field or variant is never marked exported")
	return nil
}

// missScanned is what a question taking a name owes a reader when the index
// missed. The help lists these questions among the ones that can read every
// record, and an answer that did not repeat it would leave the one place a
// reader is actually looking -- the answer in front of them -- silent about
// what it cost.
const missScanned = "the index held no declaration under this exact name, so this answer read " +
	"every declaration record in the store rather than an index"

// --- callers and callees ---

// answerUses renders the REFERENCES edges on either side of a name.
//
// One relation query per direction, anchored on every declaration of the name.
// Not a traversal: BFS and DFS deduplicate by neighbour, so a node reached by
// two edges reports one of them, and REFERENCES runs parallel to DECLARES
// almost everywhere in this schema.
func answerUses(g *graphene.Graph, name string, direction store.Direction, answer *QueryAnswer) error {
	modules, err := loadModules(g)
	if err != nil {
		return err
	}
	decls, err := declarationsNamed(g, name)
	if err != nil {
		return err
	}
	if len(decls) == 0 {
		// The only questions whose empty answer said nothing about why. `where`
		// names the declarations that differ only in case and `outline` lists
		// the modules it holds, so `callers Mean` answering a flat nothing
		// while `where Mean` finds `mean` was this file disagreeing with
		// itself about the same store.
		answer.Headline = fmt.Sprintf("nothing in this store is called %q", name)
		all, scanErr := allDeclarations(g)
		if scanErr != nil {
			return scanErr
		}
		var folded []string
		for _, decl := range all {
			if strings.EqualFold(decl.props.Name, name) && decl.props.Name != name {
				folded = append(folded, fmt.Sprintf("%s at %s", decl.props.Name, at(modules, decl.props)))
			}
		}
		if len(folded) > 0 {
			sort.Strings(folded)
			answer.Notes = append(answer.Notes, fmt.Sprintf(
				"a name is matched exactly, as the source spells it, and %d declaration(s) differ "+
					"from this one only in case: %s. Ask about one of those to see its uses",
				len(folded), strings.Join(folded, ", ")), missScanned)
			return nil
		}
		answer.Notes = append(answer.Notes,
			"nothing is declared under this name in any casing either, so the question is about "+
				"a name this store does not hold rather than about one spelled differently",
			missScanned)
		return nil
	}
	sortDeclarations(decls, modules)

	inbound := direction == store.DirectionInbound
	total := 0
	for _, decl := range decls {
		edges, err := g.QueryRelations(store.RelationQuery{
			Anchors:   []store.NodeID{decl.id},
			Direction: direction,
			EdgeTypes: []store.EdgeType{edgeReferences},
		})
		if err != nil {
			return fmt.Errorf("graph query: reading the references of %q: %w", name, err)
		}

		title := fmt.Sprintf("Used by, for %s declared at %s", decl.props.Name, at(modules, decl.props))
		empty := "  nothing in this store references it"
		if !inbound {
			title = fmt.Sprintf("Uses, from %s declared at %s", decl.props.Name, at(modules, decl.props))
			empty = "  it references nothing"
		}
		section := AnswerSection{Title: title, Empty: empty}

		rows, err := renderUses(g, modules, decl, edges, inbound)
		if err != nil {
			return err
		}
		section.Rows = rows
		total += len(rows)
		answer.Sections = append(answer.Sections, section)
	}

	if inbound {
		answer.Headline = fmt.Sprintf("%d recorded use(s) of %q", total, name)
		answer.Notes = append(answer.Notes,
			"a use from another module is not here. `stats.mean(...)` is recorded against the "+
				"import alias `stats`, which is a declaration of the calling file, and never "+
				"reaches `mean` -- so this is complete within a module and a floor across one",
			"a use the export could not resolve leaves no edge at all, so an empty answer means "+
				"'nothing in this store references it', never 'nothing does'")
	} else {
		answer.Headline = fmt.Sprintf("%d recorded use(s) from %q", total, name)
		answer.Notes = append(answer.Notes,
			"a use of a name from another module lands on the import alias, so a call written "+
				"`stats.mean(...)` appears here as a use of `stats`")
	}
	return nil
}

func renderUses(g *graphene.Graph, modules *moduleIndex, anchor declaration,
	edges []*store.Edge, inbound bool) ([]string, error) {

	counterparts := make([]store.NodeID, 0, len(edges))
	for _, edge := range edges {
		if inbound {
			counterparts = append(counterparts, edge.Src)
		} else {
			counterparts = append(counterparts, edge.Dst)
		}
	}
	found, _, err := g.GetNodes(counterparts)
	if err != nil {
		return nil, fmt.Errorf("graph query: reading the other end of a reference: %w", err)
	}
	byID := make(map[store.NodeID]*store.Node, len(found))
	for _, node := range found {
		byID[node.ID] = node
	}

	// Sorted on the position, not on the rendered row. Sorting the strings put
	// line 10 and line 11 before line 2, which is the one ordering a reader of
	// a file will not expect.
	type use struct {
		module string
		line   int
		column int
		text   string
	}
	uses := make([]use, 0, len(edges))
	for _, edge := range edges {
		var props refProps
		_ = json.Unmarshal(edge.Properties, &props)

		other := edge.Src
		if !inbound {
			other = edge.Dst
		}

		// The position on a REFERENCES edge is where the use is written, which
		// is in the module the edge runs FROM. Inbound, that is the far end;
		// outbound, it is the anchor -- and taking it from the far end there
		// named the wrong file for any reference that crossed one.
		site := anchor.props.Module
		if inbound {
			site = moduleOf(g, modules, other)
		}

		what := describeCounterpart(modules, byID[other])
		if other == anchor.id {
			what += "  (itself -- recursive)"
		}
		if props.Call {
			what += "  called"
		}
		name := modules.name(site)
		uses = append(uses, use{
			module: name,
			line:   props.Line,
			column: props.Column,
			text:   fmt.Sprintf("  %-34s %s", fmt.Sprintf("%s:%d:%d", name, props.Line, props.Column), what),
		})
	}
	sort.Slice(uses, func(i, j int) bool {
		if uses[i].module != uses[j].module {
			return uses[i].module < uses[j].module
		}
		if uses[i].line != uses[j].line {
			return uses[i].line < uses[j].line
		}
		if uses[i].column != uses[j].column {
			return uses[i].column < uses[j].column
		}
		return uses[i].text < uses[j].text
	})
	rows := make([]string, 0, len(uses))
	for _, u := range uses {
		rows = append(rows, u.text)
	}
	return rows, nil
}

// moduleOf names the file a node belongs to. A reference's source is a
// declaration when it was written inside one and the module itself when it was
// written at the top level of a file, so both have to be handled: a renderer
// that assumed a declaration would drop every module-scope use, and on the
// smallest program that is the call that starts it.
func moduleOf(g *graphene.Graph, modules *moduleIndex, id store.NodeID) string {
	if key, isModule := modules.keyByID[id]; isModule {
		return key
	}
	found, _, err := g.GetNodes([]store.NodeID{id})
	if err != nil || len(found) == 0 {
		return ""
	}
	var props declProps
	if err := json.Unmarshal(found[0].Properties, &props); err != nil {
		return ""
	}
	return props.Module
}

func describeCounterpart(modules *moduleIndex, node *store.Node) string {
	if node == nil {
		return "a node this store no longer holds"
	}
	if props, isModule := modules.byID[node.ID]; isModule {
		return "at the top level of " + modules.shortPath(props)
	}
	var props declProps
	if err := json.Unmarshal(node.Properties, &props); err != nil {
		return "a declaration this store cannot read"
	}
	return fmt.Sprintf("%s (%s)", props.Name, props.Kind)
}

// --- outline ---

func answerOutline(g *graphene.Graph, argument string, answer *QueryAnswer) error {
	modules, err := loadModules(g)
	if err != nil {
		return err
	}
	key, path, err := modules.resolve(argument)
	if err != nil {
		return err
	}

	ids, err := g.QueryNodeIDs(store.NodeQuery{
		Types: []store.NodeType{nodeDeclaration},
		Filters: []store.PropertyFilter{
			{Key: "module", Op: store.PropertyOpEqual, Value: []byte(key)},
		},
	})
	if err != nil {
		return fmt.Errorf("graph query: reading the declarations of %s: %w", modules.name(key), err)
	}
	decls, err := decodeDeclarations(g, ids)
	if err != nil {
		return err
	}

	byID := make(map[store.NodeID]declProps, len(decls))
	for _, decl := range decls {
		byID[decl.id] = decl.props
	}

	// One anchored relation query over every declaration in the file. The
	// nesting is rebuilt here rather than walked, so no edge is dropped.
	enclosing, err := g.QueryRelations(store.RelationQuery{
		Anchors:   ids,
		Direction: store.DirectionOutbound,
		EdgeTypes: []store.EdgeType{edgeEncloses},
	})
	if err != nil {
		return fmt.Errorf("graph query: reading what encloses what: %w", err)
	}
	children := make(map[store.NodeID][]store.NodeID, len(decls))
	enclosed := make(map[store.NodeID]bool, len(decls))
	for _, edge := range enclosing {
		if _, ours := byID[edge.Dst]; !ours {
			continue
		}
		children[edge.Src] = append(children[edge.Src], edge.Dst)
		enclosed[edge.Dst] = true
	}

	declared := make([]store.NodeID, 0, len(decls))
	for _, decl := range decls {
		declared = append(declared, decl.id)
	}
	outline := newOutliner(byID, children)
	section := AnswerSection{Title: "Declarations", Empty: "  this module declares nothing"}
	section.Rows = outline.module(declared, enclosed)

	answer.Headline = fmt.Sprintf("%s -- %d declaration(s)", path, len(decls))
	answer.Sections = append(answer.Sections, section)
	answer.Notes = append(answer.Notes,
		"the nesting is lexical: what a declaration encloses is what is written inside it -- a "+
			"function's parameters and locals, a struct's fields, an enum's variants")
	if outline.repeats > 0 {
		answer.Notes = append(answer.Notes, fmt.Sprintf(
			"%d declaration(s) here are enclosed by more than one other. An export writes each "+
				"declaration inside exactly one, so this store was altered after it was written; "+
				"each is shown in full once and marked where it appears again", outline.repeats))
	}
	return nil
}

// module renders every declaration of one module: those nothing encloses, in
// source order, each with what it encloses beneath it.
//
// Then any declaration that has still not been shown. One enclosed only from
// inside a cycle is reached from no root, and the headline has already counted
// it; it is rendered at the top level rather than left out of an answer that
// claims to list the module.
func (o *outliner) module(ids []store.NodeID, enclosed map[store.NodeID]bool) []string {
	roots := make([]store.NodeID, 0, len(ids))
	for _, id := range ids {
		if !enclosed[id] {
			roots = append(roots, id)
		}
	}
	sortByPosition(roots, o.byID)
	var rows []string
	for _, root := range roots {
		rows = append(rows, o.rows(root, 1, "")...)
	}

	unreached := make([]store.NodeID, 0)
	for _, id := range ids {
		if !o.shown[id] {
			unreached = append(unreached, id)
		}
	}
	sortByPosition(unreached, o.byID)
	for _, id := range unreached {
		if !o.shown[id] {
			rows = append(rows, o.rows(id, 1, "")...)
		}
	}
	return rows
}

// outliner renders a module's declarations nested as ENCLOSES says they are.
//
// It carries two sets, and each is the difference between an answer and a
// failure to give one. The nesting in a store this program wrote is a tree, but
// nothing on the read side can know that.
//
// onPath is the declarations between the root and here. A single ENCLOSES edge
// from a node to itself -- one byte's worth of damage, or a future exporter
// with a different idea of what encloses what -- made the renderer recurse
// without end, and because every frame keeps a row string that grows with its
// own depth, it did so in quadratic memory rather than in a stack overflow.
// Measured on one self-loop: 9,226 MB in 17.9 seconds, still climbing. A cycle
// is reported where it is found and not followed.
//
// shown is every declaration already rendered anywhere in the answer. onPath
// alone let a declaration with two enclosers be rendered in full under each,
// and a nesting in which every level encloses both declarations of the next
// doubles at every level: 2^(L+1)-2 rows for L levels, 131,070 of them for
// thirty-two declarations (M26-TOOL-015). Each declaration is now rendered once
// and named, one line, wherever it appears again.
type outliner struct {
	byID     map[store.NodeID]declProps
	children map[store.NodeID][]store.NodeID
	onPath   map[store.NodeID]bool
	shown    map[store.NodeID]bool

	// repeats counts the declarations reached a second time, which the answer
	// owes a note: a tree has none.
	repeats int
}

func newOutliner(byID map[store.NodeID]declProps, children map[store.NodeID][]store.NodeID) *outliner {
	return &outliner{
		byID:     byID,
		children: children,
		onPath:   map[store.NodeID]bool{},
		shown:    map[store.NodeID]bool{},
	}
}

// rows renders one declaration and everything written inside it. parent is the
// name of the declaration it was reached from, "" at a root.
func (o *outliner) rows(id store.NodeID, depth int, parent string) []string {
	props := o.byID[id]
	indent := strings.Repeat("  ", depth)
	if o.onPath[id] {
		return []string{fmt.Sprintf("%s  %s  (encloses itself -- the nesting in this store is a "+
			"cycle, so it is reported here and not followed)", indent, props.Name)}
	}
	if o.shown[id] {
		o.repeats++
		return []string{fmt.Sprintf("%s  %s  (also enclosed by %s; shown in full above, under the "+
			"first declaration that encloses it)", indent, props.Name, parent)}
	}
	o.shown[id] = true

	// The star width is clamped because fmt reads a negative one as a left
	// flag and a positive width, so past depth 15 the name column grew by two
	// per level instead of shrinking and the kind column marched right.
	width := 30 - 2*depth
	if width < 8 {
		width = 8
	}
	row := fmt.Sprintf("  %s%-*s %-10s %d:%d",
		indent, width, props.Name, props.Kind, props.Line, props.Column)
	if props.Exported {
		row += "  exported"
	}
	rows := []string{row}

	o.onPath[id] = true
	kids := append([]store.NodeID(nil), o.children[id]...)
	sortByPosition(kids, o.byID)
	for _, kid := range kids {
		rows = append(rows, o.rows(kid, depth+1, props.Name)...)
	}
	delete(o.onPath, id)
	return rows
}

func sortByPosition(ids []store.NodeID, byID map[store.NodeID]declProps) {
	sort.Slice(ids, func(i, j int) bool {
		left, right := byID[ids[i]], byID[ids[j]]
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.Column != right.Column {
			return left.Column < right.Column
		}
		return left.Name < right.Name
	})
}

// --- exported ---

// answerExported reads every declaration record.
//
// `exported` is in the blob and not in the index, and a filter on it would
// match nothing and report no error -- so this does not filter, it decodes.
// That is a real cost and it is stated in the help rather than hidden: on a
// four-thousand-declaration store it is tens of milliseconds, against
// microseconds for a lookup by name.
func answerExported(g *graphene.Graph, answer *QueryAnswer) error {
	modules, err := loadModules(g)
	if err != nil {
		return err
	}
	all, err := allDeclarations(g)
	if err != nil {
		return err
	}

	exported := make([]declaration, 0, len(all))
	for _, decl := range all {
		if decl.props.Exported {
			exported = append(exported, decl)
		}
	}
	sortDeclarations(exported, modules)

	section := AnswerSection{
		Title: "Exported",
		Empty: "  nothing in this store is exported",
	}
	for _, decl := range exported {
		section.Rows = append(section.Rows, "  "+describe(modules, decl.props, false))
	}

	answer.Headline = fmt.Sprintf("%d of %d declaration(s) are exported", len(exported), len(all))
	answer.Sections = append(answer.Sections, section)
	answer.Notes = append(answer.Notes,
		"exported means another module could name it: a top-level value or function whose name "+
			"does not begin with an underscore. That is the whole of Mutant's rule, so a struct, "+
			"an enum, a field and a variant are never exported",
		"this answer read every declaration record, because whether a name is exported is in the "+
			"blob and not in the index")
	return nil
}

// --- types and type ---

// typeUsage is what the store records about one struct or enum: how many
// members it declares, and how many recorded uses name it -- of which how many
// build it and how many match against it.
type typeUsage struct {
	members int
	uses    int
	built   int
	matched int
}

// typeDeclarations reads every struct and enum. The kind labels are the index
// here: every declaration carries its kind as a second label, so the two sets
// are found without reading a record that is not one of them.
func typeDeclarations(g *graphene.Graph) ([]declaration, error) {
	ids, err := g.QueryNodeIDs(store.NodeQuery{Types: []store.NodeType{nodeStruct, nodeEnum}})
	if err != nil {
		return nil, fmt.Errorf("graph query: reading the types: %w", err)
	}
	return decodeDeclarations(g, ids)
}

// typeUses reads what every type in decls encloses and what uses it: two
// relation queries anchored on all of them at once, grouped here. A use is
// sorted by the labels its edge carries, which is why this is a relation query
// and not a traversal -- a walk keeps one edge per neighbour, and a function
// that builds a Point twice is two constructions.
func typeUses(g *graphene.Graph, decls []declaration) (map[store.NodeID]*typeUsage,
	map[store.NodeID][]*store.Edge, error) {

	anchors := make([]store.NodeID, 0, len(decls))
	usage := make(map[store.NodeID]*typeUsage, len(decls))
	for _, decl := range decls {
		anchors = append(anchors, decl.id)
		usage[decl.id] = &typeUsage{}
	}
	if len(anchors) == 0 {
		return usage, nil, nil
	}

	members, err := g.QueryRelations(store.RelationQuery{
		Anchors:   anchors,
		Direction: store.DirectionOutbound,
		EdgeTypes: []store.EdgeType{edgeEncloses},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("graph query: reading the members of the types: %w", err)
	}
	for _, edge := range members {
		if counts, ours := usage[edge.Src]; ours {
			counts.members++
		}
	}

	uses, err := g.QueryRelations(store.RelationQuery{
		Anchors:   anchors,
		Direction: store.DirectionInbound,
		EdgeTypes: []store.EdgeType{edgeReferences},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("graph query: reading the uses of the types: %w", err)
	}
	byType := make(map[store.NodeID][]*store.Edge, len(decls))
	for _, edge := range uses {
		counts, ours := usage[edge.Dst]
		if !ours {
			continue
		}
		counts.uses++
		if edge.HasLabel(edgeConstructs) {
			counts.built++
		}
		if edge.HasLabel(edgeMatches) {
			counts.matched++
		}
		byType[edge.Dst] = append(byType[edge.Dst], edge)
	}
	return usage, byType, nil
}

// unresolvedTypeUses is every use of a type that left no edge, from the
// modules' own records, with the module each is written in.
type placedMiss struct {
	module string
	miss   typeMiss
}

func (m *moduleIndex) unresolvedTypeUses() []placedMiss {
	var out []placedMiss
	for _, props := range m.ordered {
		for _, miss := range props.UnresolvedTypeUses {
			out = append(out, placedMiss{module: props.Key, miss: miss})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if leftName, rightName := m.name(left.module), m.name(right.module); leftName != rightName {
			return leftName < rightName
		}
		if left.miss.Line != right.miss.Line {
			return left.miss.Line < right.miss.Line
		}
		return left.miss.Column < right.miss.Column
	})
	return out
}

// missRow renders one use of a type that left no edge.
func missRow(modules *moduleIndex, placed placedMiss) string {
	what := "names " + placed.miss.Name
	switch placed.miss.Role {
	case sema.RoleConstruct.String():
		what = "builds " + placed.miss.Name
	case sema.RolePattern.String():
		what = "matches against " + placed.miss.Name
	}
	return fmt.Sprintf("  %-34s %s", fmt.Sprintf("%s:%d:%d", modules.name(placed.module),
		placed.miss.Line, placed.miss.Column), what)
}

// missesNote says what a use that left no edge is. It is the compiler's rule,
// stated once, because the answer is otherwise a list of places the program
// uses a type and a reader would ask why none of them is counted.
const missesNote = "a use of a type is resolved the way the compiler resolves it: against the " +
	"types of this module and of every module compiled before it, which is every module it " +
	"imports and some it does not. A use of a type declared only by a module compiled later, " +
	"or by none, is one the compiler refuses, so it has no edge and is listed on its own"

// answerTypes lists every struct and enum with what the store records about
// its use: how often it is built, matched against, and used at all.
func answerTypes(g *graphene.Graph, roles bool, answer *QueryAnswer) error {
	modules, err := loadModules(g)
	if err != nil {
		return err
	}
	decls, err := typeDeclarations(g)
	if err != nil {
		return err
	}
	sortDeclarations(decls, modules)
	usage, _, err := typeUses(g, decls)
	if err != nil {
		return err
	}

	structs := AnswerSection{Title: "Structs", Empty: "  none"}
	enums := AnswerSection{Title: "Enums", Empty: "  none"}
	for _, decl := range decls {
		counts := usage[decl.id]
		row := fmt.Sprintf("  %-24s %-30s", decl.props.Name, at(modules, decl.props))
		switch decl.props.Kind {
		case sema.KindStruct.String():
			row += fmt.Sprintf(" %d field(s)", counts.members)
			if roles {
				row += fmt.Sprintf(", built %d time(s)", counts.built)
			}
			row += fmt.Sprintf(", %d use(s)", counts.uses)
			structs.Rows = append(structs.Rows, row)
		default:
			row += fmt.Sprintf(" %d variant(s)", counts.members)
			if roles {
				row += fmt.Sprintf(", matched %d time(s)", counts.matched)
			}
			row += fmt.Sprintf(", %d use(s)", counts.uses)
			enums.Rows = append(enums.Rows, row)
		}
	}

	answer.Headline = fmt.Sprintf("%d struct(s) and %d enum(s)", len(structs.Rows), len(enums.Rows))
	answer.Sections = append(answer.Sections, structs, enums)
	if !roles {
		answer.Notes = append(answer.Notes, preRolesNote)
		return nil
	}

	if misses := modules.unresolvedTypeUses(); len(misses) > 0 {
		section := AnswerSection{Title: "Uses of a type that left no edge"}
		for _, placed := range misses {
			section.Rows = append(section.Rows, missRow(modules, placed))
		}
		answer.Headline += fmt.Sprintf(", and %d use(s) of a type the compiler cannot see", len(misses))
		answer.Sections = append(answer.Sections, section)
	}
	answer.Notes = append(answer.Notes,
		"a use is every recorded reference to the type, built and matched ones included, so the "+
			"numbers overlap rather than add up",
		"`Dir.S` is a use of Dir and of its variant S, and `callers S` lists the second. A field "+
			"read, the `x` of `p.x`, is recorded against nothing: which struct `p` holds is "+
			"inference, which the export does not do",
		missesNote)
	return nil
}

// answerType answers for one struct or enum: what it declares, and every
// recorded use of it, sorted into the ones that build it, the ones that match
// against it, and the rest.
func answerType(g *graphene.Graph, name string, roles bool, answer *QueryAnswer) error {
	modules, err := loadModules(g)
	if err != nil {
		return err
	}
	named, err := declarationsNamed(g, name)
	if err != nil {
		return err
	}
	var decls []declaration
	var others []declaration
	for _, decl := range named {
		if decl.props.Kind == sema.KindStruct.String() || decl.props.Kind == sema.KindEnum.String() {
			decls = append(decls, decl)
		} else {
			others = append(others, decl)
		}
	}
	sortDeclarations(decls, modules)
	sortDeclarations(others, modules)

	var misses []placedMiss
	if roles {
		for _, placed := range modules.unresolvedTypeUses() {
			if placed.miss.Name == name {
				misses = append(misses, placed)
			}
		}
	}

	if len(decls) == 0 {
		return answerNoType(g, modules, name, others, misses, answer)
	}

	usage, uses, err := typeUses(g, decls)
	if err != nil {
		return err
	}
	for _, decl := range decls {
		if err := typeSections(g, modules, decl, uses[decl.id], roles, answer); err != nil {
			return err
		}
	}

	if len(decls) == 1 {
		decl, counts := decls[0], usage[decls[0].id]
		answer.Headline = fmt.Sprintf("%s %s, declared at %s: %d use(s)",
			decl.props.Kind, decl.props.Name, at(modules, decl.props), counts.uses)
		if roles && decl.props.Kind == sema.KindStruct.String() {
			answer.Headline += fmt.Sprintf(", %d of them building it", counts.built)
		}
		if roles && decl.props.Kind == sema.KindEnum.String() {
			answer.Headline += fmt.Sprintf(", %d of them in a match arm", counts.matched)
		}
	} else {
		answer.Headline = fmt.Sprintf("%d structs or enums are called %q", len(decls), name)
		answer.Notes = append(answer.Notes,
			"a struct or enum name belongs to the whole program, so a program that declares one "+
				"twice is refused by the compiler; the export writes it down anyway, and each "+
				"declaration is answered for separately")
	}
	if len(misses) > 0 {
		section := AnswerSection{Title: "Uses that left no edge"}
		for _, placed := range misses {
			section.Rows = append(section.Rows, missRow(modules, placed))
		}
		answer.Sections = append(answer.Sections, section)
	}
	if !roles {
		answer.Notes = append(answer.Notes, preRolesNote)
		return nil
	}
	answer.Notes = append(answer.Notes, missesNote)
	return nil
}

// typeSections renders one type's members and uses.
func typeSections(g *graphene.Graph, modules *moduleIndex, decl declaration,
	uses []*store.Edge, roles bool, answer *QueryAnswer) error {

	place := fmt.Sprintf("%s declared at %s", decl.props.Name, at(modules, decl.props))
	memberWord, emptyMembers := "Fields", "  it declares no fields"
	if decl.props.Kind == sema.KindEnum.String() {
		memberWord, emptyMembers = "Variants", "  it declares no variants"
	}

	enclosed, err := g.QueryRelations(store.RelationQuery{
		Anchors:   []store.NodeID{decl.id},
		Direction: store.DirectionOutbound,
		EdgeTypes: []store.EdgeType{edgeEncloses},
	})
	if err != nil {
		return fmt.Errorf("graph query: reading the members of %s: %w", decl.props.Name, err)
	}
	memberIDs := make([]store.NodeID, 0, len(enclosed))
	for _, edge := range enclosed {
		memberIDs = append(memberIDs, edge.Dst)
	}
	members, err := decodeDeclarations(g, memberIDs)
	if err != nil {
		return err
	}
	sortDeclarations(members, modules)
	membersSection := AnswerSection{Title: memberWord + " of " + place, Empty: emptyMembers}
	for _, member := range members {
		membersSection.Rows = append(membersSection.Rows,
			fmt.Sprintf("  %-28s %d:%d", member.props.Name, member.props.Line, member.props.Column))
	}
	answer.Sections = append(answer.Sections, membersSection)

	if !roles {
		rows, err := renderUses(g, modules, decl, uses, true)
		if err != nil {
			return err
		}
		answer.Sections = append(answer.Sections,
			AnswerSection{Title: "Used by, for " + place, Rows: rows, Empty: "  nothing in this store uses it"})
		return nil
	}

	var built, matched, rest []*store.Edge
	for _, edge := range uses {
		switch {
		case edge.HasLabel(edgeConstructs):
			built = append(built, edge)
		case edge.HasLabel(edgeMatches):
			matched = append(matched, edge)
		default:
			rest = append(rest, edge)
		}
	}
	isStruct := decl.props.Kind == sema.KindStruct.String()
	groups := []struct {
		title, empty string
		edges        []*store.Edge
		applies      bool
	}{
		{"Built by, for " + place, "  nothing in this store builds it", built, isStruct},
		{"Matched by, for " + place, "  no match arm in this store names it", matched, !isStruct},
		{"Otherwise used by, for " + place, "  nothing else in this store uses it", rest, true},
	}
	for _, group := range groups {
		// A struct is never matched and an enum never built -- a pattern is a
		// literal or a dotted name, and a struct literal names a struct -- so
		// a heading that cannot apply is left out rather than shown empty. One
		// that could and has nothing is shown, because "nothing builds it" is
		// an answer.
		if !group.applies && len(group.edges) == 0 {
			continue
		}
		rows, err := renderUses(g, modules, decl, group.edges, true)
		if err != nil {
			return err
		}
		answer.Sections = append(answer.Sections, AnswerSection{Title: group.title, Rows: rows, Empty: group.empty})
	}
	return nil
}

// answerNoType answers for a name that is no struct or enum here: what it is
// instead, if anything, and the casings that are types.
func answerNoType(g *graphene.Graph, modules *moduleIndex, name string, others []declaration,
	misses []placedMiss, answer *QueryAnswer) error {

	answer.Headline = fmt.Sprintf("nothing in this store declares a struct or enum called %q", name)
	if len(others) > 0 {
		section := AnswerSection{Title: "Declared, but not as a type"}
		for _, decl := range others {
			section.Rows = append(section.Rows, "  "+describe(modules, decl.props, true))
		}
		answer.Sections = append(answer.Sections, section)
		answer.Notes = append(answer.Notes, fmt.Sprintf(
			"%q is declared here, as something other than a struct or enum; `callers %s` lists its uses",
			name, name))
	}
	if len(misses) > 0 {
		section := AnswerSection{Title: "Uses that left no edge"}
		for _, placed := range misses {
			section.Rows = append(section.Rows, missRow(modules, placed))
		}
		answer.Sections = append(answer.Sections, section)
		answer.Notes = append(answer.Notes, missesNote)
	}
	if len(others) > 0 {
		return nil
	}

	types, err := typeDeclarations(g)
	if err != nil {
		return err
	}
	var folded []string
	for _, decl := range types {
		if strings.EqualFold(decl.props.Name, name) {
			folded = append(folded, fmt.Sprintf("%s at %s", decl.props.Name, at(modules, decl.props)))
		}
	}
	sort.Strings(folded)
	if len(folded) > 0 {
		answer.Notes = append(answer.Notes, fmt.Sprintf(
			"a name is matched exactly, as the source spells it, and %d type(s) differ from this one "+
				"only in case: %s", len(folded), strings.Join(folded, ", ")))
		return nil
	}
	answer.Notes = append(answer.Notes,
		"no struct or enum here is called this in any casing either, and nothing else is declared "+
			"under the name")
	return nil
}

// --- deps and rdeps ---

// importEdge is one IMPORTS edge, between two modules this store holds.
type importEdge struct {
	src, dst store.NodeID
	alias    string
}

// importEdges reads every IMPORTS edge. There is one per resolved `import`
// statement, so this is as many edges as the program has imports.
func importEdges(g *graphene.Graph, modules *moduleIndex) ([]importEdge, error) {
	ids, err := g.QueryEdgeIDs(store.EdgeQuery{Types: []store.EdgeType{edgeImports}})
	if err != nil {
		return nil, fmt.Errorf("graph query: reading the imports: %w", err)
	}
	edges, _, err := g.GetEdges(ids)
	if err != nil {
		return nil, fmt.Errorf("graph query: reading the imports: %w", err)
	}
	out := make([]importEdge, 0, len(edges))
	for _, edge := range edges {
		_, srcKnown := modules.keyByID[edge.Src]
		_, dstKnown := modules.keyByID[edge.Dst]
		if !srcKnown || !dstKnown {
			continue
		}
		var props importProps
		_ = json.Unmarshal(edge.Properties, &props)
		out = append(out, importEdge{src: edge.Src, dst: edge.Dst, alias: props.Alias})
	}
	return out, nil
}

// answerDeps answers `deps` (forward: what a module imports, transitively) and
// `rdeps` (what imports it).
//
// The walk is written here, over the IMPORTS edges read whole, and not handed
// to graphene. Its BFS keeps one edge per neighbour, so a module importing
// another under two aliases would show one import; and its path searches walk
// an edge either way, so a question about what a module imports would be
// answered with what imports it too. This follows each edge in its own
// direction and keeps every one.
//
// A module is listed once, at the fewest imports it takes to reach it, with
// every import in the closure that reaches it. The walk keeps the set of
// modules it has reached, so an import back into one of them is listed and not
// followed: module.Load refuses a cycle, but the store is a file, and a hang is
// the wrong answer to a damaged one.
func answerDeps(g *graphene.Graph, argument string, forward bool, answer *QueryAnswer) error {
	modules, err := loadModules(g)
	if err != nil {
		return err
	}
	key, path, err := modules.resolve(argument)
	if err != nil {
		return err
	}
	origin := modules.idByKey[key]
	edges, err := importEdges(g, modules)
	if err != nil {
		return err
	}

	walk := walkImports(origin, edges, forward)
	level, reached := walk.level, walk.reached
	sort.SliceStable(reached, func(i, j int) bool {
		if level[reached[i]] != level[reached[j]] {
			return level[reached[i]] < level[reached[j]]
		}
		return modules.shortPath(modules.byID[reached[i]]) < modules.shortPath(modules.byID[reached[j]])
	})

	verb := "imported by"
	if !forward {
		verb = "imports"
	}
	arriving := make(map[store.NodeID][]string, len(reached))
	for to, how := range walk.arriving {
		for _, edge := range how {
			from := edge.src
			if !forward {
				from = edge.dst
			}
			arriving[to] = append(arriving[to], fmt.Sprintf("%s %s as %s",
				verb, modules.name(modules.keyByID[from]), edge.alias))
		}
	}

	title, empty := "Imported, nearest first", "  it imports nothing"
	if !forward {
		title, empty = "Imported by, nearest first", "  nothing in this store imports it"
	}
	section := AnswerSection{Title: title, Empty: empty}
	direct := 0
	for _, id := range reached {
		if level[id] == 1 {
			direct++
		}
		how := arriving[id]
		sort.Strings(how)
		row := fmt.Sprintf("  %d  %-34s %s", level[id], modules.shortPath(modules.byID[id]), how[0])
		for _, more := range how[1:] {
			row += fmt.Sprintf("\n     %-34s %s", "", more)
		}
		section.Rows = append(section.Rows, row)
	}

	if forward {
		answer.Headline = fmt.Sprintf("%s imports %d module(s), %d of them directly", path, len(reached), direct)
	} else {
		answer.Headline = fmt.Sprintf("%d module(s) import %s, %d of them directly", len(reached), path, direct)
	}
	answer.Sections = append(answer.Sections, section)
	answer.Notes = append(answer.Notes,
		"the number is how many imports it takes to get there, counting the fewest; a module "+
			"reached more than one way is listed once, with every import that reaches it")
	if forward {
		answer.Notes = append(answer.Notes,
			"this is the whole closure: the export writes an import edge for every import that "+
				"resolved, and the loader refuses one that does not")
	} else {
		answer.Notes = append(answer.Notes,
			"this is complete for this store, which is the program the export was given. A module "+
				"the entry does not reach was not exported with it, so if it imports this one, it "+
				"is not here")
	}
	if walk.cycle {
		answer.Notes = append(answer.Notes, fmt.Sprintf(
			"an import leads back to %s. The loader refuses a cycle, so this store was not written "+
				"as it is by an export, or has been altered since; the walk stopped there rather "+
				"than going round", path))
	}
	return nil
}

// importWalk is what walkImports found: how many imports it takes to reach
// each module, the modules reached in the order the walk met them, every
// import inside the closure that lands on each, and whether one led back to
// the origin.
type importWalk struct {
	level    map[store.NodeID]int
	reached  []store.NodeID
	arriving map[store.NodeID][]importEdge
	cycle    bool
}

// walkImports follows IMPORTS edges from origin, each in its own direction:
// from importer to imported when forward, and back the other way when not.
// Breadth first, so a module's level is the fewest imports to it; each module
// is expanded once, which is the whole of the cycle guard.
func walkImports(origin store.NodeID, edges []importEdge, forward bool) importWalk {
	near, far := func(e importEdge) store.NodeID { return e.src }, func(e importEdge) store.NodeID { return e.dst }
	if !forward {
		near, far = far, near
	}
	next := make(map[store.NodeID][]importEdge)
	for _, edge := range edges {
		next[near(edge)] = append(next[near(edge)], edge)
	}

	walk := importWalk{
		level:    map[store.NodeID]int{origin: 0},
		reached:  []store.NodeID{},
		arriving: map[store.NodeID][]importEdge{},
	}
	queue := []store.NodeID{origin}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, edge := range next[id] {
			other := far(edge)
			if other == origin {
				walk.cycle = true
				continue
			}
			if _, seen := walk.level[other]; seen {
				continue
			}
			walk.level[other] = walk.level[id] + 1
			walk.reached = append(walk.reached, other)
			queue = append(queue, other)
		}
	}

	// Every import that lands on a reached module from inside the closure --
	// the origin included -- is how it was reached, and all of them are kept.
	// Two imports of one module under two aliases are two imports.
	for _, edge := range edges {
		from, to := near(edge), far(edge)
		if _, inside := walk.level[from]; !inside || to == origin {
			continue
		}
		if _, counted := walk.level[to]; counted {
			walk.arriving[to] = append(walk.arriving[to], edge)
		}
	}
	return walk
}
