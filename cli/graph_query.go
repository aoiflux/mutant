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
// graphene.Open takes an exclusive lock, stamps the calling process's pid into
// graphene.lock on open and again on close, and -- the part that decides this
// -- CREATES a store for any path that does not hold one. A query built on it
// would answer "0 modules, 0 declarations" for a mistyped --store while writing
// two files into whatever directory was actually named.
//
// So the store is identified before it is opened, by its own label table, and
// opened read-only afterwards. OpenReadOnly refuses a missing path and a path
// that is not a directory, admits other readers, and writes nothing into any
// file that carries what the store says.
//
// It does not leave the directory untouched, and saying that it did would be
// the kind of claim this tool exists not to make. OpenReadOnly takes its shared
// lock through graphene.lock and opens that file O_CREATE, so reading a store
// that has no lock file creates a zero-byte one and moves the directory's
// mtime. That is not an exotic shape: graphene's Store.Backup excludes
// graphene.lock by design, so every store recovered through its own supported
// restore path arrives without one and would be modified by its first query.
//
// Hence three ways in, chosen by what is on disk before anything is opened.
//
//   - graphene.lock is present and writable. OpenReadOnly. A writer holding the
//     store is refused here rather than read around.
//
//   - graphene.lock is absent. No lock can be held through a file that does not
//     exist, so the store is opened live, which creates nothing, and the answer
//     says the read was lock-free and why.
//
//   - graphene.lock is present and cannot be opened for writing, because the
//     media or the directory is read-only. OpenReadOnly cannot take its shared
//     lock. The store is opened live and the answer says so -- but only after
//     the lock's own owner record has been read, because a permission error is
//     also what a live writer on read-only media looks like, and that is the
//     one case where a lock-free read would be reading a store mid-change.

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"mutant/sema"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/disk"
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
func QueryQuestions() []QueryQuestion {
	return []QueryQuestion{
		{"summary", "", "What this store holds: the counts, by label.", costIndex},
		{"modules", "", "Every module, what it declares, and what it imports.", costIndex},
		{"where", "<name>", "Every declaration of a name, and where it is.", costIndexThen},
		{"callers", "<name>", "Every recorded use of a name, and where it is used from.", costIndex},
		{"callees", "<name>", "Every name a declaration uses.", costIndex},
		{"outline", "<module>", "The declarations of one module, nested as they are written.", costIndex},
		{"exported", "", "Every declaration another module could name.", costScan},
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

	extras, err := requireSymbolGraph(opts.Store)
	if err != nil {
		return answer, err
	}
	if extras > 0 {
		answer.Warnings = append(answer.Warnings, fmt.Sprintf(
			"this store names %d label(s) this build does not know, so it was written by a "+
				"later version of `mutant graph export`; the questions below only use the labels "+
				"both versions agree on", extras))
	}

	g, lockFree, err := openForReading(opts.Store)
	if err != nil {
		return answer, err
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
// know, which is what a store from a later export looks like.
func requireSymbolGraph(dir string) (int, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, fmt.Errorf("graph query: %s does not exist", dir)
		}
		return 0, fmt.Errorf("graph query: %s: %w", dir, err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("graph query: %s is a file; a graph store is a directory", dir)
	}

	nodes, edges, err := readLabelTable(filepath.Join(dir, "graphene.labels"))
	if err != nil {
		return 0, fmt.Errorf("graph query: %s is not a symbol graph: %w", dir, err)
	}

	// Both tables are walked in label order rather than in map order. A store
	// that disagrees about two labels disagrees about two labels whichever is
	// named first, but a refusal an examiner might quote should be the same
	// sentence every time it is produced, and ranging a Go map made it a coin
	// toss between them.
	wantNodes, wantEdges := labelNames()
	for _, label := range sortedLabels(wantNodes) {
		name := wantNodes[store.NodeType(label)]
		got, named := nodes[label]
		if !named {
			return 0, fmt.Errorf("graph query: %s is not a symbol graph: its labels do not name %s", dir, name)
		}
		if got != name {
			return 0, fmt.Errorf("graph query: %s is not a symbol graph: it calls label %d %q, "+
				"where this program calls it %q", dir, label, got, name)
		}
	}
	for _, label := range sortedLabels(wantEdges) {
		name := wantEdges[store.EdgeType(label)]
		got, named := edges[label]
		if !named {
			return 0, fmt.Errorf("graph query: %s is not a symbol graph: its labels do not name %s", dir, name)
		}
		if got != name {
			return 0, fmt.Errorf("graph query: %s is not a symbol graph: it calls edge label %d %q, "+
				"where this program calls it %q", dir, label, got, name)
		}
	}
	return (len(nodes) - len(wantNodes)) + (len(edges) - len(wantEdges)), nil
}

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

// readLabelTable parses graphene.labels.
//
// graphene's own parser is unexported, and reimplementing it is the point
// rather than a workaround: this one is stricter where the engine is lenient,
// because the engine is deciding what to register and this is deciding whether
// to believe a directory at all. A table truncated inside its last name parses
// as a shorter name there and is accepted; here a file whose last byte is not a
// newline is torn, because the writer always ends with one.
func readLabelTable(path string) (map[uint16]string, map[uint16]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, errors.New("it has no graphene.labels, so nothing says what its numbers mean")
		}
		return nil, nil, err
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("its graphene.labels is empty")
	}
	if raw[len(raw)-1] != '\n' {
		return nil, nil, errors.New("its graphene.labels does not end in a newline, so it is torn")
	}

	nodes := make(map[uint16]string)
	edges := make(map[uint16]string)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	if !scanner.Scan() {
		return nil, nil, errors.New("its graphene.labels is empty")
	}
	if header := scanner.Text(); header != "graphene-labels v1" {
		return nil, nil, fmt.Errorf("its graphene.labels begins %q, not %q",
			header, "graphene-labels v1")
	}

	for line := 2; scanner.Scan(); line++ {
		text := scanner.Text()
		if text == "" {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) != 3 {
			return nil, nil, fmt.Errorf("graphene.labels line %d: want three tab-separated fields, got %d",
				line, len(fields))
		}
		value, convErr := strconv.ParseUint(fields[1], 10, 16)
		if convErr != nil {
			return nil, nil, fmt.Errorf("graphene.labels line %d: %q is not a label number", line, fields[1])
		}
		// Last-wins is what the engine does with a repeated number, silently. A
		// table that names one number twice has drifted from whatever wrote it,
		// and that is enough to stop trusting the rest of it.
		switch fields[0] {
		case "node":
			if _, twice := nodes[uint16(value)]; twice {
				return nil, nil, fmt.Errorf("graphene.labels names node label %d twice", value)
			}
			nodes[uint16(value)] = fields[2]
		case "edge":
			if _, twice := edges[uint16(value)]; twice {
				return nil, nil, fmt.Errorf("graphene.labels names edge label %d twice", value)
			}
			edges[uint16(value)] = fields[2]
		default:
			return nil, nil, fmt.Errorf("graphene.labels line %d: unknown kind %q", line, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return nodes, edges, nil
}

// openForReading opens the store without changing what it says, and reports
// why, when it could not take a lock. See the file header.
//
// The empty string means the ordinary locked read. Anything else is the reason
// the read was lock-free, and it is carried to the answer verbatim rather than
// reduced to a boolean, because the two reasons are not equally comfortable and
// a reader is entitled to know which one they got.
func openForReading(dir string) (*graphene.Graph, string, error) {
	// A store with no lock file cannot be held by anybody, and OpenReadOnly
	// would create one. Open live: it takes no lock and creates nothing.
	if _, err := os.Stat(filepath.Join(dir, "graphene.lock")); errors.Is(err, fs.ErrNotExist) {
		live, liveErr := graphene.OpenLive(dir)
		if liveErr != nil {
			return nil, "", fmt.Errorf("graph query: %w", liveErr)
		}
		return live, "this store has no graphene.lock, so it was read without taking one rather " +
			"than have one created for it. graphene's own Backup excludes that file, so a store " +
			"restored from a backup looks exactly like this -- but so does a store somebody " +
			"deleted it from, and the two are not distinguishable from here", nil
	}

	g, err := graphene.OpenReadOnly(dir)
	if err == nil {
		return g, "", nil
	}
	// A writer holding the store is the one case where reading without a lock
	// would be reading a store mid-change. Refuse rather than fall back.
	if errors.Is(err, disk.ErrStoreLocked) {
		return nil, "", fmt.Errorf("graph query: %w", err)
	}
	// Everything else is a candidate for the lock-free read, but only two
	// things make it sound: the failure has to be about permission, and the
	// lock's owner record has to say nobody is holding it. A live writer on
	// read-only media fails with a permission error too, so the first test
	// alone would read a store mid-change and call it write-protected.
	if !errors.Is(err, fs.ErrPermission) {
		return nil, "", fmt.Errorf("graph query: %w", err)
	}
	if owner, readable := readLockOwner(filepath.Join(dir, "graphene.lock")); readable &&
		owner.present && !owner.clean && owner.pid != 0 {
		return nil, "", fmt.Errorf("graph query: %s could not be locked for reading, and its "+
			"graphene.lock records process %d as holding it without having closed it. Reading "+
			"without a lock would read a store that is being written: %w", dir, owner.pid, err)
	}
	live, liveErr := graphene.OpenLive(dir)
	if liveErr != nil {
		// Both attempts failed, and it is the second that decided the outcome:
		// the lock-free read is the one this tool exists to be able to do, so
		// blaming the lock here would name as fatal the exact condition the
		// fallback was written to survive.
		return nil, "", fmt.Errorf("graph query: %s could not be read with a lock (%v) and could "+
			"not be read without one either: %w", dir, err, liveErr)
	}
	return live, "the store is write-protected, so it was read without taking a lock. Its " +
		"graphene.lock records no unclosed writer, so the reading is consistent -- but that is " +
		"an inference from a record the last writer left, not a guarantee from the engine", nil
}

// lockOwner is what graphene's last exclusive holder recorded about itself.
//
// graphene writes a 32-byte record at offset 0 of graphene.lock -- magic
// "GLK1", a version byte, the pid, and a clean flag Close sets before it
// releases -- and keeps every reader of it unexported. Reading it here is the
// same decision readLabelTable already makes for graphene.labels: the engine is
// deciding what to do about the file, and this is deciding whether to believe a
// directory at all, which has to happen before the engine is involved.
//
// It is deliberately read without a lock. The record sits outside the locked
// byte range and is written in one 32-byte WriteAt, so a concurrent reader sees
// the old record or the new one and never a mixture.
type lockOwner struct {
	present bool
	pid     uint64
	clean   bool
}

// readLockOwner returns the record and whether the file could be read at all.
// An unreadable or foreign file yields a zero owner and false, which callers
// must treat as "nothing is known" rather than as "nobody is holding it".
func readLockOwner(path string) (lockOwner, bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < 32 {
		return lockOwner{}, false
	}
	if string(raw[0:4]) != "GLK1" || raw[4] != 1 {
		return lockOwner{}, false
	}
	return lockOwner{
		present: true,
		pid:     binary.LittleEndian.Uint64(raw[8:16]),
		clean:   raw[16] == 1,
	}, true
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

	keys, supported := g.NodePropKeys()
	if !supported {
		return nil
	}
	have := make(map[string]bool, len(keys))
	for _, key := range keys {
		have[key] = true
	}
	need := []string{"key", "name"}
	declarations, err := g.QueryNodeIDs(store.NodeQuery{Types: []store.NodeType{nodeDeclaration}})
	if err != nil {
		return fmt.Errorf("graph query: %w", err)
	}
	if len(declarations) > 0 {
		need = append(need, "id", "kind", "module")
	}
	for _, key := range need {
		if !have[key] {
			return fmt.Errorf("graph query: this store does not index %q, so a lookup by it would "+
				"match nothing and report no error. It was written by a different version of "+
				"`mutant graph export`", key)
		}
	}
	return nil
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
			"Declaration and its kind, so it is counted twice; a USES_TYPE edge is a REFERENCES "+
			"edge carrying a second label, so it is too")
	return nil
}

func orderedNodeLabels() []store.NodeType {
	return []store.NodeType{
		nodeModule, nodeDeclaration, nodeFunction, nodeValue, nodeParam,
		nodeLoopBind, nodeNamespace, nodeStruct, nodeEnum, nodeField, nodeVariant,
	}
}

func orderedEdgeLabels() []store.EdgeType {
	return []store.EdgeType{edgeDeclares, edgeEncloses, edgeReferences, edgeImports, edgeUsesType}
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
			answer.Notes = append(answer.Notes, whereScanned)
			return nil
		}
		answer.Headline = fmt.Sprintf("nothing in this store is called %q", name)
		answer.Notes = append(answer.Notes,
			"a name is matched exactly, as the source spells it. This store was searched for "+
				"other casings too, and there are none",
			whereScanned)
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

// whereScanned is what `where` owes a reader when the index missed. The help
// lists `where` among the questions that can read every record, and an answer
// that did not repeat it would leave the one place a reader is actually looking
// -- the answer in front of them -- silent about what it cost.
const whereScanned = "the index held no declaration under this exact name, so this answer read " +
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
				len(folded), strings.Join(folded, ", ")))
			return nil
		}
		answer.Notes = append(answer.Notes,
			"nothing is declared under this name in any casing either, so the question is about "+
				"a name this store does not hold rather than about one spelled differently")
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

	roots := make([]store.NodeID, 0, len(decls))
	for _, decl := range decls {
		if !enclosed[decl.id] {
			roots = append(roots, decl.id)
		}
	}

	section := AnswerSection{Title: "Declarations", Empty: "  this module declares nothing"}
	sortByPosition(roots, byID)
	for _, root := range roots {
		section.Rows = append(section.Rows, outlineRows(root, byID, children, 1, map[store.NodeID]bool{})...)
	}

	answer.Headline = fmt.Sprintf("%s -- %d declaration(s)", path, len(decls))
	answer.Sections = append(answer.Sections, section)
	answer.Notes = append(answer.Notes,
		"the nesting is lexical: what a declaration encloses is what is written inside it -- a "+
			"function's parameters and locals, a struct's fields, an enum's variants")
	return nil
}

// outlineRows renders one declaration and everything written inside it.
//
// onPath carries the declarations between the root and here, and it is the
// difference between an answer and a hang. The nesting in a store this program
// wrote is a tree, but nothing on the read side can know that: a single
// ENCLOSES edge from a node to itself -- one byte's worth of damage, or a
// future exporter with a different idea of what encloses what -- made this
// recurse without end, and because every frame keeps a row string that grows
// with its own depth, it did so in quadratic memory rather than in a stack
// overflow. Measured on one self-loop: 9,226 MB in 17.9 seconds, still
// climbing. A cycle is reported where it is found and not followed.
func outlineRows(id store.NodeID, byID map[store.NodeID]declProps,
	children map[store.NodeID][]store.NodeID, depth int, onPath map[store.NodeID]bool) []string {

	props := byID[id]
	indent := strings.Repeat("  ", depth)
	if onPath[id] {
		return []string{fmt.Sprintf("%s  %s  (encloses itself -- the nesting in this store is a "+
			"cycle, so it is reported here and not followed)", indent, props.Name)}
	}

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

	onPath[id] = true
	kids := append([]store.NodeID(nil), children[id]...)
	sortByPosition(kids, byID)
	for _, kid := range kids {
		rows = append(rows, outlineRows(kid, byID, children, depth+1, onPath)...)
	}
	delete(onPath, id)
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
