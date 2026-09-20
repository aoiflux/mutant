package builtin

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	libtable "github.com/aoiflux/libtable"
	"github.com/aoiflux/libtable/partition"

	"mutant/object"
)

// tableWarning is one of libtable's non-fatal findings -- an entry past the end
// of the device, overlapping extents, a truncated entry count, a hybrid MBR, a
// secondary GPT that is missing or disagrees. The library parses such media and
// reports the anomaly rather than failing, so the evidence is surfaced instead
// of dropped.
//
// Code is the library's own stable identifier: "overlap", "hybrid_mbr",
// "backup_mismatch". It is what a script branches on. Message is prose for a
// report and is reworded between releases, so a script that matches on the
// prose is a script that stops noticing the anomaly at the next upgrade,
// without saying that it has.
type tableWarning struct {
	Code    string
	Message string
	LBA     uint64
}

type tableInfo struct {
	TableType      string
	BlockSize      uint32
	Offset         uint64
	IsBackup       bool
	PartitionCount int
	// GPTBackup is the state of the secondary GPT relative to the primary:
	// "ok", "missing", "mismatch", or "unknown" when the question was not asked
	// -- the table is not GPT, or was itself recovered from the backup. Both
	// copies are written together, so "mismatch" means one was rewritten
	// without the other: an interrupted resize, or tampering.
	GPTBackup string
	// Warnings carries libtable's "merely suspicious" findings. They are
	// structured rather than rendered because the code is the part a script may
	// rely on.
	Warnings []tableWarning
	// Candidates lists every scheme that parsed cleanly, in preference order.
	// More than one entry means the media was ambiguous and the parse options
	// picked a winner.
	Candidates []string
}

type tablePartition struct {
	Index       int
	StartLBA    uint64
	LengthLBA   uint64
	EndLBA      uint64
	TypeCode    uint64
	TypeName    string
	Name        string
	Flags       uint8
	TableNumber int32
	SlotNumber  int32
	Attributes  uint64
	GUIDType    string
	GUIDUnique  string
	// StartByte and LengthByte are absolute byte offsets into the image.
	// Partition LBAs are relative to the table's own offset, so a script that
	// multiplies StartLBA by BlockSize mislocates every partition on a table
	// parsed at a non-zero offset -- a decoded container, or a nested table.
	StartByte  uint64
	LengthByte uint64
	// Allocated, Unallocated, Meta and Structure decode Flags. The listing maps
	// the whole device, not just its volumes, so most rows are not something to
	// open as a filesystem: a script that walks the listing handing each entry
	// to fat_open is handing it GPT headers and interior gaps.
	Allocated   bool
	Unallocated bool
	Meta        bool
	Structure   bool
	// OccupiesSpace reports whether the row lays claim to the sectors it covers
	// and so takes part in tiling the device exactly once. Meta rows without
	// Structure are containers -- an MBR extended entry, a Sun whole-disk backup
	// slice -- which span the extents they hold and overlap them by design, so
	// summing them double-counts.
	OccupiesSpace bool
	// NestedType names the subordinate scheme found inside this partition, or
	// is empty when there is none. table_nested returns its contents.
	NestedType string
}

// tableNestedTable is a partition scheme found inside a partition of another --
// a BSD disklabel in an MBR 0xA5 slice being the one that occurs in practice.
// Its partitions carry absolute byte offsets like any other, computed by the
// inner table, which is the only thing that knows which addressing convention
// the label was written with.
type tableNestedTable struct {
	TableType  string
	BlockSize  uint32
	Offset     uint64
	Warnings   []tableWarning
	Partitions []tablePartition
}

// tableParseOptions carries the decisions a script makes before a table is
// parsed. Each is an evidentiary decision about ambiguous or hybrid media, and
// each has its own builtin rather than a key in an options hash.
type tableParseOptions struct {
	// Scheme forces one scheme instead of autodetecting. Empty autodetects.
	Scheme string
	// RefuseAmbiguous returns an error naming every candidate instead of
	// resolving by preference order.
	RefuseAmbiguous bool
	// All returns one table per scheme that parsed, rather than one winner.
	All bool
}

type tableSession interface {
	Info() tableInfo
	ListPartitions() ([]tablePartition, error)
	PartitionInfo(index int) (tablePartition, error)
	NestedTable(index int) (tableNestedTable, error)
	Close() error
}

type tableBackend interface {
	Open(imagePath string, opts tableParseOptions) ([]tableSession, error)
}

type realTableBackend struct{}

type realTableSession struct {
	file  *os.File
	table *libtable.Table
}

type tableHandleState struct {
	ImagePath string
	Session   tableSession
}

var tableStore = struct {
	sync.RWMutex
	nextID  int64
	backend tableBackend
	handles map[string]tableHandleState
}{
	backend: realTableBackend{},
	handles: map[string]tableHandleState{},
}

func TableOpen(args ...object.Object) object.Object {
	return tableOpenOne(BuiltinNameTableOpen, args, tableParseOptions{})
}

// TableOpenStrict refuses media on which more than one scheme parses, instead
// of resolving it by preference order.
func TableOpenStrict(args ...object.Object) object.Object {
	return tableOpenOne(BuiltinNameTableOpenStrict, args, tableParseOptions{RefuseAmbiguous: true})
}

// TableOpenAs parses the image as one named scheme, which is how an examiner
// records having chosen between candidates rather than accepting a default.
func TableOpenAs(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	schemeObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be STRING, got %s", BuiltinNameTableOpenAs, args[1].Type()))
	}
	scheme, errObj := tableScheme(BuiltinNameTableOpenAs, schemeObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return tableOpenOne(BuiltinNameTableOpenAs, args[:1], tableParseOptions{Scheme: scheme})
}

// TableOpenAll returns a handle per scheme that parsed cleanly. Parse has to
// pick one answer; hybrid media has two, and the entries of the losing scheme
// are unreachable through any other route.
func TableOpenAll(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be STRING, got %s", BuiltinNameTableOpenAll, args[0].Type()))
	}

	tables, errObj := tableOpenSessions(BuiltinNameTableOpenAll, pathObj.Value, tableParseOptions{All: true})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(&object.Array{Elements: tables}, nil)
}

// TableDetect names every scheme that parses cleanly and issues no handle. It
// is the question asked before the decision: a script that only wants to know
// what an image is has nothing to release afterwards.
func TableDetect(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be STRING, got %s", BuiltinNameTableDetect, args[0].Type()))
	}

	tableStore.RLock()
	backend := tableStore.backend
	tableStore.RUnlock()

	sessions, err := backend.Open(pathObj.Value, tableParseOptions{All: true})
	if err != nil {
		return resultAndError(nil, tableOpenError(BuiltinNameTableDetect, err))
	}
	if len(sessions) == 0 {
		return resultAndError(nil, newError("%s: no partition scheme parsed cleanly", BuiltinNameTableDetect))
	}

	candidates := make([]string, 0, len(sessions))
	for _, session := range sessions {
		candidates = append(candidates, session.Info().TableType)
		_ = session.Close()
	}

	// Detection reads the evidence, so the case records it, with a handle that
	// names what read it and is never issued to the script.
	detectID := atomic.AddInt64(&tableStore.nextID, 1)
	custodyRecordOpen(BuiltinNameTableDetect, fmt.Sprintf("table-detect-%d", detectID), pathObj.Value)

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":            stringObj(pathObj.Value),
		"table_type":      stringObj(candidates[0]),
		"candidates":      stringArrayObj(candidates),
		"candidate_count": intObj(int64(len(candidates))),
		"ambiguous":       boolObj(len(candidates) > 1),
	}), nil)
}

func TableListPartitions(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveTableHandle(args[0], BuiltinNameTableListPartitions)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	partitions, err := state.Session.ListPartitions()
	if err != nil {
		return resultAndError(nil, newError("table_list_partitions: %s", err.Error()))
	}

	return resultAndError(&object.Array{Elements: makeTablePartitionHashes(partitions)}, nil)
}

func TablePartitionInfo(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveTableHandle(args[0], BuiltinNameTablePartitionInfo)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	index, errObj := tablePartitionIndex(BuiltinNameTablePartitionInfo, args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	partition, err := state.Session.PartitionInfo(index)
	if err != nil {
		return resultAndError(nil, newError("table_partition_info: %s", err.Error()))
	}

	return resultAndError(makeTablePartitionHash(partition), nil)
}

// TableNested returns the partition scheme found inside one partition. A
// missing one is an error rather than an empty listing: an empty listing is
// what a script reads as "this container holds nothing", which is a different
// finding from "nothing was looked for here".
func TableNested(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveTableHandle(args[0], BuiltinNameTableNested)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	index, errObj := tablePartitionIndex(BuiltinNameTableNested, args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	nested, err := state.Session.NestedTable(index)
	if err != nil {
		return resultAndError(nil, newError("table_nested: %s", err.Error()))
	}

	warnings, codes := makeTableWarnings(nested.Warnings)

	return resultAndError(makeHashObject(map[string]object.Object{
		"index":           intObj(int64(index)),
		"table_type":      stringObj(nested.TableType),
		"block_size":      intObj(int64(nested.BlockSize)),
		"table_offset":    intObj(int64(nested.Offset)),
		"partition_count": intObj(int64(len(nested.Partitions))),
		"warnings":        warnings,
		"warning_codes":   codes,
		"partitions":      &object.Array{Elements: makeTablePartitionHashes(nested.Partitions)},
	}), nil)
}

func TableClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	handleObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `table_close` must be STRING handle, got %s", args[0].Type()))
	}

	tableStore.Lock()
	state, exists := tableStore.handles[handleObj.Value]
	if exists {
		delete(tableStore.handles, handleObj.Value)
	}
	tableStore.Unlock()

	if !exists {
		return resultAndError(nil, newError("table_close: unknown table handle: %s", handleObj.Value))
	}

	custodyRecordTouch(BuiltinNameTableClose, handleObj.Value)

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("table_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

// tableOpenOne is the shape every single-handle opener shares: one path
// argument, one parse, one handle.
func tableOpenOne(op string, args []object.Object, opts tableParseOptions) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be STRING, got %s", op, args[0].Type()))
	}

	tables, errObj := tableOpenSessions(op, pathObj.Value, opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// A single-handle opener asked for one table, and both Parse and a forced
	// scheme return exactly one. Anything further would be a handle no script
	// holds and nothing closes.
	for _, extra := range tables[1:] {
		tableReleaseHash(extra)
	}

	return resultAndError(tables[0], nil)
}

// tableOpenSessions runs one parse and registers a handle for every table it
// produced.
func tableOpenSessions(op, imagePath string, opts tableParseOptions) ([]object.Object, *object.Error) {
	tableStore.RLock()
	backend := tableStore.backend
	tableStore.RUnlock()

	sessions, err := backend.Open(imagePath, opts)
	if err != nil {
		return nil, tableOpenError(op, err)
	}
	if len(sessions) == 0 {
		return nil, newError("%s: no partition scheme parsed cleanly", op)
	}

	out := make([]object.Object, 0, len(sessions))
	for _, session := range sessions {
		handleID := atomic.AddInt64(&tableStore.nextID, 1)
		handle := fmt.Sprintf("table-handle-%d", handleID)

		tableStore.Lock()
		tableStore.handles[handle] = tableHandleState{ImagePath: imagePath, Session: session}
		tableStore.Unlock()

		custodyRecordOpen(op, handle, imagePath)

		out = append(out, makeTableInfoHash(handle, imagePath, session.Info()))
	}

	return out, nil
}

// tableOpenError names the two builtins that resolve ambiguous media, since the
// library's own message says only that it refused.
func tableOpenError(op string, err error) *object.Error {
	var ambiguous *partition.AmbiguityError
	if errors.As(err, &ambiguous) {
		return newError("%s: %s; choose one with `table_open_as(image, scheme)`, or keep every scheme with `table_open_all(image)`",
			op, err.Error())
	}
	return newError("%s: %s", op, err.Error())
}

// tableReleaseHash closes and forgets a handle that was registered but is not
// being returned.
func tableReleaseHash(info object.Object) {
	hash, ok := info.(*object.Hash)
	if !ok {
		return
	}
	handle, ok := hashStringValue(hash, "handle")
	if !ok {
		return
	}

	tableStore.Lock()
	state, exists := tableStore.handles[handle]
	if exists {
		delete(tableStore.handles, handle)
	}
	tableStore.Unlock()

	if exists {
		_ = state.Session.Close()
	}
}

// tableScheme normalises a requested partition scheme. Forcing a scheme is how
// an examiner records a decision about ambiguous media, so a name the parser
// does not have is refused here, by the builtin that was called, rather than
// reaching the library to fail in its own words.
func tableScheme(op, scheme string) (string, *object.Error) {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "mbr":
		return string(libtable.TypeMBR), nil
	case "gpt":
		return string(libtable.TypeGPT), nil
	case "bsd":
		return string(libtable.TypeBSD), nil
	case "sun":
		return string(libtable.TypeSun), nil
	case "mac":
		return string(libtable.TypeMac), nil
	}
	return "", newError("%s: unsupported partition scheme `%s`; expected one of mbr, gpt, bsd, sun, mac", op, scheme)
}

func tablePartitionIndex(op string, arg object.Object) (int, *object.Error) {
	indexObj, ok := arg.(*object.Integer)
	if !ok {
		return 0, newError("argument 2 to `%s` must be INTEGER, got %s", op, arg.Type())
	}
	if indexObj.Value < 0 {
		return 0, newError("%s: index must be >= 0", op)
	}
	return int(indexObj.Value), nil
}

func makeTableInfoHash(handle, imagePath string, info tableInfo) object.Object {
	warnings, codes := makeTableWarnings(info.Warnings)

	return makeHashObject(map[string]object.Object{
		"handle":          stringObj(handle),
		"path":            stringObj(imagePath),
		"status":          stringObj("ok"),
		"table_type":      stringObj(info.TableType),
		"block_size":      intObj(int64(info.BlockSize)),
		"table_offset":    intObj(int64(info.Offset)),
		"is_backup":       boolObj(info.IsBackup),
		"partition_count": intObj(int64(info.PartitionCount)),
		"gpt_backup":      stringObj(info.GPTBackup),
		"warnings":        warnings,
		"warning_codes":   codes,
		"candidates":      stringArrayObj(info.Candidates),
		"ambiguous":       boolObj(len(info.Candidates) > 1),
	})
}

// makeTableWarnings returns the findings and, beside them, the set of codes
// they carry. The set is what answers "did this happen at all" without a loop,
// and a loop over an array of hashes is not the shape a one-line check wants.
func makeTableWarnings(warnings []tableWarning) (object.Object, object.Object) {
	elements := make([]object.Object, 0, len(warnings))
	codes := make([]string, 0, len(warnings))
	seen := make(map[string]bool, len(warnings))

	for _, warning := range warnings {
		elements = append(elements, makeHashObject(map[string]object.Object{
			"code":    stringObj(warning.Code),
			"message": stringObj(warning.Message),
			"lba":     intObj(int64(warning.LBA)),
		}))
		if !seen[warning.Code] {
			seen[warning.Code] = true
			codes = append(codes, warning.Code)
		}
	}

	return &object.Array{Elements: elements}, stringArrayObj(codes)
}

func makeTablePartitionHashes(partitions []tablePartition) []object.Object {
	elements := make([]object.Object, 0, len(partitions))
	for _, part := range partitions {
		elements = append(elements, makeTablePartitionHash(part))
	}
	return elements
}

func makeTablePartitionHash(part tablePartition) object.Object {
	return makeHashObject(map[string]object.Object{
		"index":      intObj(int64(part.Index)),
		"start_lba":  intObj(int64(part.StartLBA)),
		"length_lba": intObj(int64(part.LengthLBA)),
		"end_lba":    intObj(int64(part.EndLBA)),
		// Absolute byte offsets into the image. Prefer these over start_lba *
		// block_size, which is wrong for any table parsed at a non-zero offset.
		"start_byte":  intObj(int64(part.StartByte)),
		"length_byte": intObj(int64(part.LengthByte)),
		// type_code and attributes are uint64 bitfields whose high bit (e.g. the
		// GPT "required partition" attribute, bit 63) overflows a signed integer,
		// so they are surfaced as lossless hex strings.
		"type_code":    stringObj(fmt.Sprintf("0x%016x", part.TypeCode)),
		"type_name":    stringObj(part.TypeName),
		"name":         stringObj(part.Name),
		"flags":        intObj(int64(part.Flags)),
		"table_number": intObj(int64(part.TableNumber)),
		"slot_number":  intObj(int64(part.SlotNumber)),
		"attributes":   stringObj(fmt.Sprintf("0x%016x", part.Attributes)),
		"guid_type":    stringObj(part.GUIDType),
		"guid_unique":  stringObj(part.GUIDUnique),
		// The decoded flags. allocated is the only one of them that names a
		// volume; the rest map the parts of the device that are not one.
		"allocated":      boolObj(part.Allocated),
		"unallocated":    boolObj(part.Unallocated),
		"meta":           boolObj(part.Meta),
		"structure":      boolObj(part.Structure),
		"occupies_space": boolObj(part.OccupiesSpace),
		"has_nested":     boolObj(part.NestedType != ""),
		"nested_type":    stringObj(part.NestedType),
	})
}

func resolveTableHandle(arg object.Object, opName string) (tableHandleState, *object.Error) {
	handleObj, ok := arg.(*object.String)
	if !ok {
		return tableHandleState{}, newError("argument 1 to `%s` must be STRING handle, got %s", opName, arg.Type())
	}

	tableStore.RLock()
	state, ok := tableStore.handles[handleObj.Value]
	tableStore.RUnlock()
	if !ok {
		return tableHandleState{}, newError("%s: unknown table handle: %s", opName, handleObj.Value)
	}

	custodyRecordTouch(opName, handleObj.Value)

	return state, nil
}

func (realTableBackend) Open(imagePath string, opts tableParseOptions) ([]tableSession, error) {
	tables, err := tableParse(imagePath, tableLibOptions(opts), opts.All)
	if err != nil {
		return nil, err
	}

	// Each handle owns its own descriptor. One ParseAll can yield several
	// tables, and a script closing the GPT handle must not pull the file out
	// from under the MBR one.
	sessions := make([]tableSession, 0, len(tables))
	for _, tbl := range tables {
		file, openErr := os.Open(imagePath)
		if openErr != nil {
			for _, open := range sessions {
				_ = open.Close()
			}
			return nil, openErr
		}
		sessions = append(sessions, &realTableSession{file: file, table: tbl})
	}

	return sessions, nil
}

// tableParse reads the table, or every table, and closes the reader it used. A
// parsed Table keeps no reference to the reader it came from -- ByteOffset and
// ByteSize are arithmetic over fields already copied out -- so the descriptor a
// handle holds is a claim on the evidence file, not a dependency of the parse.
func tableParse(imagePath string, opts libtable.Options, all bool) ([]*libtable.Table, error) {
	file, err := os.Open(imagePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	size := uint64(stat.Size())

	if all {
		return libtable.ParseAll(file, size, opts)
	}

	tbl, err := libtable.Parse(file, size, opts)
	if err != nil {
		return nil, err
	}
	return []*libtable.Table{tbl}, nil
}

func tableLibOptions(opts tableParseOptions) libtable.Options {
	out := libtable.Options{
		// Nesting is looked for on every parse. A BSD disklabel inside an MBR
		// 0xA5 slice is the partition table an examiner is actually after, and
		// finding it costs one sector read per container slice. It adds nothing
		// to the listing -- it is recorded on the slice that holds it -- so the
		// listing is the same listing either way.
		DetectNested: true,
	}
	if opts.RefuseAmbiguous {
		out.Ambiguity = libtable.AmbiguityErrorOut
	}
	if opts.Scheme != "" {
		out.Type = libtable.TableType(opts.Scheme)
	}
	return out
}

func (s *realTableSession) Info() tableInfo {
	info := tableInfo{
		TableType:      string(s.table.Type),
		BlockSize:      s.table.BlockSize,
		Offset:         s.table.Offset,
		IsBackup:       s.table.IsBackup,
		PartitionCount: len(s.table.Partitions),
		GPTBackup:      s.table.GPTBackup.String(),
		Warnings:       tableWarningsFrom(s.table.Warnings),
	}
	for _, c := range s.table.Candidates {
		info.Candidates = append(info.Candidates, string(c))
	}
	return info
}

func (s *realTableSession) ListPartitions() ([]tablePartition, error) {
	partitions := make([]tablePartition, 0, len(s.table.Partitions))
	for _, p := range s.table.Partitions {
		partitions = append(partitions, tablePartitionFrom(s.table, p))
	}

	sort.Slice(partitions, func(i, j int) bool {
		return partitions[i].Index < partitions[j].Index
	})

	return partitions, nil
}

func (s *realTableSession) PartitionInfo(index int) (tablePartition, error) {
	// Scan the library's own slice: rebuilding and re-sorting the full listing
	// per lookup made a loop over k partitions O(k·n log n).
	for _, p := range s.table.Partitions {
		if p.Index == index {
			return tablePartitionFrom(s.table, p), nil
		}
	}
	return tablePartition{}, fmt.Errorf("partition index %d not found", index)
}

func (s *realTableSession) NestedTable(index int) (tableNestedTable, error) {
	for _, p := range s.table.Partitions {
		if p.Index != index {
			continue
		}
		if p.Nested == nil {
			return tableNestedTable{}, fmt.Errorf("partition %d holds no nested partition scheme", index)
		}

		inner := p.Nested
		nested := tableNestedTable{
			TableType: string(inner.Type),
			BlockSize: inner.BlockSize,
			Offset:    inner.Offset,
			Warnings:  tableWarningsFrom(inner.Warnings),
		}
		for _, ip := range inner.Partitions {
			nested.Partitions = append(nested.Partitions, tablePartitionFrom(inner, ip))
		}
		sort.Slice(nested.Partitions, func(i, j int) bool {
			return nested.Partitions[i].Index < nested.Partitions[j].Index
		})

		return nested, nil
	}

	return tableNestedTable{}, fmt.Errorf("partition index %d not found", index)
}

func (s *realTableSession) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// tablePartitionFrom converts one library partition, taking the byte offsets
// from the table it came out of rather than deriving them, since only the table
// knows its own base offset. A nested table's offset is the byte offset of the
// slice that holds it, and for a disklabel written with disk-absolute addresses
// the library leaves that base where the outer table put it -- so this is
// correct under both conventions and arithmetic here would be correct under
// neither.
func tablePartitionFrom(t *libtable.Table, p partition.Partition) tablePartition {
	nestedType := ""
	if p.Nested != nil {
		nestedType = string(p.Nested.Type)
	}

	return tablePartition{
		Index:         p.Index,
		StartLBA:      p.StartLBA,
		LengthLBA:     p.LengthLBA,
		EndLBA:        endLBA(p.StartLBA, p.LengthLBA),
		TypeCode:      p.TypeCode,
		TypeName:      p.TypeName,
		Name:          p.Name,
		Flags:         uint8(p.Flags),
		TableNumber:   p.TableNumber,
		SlotNumber:    p.SlotNumber,
		Attributes:    p.Attributes,
		GUIDType:      p.GUIDType,
		GUIDUnique:    p.GUIDUnique,
		StartByte:     t.ByteOffset(p),
		LengthByte:    t.ByteSize(p),
		Allocated:     p.Flags&partition.PartFlagAlloc != 0,
		Unallocated:   p.Flags&partition.PartFlagUnalloc != 0,
		Meta:          p.Flags&partition.PartFlagMeta != 0,
		Structure:     p.Flags&partition.PartFlagStruct != 0,
		OccupiesSpace: p.Flags&(partition.PartFlagAlloc|partition.PartFlagUnalloc|partition.PartFlagStruct) != 0,
		NestedType:    nestedType,
	}
}

func tableWarningsFrom(warnings []partition.Warning) []tableWarning {
	out := make([]tableWarning, 0, len(warnings))
	for _, w := range warnings {
		out = append(out, tableWarning{Code: string(w.Code), Message: w.Msg, LBA: w.LBA})
	}
	return out
}

// endLBA is the inclusive last LBA of a partition. A zero-length entry has no
// last block, so it reports its start — which is indistinguishable from a
// one-sector partition; use length_lba or length_byte to tell them apart.
func endLBA(start uint64, length uint64) uint64 {
	if length == 0 {
		return start
	}
	return start + length - 1
}
