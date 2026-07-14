package builtin

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"

	libtable "github.com/aoiflux/libtable"

	"mutant/object"
)

type tableInfo struct {
	TableType      string
	BlockSize      uint32
	Offset         uint64
	IsBackup       bool
	PartitionCount int
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
	TableNumber int8
	SlotNumber  int8
	Attributes  uint64
	GUIDType    string
	GUIDUnique  string
}

type tableSession interface {
	Info() tableInfo
	ListPartitions() ([]tablePartition, error)
	PartitionInfo(index int) (tablePartition, error)
	Close() error
}

type tableBackend interface {
	Open(imagePath string) (tableSession, error)
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
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `table_open` must be STRING, got %s", args[0].Type()))
	}

	tableStore.RLock()
	backend := tableStore.backend
	tableStore.RUnlock()

	session, err := backend.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("table_open: %s", err.Error()))
	}

	handleID := atomic.AddInt64(&tableStore.nextID, 1)
	handle := fmt.Sprintf("table-handle-%d", handleID)
	info := session.Info()

	tableStore.Lock()
	tableStore.handles[handle] = tableHandleState{ImagePath: pathObj.Value, Session: session}
	tableStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle":          stringObj(handle),
		"path":            stringObj(pathObj.Value),
		"status":          stringObj("ok"),
		"table_type":      stringObj(info.TableType),
		"block_size":      intObj(int64(info.BlockSize)),
		"table_offset":    intObj(int64(info.Offset)),
		"is_backup":       boolObj(info.IsBackup),
		"partition_count": intObj(int64(info.PartitionCount)),
	}), nil)
}

func TableListPartitions(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	state, errObj := resolveTableHandle(args[0], "table_list_partitions")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	partitions, err := state.Session.ListPartitions()
	if err != nil {
		return resultAndError(nil, newError("table_list_partitions: %s", err.Error()))
	}

	elements := make([]object.Object, 0, len(partitions))
	for _, part := range partitions {
		elements = append(elements, makeTablePartitionHash(part))
	}

	return resultAndError(&object.Array{Elements: elements}, nil)
}

func TablePartitionInfo(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	state, errObj := resolveTableHandle(args[0], "table_partition_info")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	indexObj, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `table_partition_info` must be INTEGER, got %s", args[1].Type()))
	}
	if indexObj.Value < 0 {
		return resultAndError(nil, newError("table_partition_info: index must be >= 0"))
	}

	partition, err := state.Session.PartitionInfo(int(indexObj.Value))
	if err != nil {
		return resultAndError(nil, newError("table_partition_info: %s", err.Error()))
	}

	return resultAndError(makeTablePartitionHash(partition), nil)
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

	if err := state.Session.Close(); err != nil {
		return resultAndError(nil, newError("table_close: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handleObj.Value),
		"closed": boolObj(true),
		"status": stringObj("ok"),
	}), nil)
}

func makeTablePartitionHash(part tablePartition) object.Object {
	return makeHashObject(map[string]object.Object{
		"index":        intObj(int64(part.Index)),
		"start_lba":    intObj(int64(part.StartLBA)),
		"length_lba":   intObj(int64(part.LengthLBA)),
		"end_lba":      intObj(int64(part.EndLBA)),
		"type_code":    intObj(int64(part.TypeCode)),
		"type_name":    stringObj(part.TypeName),
		"name":         stringObj(part.Name),
		"flags":        intObj(int64(part.Flags)),
		"table_number": intObj(int64(part.TableNumber)),
		"slot_number":  intObj(int64(part.SlotNumber)),
		"attributes":   intObj(int64(part.Attributes)),
		"guid_type":    stringObj(part.GUIDType),
		"guid_unique":  stringObj(part.GUIDUnique),
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

	return state, nil
}

func (realTableBackend) Open(imagePath string) (tableSession, error) {
	f, err := os.Open(imagePath)
	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	tbl, err := libtable.Parse(f, uint64(stat.Size()), libtable.Options{})
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	return &realTableSession{file: f, table: tbl}, nil
}

func (s *realTableSession) Info() tableInfo {
	return tableInfo{
		TableType:      string(s.table.Type),
		BlockSize:      s.table.BlockSize,
		Offset:         s.table.Offset,
		IsBackup:       s.table.IsBackup,
		PartitionCount: len(s.table.Partitions),
	}
}

func (s *realTableSession) ListPartitions() ([]tablePartition, error) {
	partitions := make([]tablePartition, 0, len(s.table.Partitions))
	for _, p := range s.table.Partitions {
		partitions = append(partitions, tablePartition{
			Index:       p.Index,
			StartLBA:    p.StartLBA,
			LengthLBA:   p.LengthLBA,
			EndLBA:      endLBA(p.StartLBA, p.LengthLBA),
			TypeCode:    p.TypeCode,
			TypeName:    p.TypeName,
			Name:        p.Name,
			Flags:       uint8(p.Flags),
			TableNumber: p.TableNumber,
			SlotNumber:  p.SlotNumber,
			Attributes:  p.Attributes,
			GUIDType:    p.GUIDType,
			GUIDUnique:  p.GUIDUnique,
		})
	}

	sort.Slice(partitions, func(i, j int) bool {
		return partitions[i].Index < partitions[j].Index
	})

	return partitions, nil
}

func (s *realTableSession) PartitionInfo(index int) (tablePartition, error) {
	parts, err := s.ListPartitions()
	if err != nil {
		return tablePartition{}, err
	}
	for _, part := range parts {
		if part.Index == index {
			return part, nil
		}
	}
	return tablePartition{}, fmt.Errorf("partition index %d not found", index)
}

func (s *realTableSession) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func endLBA(start uint64, length uint64) uint64 {
	if length == 0 {
		return start
	}
	return start + length - 1
}
