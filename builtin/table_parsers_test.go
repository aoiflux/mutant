package builtin

import (
	"errors"
	"testing"

	"mutant/object"
)

type fakeTableBackend struct {
	session tableSession
	err     error
}

func (f fakeTableBackend) Open(imagePath string) (tableSession, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.session, nil
}

type fakeTableSession struct {
	info       tableInfo
	partitions []tablePartition
	closeErr   error
	closed     bool
}

func (f *fakeTableSession) Info() tableInfo {
	return f.info
}

func (f *fakeTableSession) ListPartitions() ([]tablePartition, error) {
	out := make([]tablePartition, 0, len(f.partitions))
	out = append(out, f.partitions...)
	return out, nil
}

func (f *fakeTableSession) PartitionInfo(index int) (tablePartition, error) {
	for _, part := range f.partitions {
		if part.Index == index {
			return part, nil
		}
	}
	return tablePartition{}, errors.New("partition not found")
}

func (f *fakeTableSession) Close() error {
	f.closed = true
	return f.closeErr
}

func installFakeTableBackend(t *testing.T, backend tableBackend) {
	t.Helper()

	tableStore.Lock()
	prevBackend := tableStore.backend
	prevHandles := tableStore.handles
	prevNextID := tableStore.nextID
	tableStore.backend = backend
	tableStore.handles = map[string]tableHandleState{}
	tableStore.nextID = 0
	tableStore.Unlock()

	t.Cleanup(func() {
		tableStore.Lock()
		for _, state := range tableStore.handles {
			_ = state.Session.Close()
		}
		tableStore.backend = prevBackend
		tableStore.handles = prevHandles
		tableStore.nextID = prevNextID
		tableStore.Unlock()
	})
}

func TestTableBuiltinFlowWithSyntheticDataset(t *testing.T) {
	session := &fakeTableSession{
		info: tableInfo{
			TableType:      "gpt",
			BlockSize:      512,
			Offset:         0,
			IsBackup:       false,
			PartitionCount: 2,
		},
		partitions: []tablePartition{
			{Index: 1, StartLBA: 2048, LengthLBA: 409600, EndLBA: 411647, TypeName: "EFI System", Name: "EFI", TableNumber: 0, SlotNumber: 1},
			{Index: 2, StartLBA: 411648, LengthLBA: 1024000, EndLBA: 1435647, TypeName: "Linux filesystem", Name: "rootfs", TableNumber: 0, SlotNumber: 2},
		},
	}
	installFakeTableBackend(t, fakeTableBackend{session: session})

	openPayload, errObj := unwrapPair(t, TableOpen(stringObj("synthetic.img")))
	if errObj != nil {
		t.Fatalf("table_open returned error: %s", errObj.Inspect())
	}
	openHash, ok := openPayload.(*object.Hash)
	if !ok {
		t.Fatalf("table_open payload is not HASH. got=%T", openPayload)
	}

	handleObj := mustHashStringValue(t, openHash, "handle")
	if handleObj == "" {
		t.Fatal("expected non-empty table handle")
	}

	listPayload, errObj := unwrapPair(t, TableListPartitions(stringObj(handleObj)))
	if errObj != nil {
		t.Fatalf("table_list_partitions returned error: %s", errObj.Inspect())
	}
	listArr, ok := listPayload.(*object.Array)
	if !ok {
		t.Fatalf("table_list_partitions payload is not ARRAY. got=%T", listPayload)
	}
	if len(listArr.Elements) != 2 {
		t.Fatalf("partition count mismatch. got=%d, want=2", len(listArr.Elements))
	}

	infoPayload, errObj := unwrapPair(t, TablePartitionInfo(stringObj(handleObj), intObj(2)))
	if errObj != nil {
		t.Fatalf("table_partition_info returned error: %s", errObj.Inspect())
	}
	partHash, ok := infoPayload.(*object.Hash)
	if !ok {
		t.Fatalf("table_partition_info payload is not HASH. got=%T", infoPayload)
	}
	if got := mustHashStringValue(t, partHash, "name"); got != "rootfs" {
		t.Fatalf("partition name mismatch. got=%q, want=%q", got, "rootfs")
	}

	closePayload, errObj := unwrapPair(t, TableClose(stringObj(handleObj)))
	if errObj != nil {
		t.Fatalf("table_close returned error: %s", errObj.Inspect())
	}
	closeHash, ok := closePayload.(*object.Hash)
	if !ok {
		t.Fatalf("table_close payload is not HASH. got=%T", closePayload)
	}
	if !mustHashBoolValue(t, closeHash, "closed") {
		t.Fatal("expected closed=true")
	}
	if !session.closed {
		t.Fatal("expected session Close to be called")
	}

	_, errObj = unwrapPair(t, TableListPartitions(stringObj(handleObj)))
	if errObj == nil {
		t.Fatal("expected unknown table handle after close")
	}
}

func TestTableBuiltinArgumentAndHandleErrors(t *testing.T) {
	installFakeTableBackend(t, fakeTableBackend{err: errors.New("open failed")})

	if _, errObj := unwrapPair(t, TableOpen()); errObj == nil {
		t.Fatal("expected arity error for table_open")
	}
	if _, errObj := unwrapPair(t, TableOpen(intObj(1))); errObj == nil {
		t.Fatal("expected type error for table_open path")
	}
	if _, errObj := unwrapPair(t, TableOpen(stringObj("bad.img"))); errObj == nil {
		t.Fatal("expected backend open error")
	}

	if _, errObj := unwrapPair(t, TableListPartitions(stringObj("missing"))); errObj == nil {
		t.Fatal("expected unknown handle error for table_list_partitions")
	}
	if _, errObj := unwrapPair(t, TablePartitionInfo(stringObj("missing"), intObj(1))); errObj == nil {
		t.Fatal("expected unknown handle error for table_partition_info")
	}
	if _, errObj := unwrapPair(t, TablePartitionInfo(stringObj("missing"), stringObj("1"))); errObj == nil {
		t.Fatal("expected type error for partition index")
	}
	if _, errObj := unwrapPair(t, TableClose(stringObj("missing"))); errObj == nil {
		t.Fatal("expected unknown handle error for table_close")
	}
}
