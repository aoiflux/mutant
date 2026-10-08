package builtin

import (
	"testing"

	libntfs "github.com/aoiflux/libntfs"

	"mutant/object"
)

// ntfsLogClient is a client record of transaction 7 at lsn, naming previous
// as the record before it in its transaction.
func ntfsLogClient(lsn, previous uint64, redo uint16) *libntfs.LogRecord {
	return &libntfs.LogRecord{
		LSN:               lsn,
		ClientPreviousLSN: previous,
		RecordType:        libntfs.LogRecordTypeClient,
		TransactionID:     7,
		RedoOperation:     redo,
	}
}

// ntfsLogStraddle is transaction 7 in the order a wrapped $LogFile's pages
// hold it: the walk meets its continuation and its forget record at the front
// of the file, where the log was written round, and its first record, 990, at
// the back.
func ntfsLogStraddle() []*libntfs.LogRecord {
	return []*libntfs.LogRecord{
		ntfsLogClient(1000, 990, 0),
		ntfsLogClient(1010, 1000, libntfs.LogOpForgetTransaction),
		ntfsLogClient(990, 0, 0),
	}
}

// TestStartPresentIsReadFromTheEarliestRecord is part of M26-FS2-023's
// regression: start_present asked whether the transaction's first record
// names no previous one, and took "first" as the first in page order, which
// after a wrap is not the first written.
func TestStartPresentIsReadFromTheEarliestRecord(t *testing.T) {
	transaction := libntfs.LogTransaction{ID: 7, FirstLSN: 990, LastLSN: 1010, Records: ntfsLogStraddle(), Forgotten: true}
	hash := ntfsLogTransactionHash(transaction).(*object.Hash)
	if !mustHashBoolValue(t, hash, "start_present") {
		t.Errorf("a transaction holding its own first record says its start is gone: %s", hash.Inspect())
	}
}

// libntfs groups records in the order it is handed them; this pins that the
// page order splits a transaction straddling the seam, which is why the scan
// sorts first.
func TestLibntfsGroupsInTheOrderItIsHanded(t *testing.T) {
	if got := len(libntfs.GroupLogTransactions(ntfsLogStraddle())); got != 2 {
		t.Fatalf("libntfs grouped the straddling transaction into %d, want the 2 that sorting avoids", got)
	}
}
