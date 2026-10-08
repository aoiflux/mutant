package builtin

import (
	"testing"

	libntfs "github.com/aoiflux/libntfs"

	"mutant/object"
)

// M26-FS2-023: in LSN order the straddling transaction is one transaction,
// forgotten, with its start present.
func TestALogTransactionStraddlingTheSeamIsOne(t *testing.T) {
	records, copies := ntfsDistinctLogRecords(ntfsLogStraddle())
	if copies != 0 {
		t.Fatalf("%d copies in records that hold none", copies)
	}
	transactions := libntfs.GroupLogTransactions(records)
	if len(transactions) != 1 {
		t.Fatalf("%d transactions, want 1", len(transactions))
	}
	hash := ntfsLogTransactionHash(transactions[0]).(*object.Hash)
	if mustHashStringValue(t, hash, "end_state") != "forgotten" || !mustHashBoolValue(t, hash, "start_present") ||
		mustHashIntValue(t, hash, "record_count") != 3 {
		t.Errorf("the reassembled transaction: %s", hash.Inspect())
	}
}

// M26-FS2-024: an LSN met twice is one record, counted once, and a walk
// holding copies does not judge a wrap.
func TestARepeatedLSNIsOneRecordAndNoWrapVerdict(t *testing.T) {
	records := append(ntfsLogStraddle(), ntfsLogClient(1010, 1000, libntfs.LogOpForgetTransaction))
	distinct, copies := ntfsDistinctLogRecords(records)
	if copies != 1 || len(distinct) != 3 {
		t.Fatalf("%d distinct records and %d copies, want 3 and 1", len(distinct), copies)
	}

	scan := newJournalScan("ntfs", fsJournalLogFile, fsJournalOrderLSN)
	scan.WrapChecked = true
	scan.Wrapped = true
	if !ntfsLogCopies(&scan, copies) || scan.Wrapped || scan.WrapChecked {
		t.Errorf("a walk holding copies kept its wrap verdict: wrapped %v, checked %v", scan.Wrapped, scan.WrapChecked)
	}
	if len(scan.Warnings) != 1 || scan.Warnings[0].Code != fsJournalWarnLogCopies {
		t.Errorf("the copies were not reported: %+v", scan.Warnings)
	}
	if ntfsLogCopies(&scan, 0) {
		t.Errorf("a walk with no copies was said to hold some")
	}
}
