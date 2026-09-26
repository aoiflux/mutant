package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
	"mutant/security"
)

// A reclassification asked about a second time finds the first record of it
// and writes nothing to the ledger, which is the disclosure family's cheapest
// write path: what is left is the lookups, and -- until the names were declared
// once per session (M26-CUS-003) -- a rewrite and fsync of the label table
// beside the ledger. Read ns/op against the base for the fsync; see
// db_bench_test.go on ns/op noise.
func BenchmarkDiscloseReclassifiedAgain(b *testing.B) {
	resetCustodyForTesting()
	b.Cleanup(resetCustodyForTesting)
	previous := security.SetPassphraseSource(passphraseFunc(func(security.PassphraseRequest) ([]byte, error) {
		return []byte(testCasePassphrase), nil
	}))
	b.Cleanup(func() { security.SetPassphraseSource(previous) })

	dir := b.TempDir()
	// After TempDir: cleanups run last first, and the records must be closed
	// before their directory is removed.
	b.Cleanup(resetRecordsForTesting)
	benchPayload(b, "case_open", CaseOpen(stringObj("IR-BENCH"), stringObj("examiner")))
	key := filepath.Join(dir, "case.mkey")
	benchPayload(b, "case_key_create", CaseKeyCreate(stringObj(key)))
	benchPayload(b, "case_key_open", CaseKeyOpen(stringObj(key)))
	for _, class := range []string{"open", "restricted", "pii"} {
		benchPayload(b, "class_define", ClassDefine(stringObj(class)))
	}

	source := filepath.Join(dir, "evidence.bin")
	plaintext := make([]byte, 400)
	for i := range plaintext {
		plaintext[i] = byte('A' + i%26)
	}
	if err := os.WriteFile(source, plaintext, 0o600); err != nil {
		b.Fatal(err)
	}
	seal := func(name string, ranges ...[3]any) object.Object {
		classified := make([]object.Object, 0, len(ranges))
		for _, r := range ranges {
			classified = append(classified, benchPayload(b, "record_classify_range",
				RecordClassifyRange(intObj(int64(r[0].(int))), intObj(int64(r[1].(int))), stringObj(r[2].(string)))))
		}
		dest := filepath.Join(dir, name)
		benchPayload(b, "record_seal", RecordSeal(stringObj(source), stringObj(dest), recordArray(classified...),
			recordSealOpts(map[string]object.Object{"sign": boolObj(true)})))
		opened := benchPayload(b, "record_open", RecordOpen(stringObj(dest)))
		value, _ := hashValueByStringKey(opened.(*object.Hash), "handle")
		return value
	}
	old := seal("evidence.mrec", [3]any{100, 60, "pii"}, [3]any{160, 90, "restricted"})
	reclassified := seal("reclassified.mrec", [3]any{100, 150, "restricted"})

	opened := benchPayload(b, "ledger_open", LedgerOpen(stringObj(filepath.Join(dir, "ledger")), stringObj("examiner")))
	ledger := benchHashInt(b, "ledger_open", opened, "handle")
	b.Cleanup(func() { LedgerClose(intObj(ledger)) })
	benchPayload(b, "disclose_reclassified", DiscloseReclassified(intObj(ledger), reclassified, old))

	b.ReportAllocs()
	for b.Loop() {
		benchPayload(b, "disclose_reclassified", DiscloseReclassified(intObj(ledger), reclassified, old))
	}
}
