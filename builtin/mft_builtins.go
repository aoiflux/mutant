package builtin

import (
	"fmt"
	"io"
	"os"
	"time"

	libntfs "github.com/aoiflux/libntfs"
	"mutant/object"
)

// mftRootRecord is the MFT record number of the volume root directory (".").
const mftRootRecord = 5

// MftParse decodes an NTFS Master File Table into a per-record timeline. It
// auto-detects its input: a standalone $MFT file (records beginning with the
// "FILE" signature, as extracted by KAPE/FTK/icat) is streamed record-by-record
// via libntfs.ParseMFTRecord; otherwise the path is opened as a full NTFS volume
// image and walked via libntfs EachMFTEntry.
//
// Each entry carries both the $STANDARD_INFORMATION and $FILE_NAME MAC times
// (unix + ISO-8601), the reconstructed full path, size, sequence number, and
// hard-link count. Returns {source_type, record_size, count, entries} paired
// with an error.
func MftParse(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("mft_parse: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("mft_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var rows []mftRow
	sourceType, recordSize, err := walkMFT(path, func(n uint64, e *libntfs.MFTEntry) {
		rows = append(rows, mftRowFromEntry(e, n))
	})
	if err != nil {
		return resultAndError(nil, newError("mft_parse: %s", err.Error()))
	}

	paths := reconstructMFTPaths(rows)
	entries := make([]object.Object, len(rows))
	for i, r := range rows {
		entries[i] = r.toHash(paths[r.record])
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"source_type": stringObj(sourceType),
		"record_size": intObj(int64(recordSize)),
		"count":       intObj(int64(len(rows))),
		"entries":     &object.Array{Elements: entries},
	}), nil)
}

// walkMFT auto-detects the input (a standalone $MFT file whose records start with
// the "FILE" signature vs a full NTFS volume image) and invokes fn for every
// parsable MFT entry, returning the detected source type and record size. Shared
// by mft_parse and fs_deleted.
func walkMFT(path string, fn func(recordNum uint64, e *libntfs.MFTEntry)) (string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	peek := make([]byte, 4)
	if _, err := io.ReadFull(f, peek); err != nil {
		return "", 0, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}

	if string(peek) == "FILE" {
		data, rerr := io.ReadAll(f)
		if rerr != nil {
			return "", 0, rerr
		}
		rs := libntfs.DefaultMFTRecordSize
		// Each record's fixup modifies its slice in place, which is safe because
		// every record is parsed exactly once.
		for off := 0; off+rs <= len(data); off += rs {
			entryNum := uint64(off / rs)
			e, perr := libntfs.ParseMFTRecord(data[off:off+rs], entryNum, uint32(rs))
			if perr != nil {
				continue
			}
			fn(entryNum, e)
		}
		return "mft", rs, nil
	}

	vol, verr := libntfs.Open(f)
	if verr != nil {
		return "", 0, fmt.Errorf("not a standalone $MFT (no FILE signature) and not a mountable NTFS volume: %s. For a full-disk image, locate the NTFS partition offset with table_* first", verr.Error())
	}
	recordSize := 0
	if rs := vol.MFTRecordSize(); rs > 0 {
		recordSize = int(rs)
	}
	_ = vol.EachMFTEntry(func(n uint64, e *libntfs.MFTEntry) error {
		fn(n, e)
		return nil
	})
	return "volume", recordSize, nil
}

// mftRow is the extracted, Volume-independent view of one MFT record. It copies
// out everything needed for output so results survive ParseMFTRecordInto reuse
// and volume-cache eviction.
type mftRow struct {
	record       uint64
	parent       uint64
	inUse        bool
	isDir        bool
	name         string
	size         uint64
	allocated    uint64
	sequence     uint16
	hardLinks    uint16
	fileAttrs    uint32
	si           *libntfs.StandardInformation
	fn           *libntfs.FileName
}

func mftRowFromEntry(e *libntfs.MFTEntry, recordNum uint64) mftRow {
	row := mftRow{
		record:    recordNum,
		parent:    mftRootRecord, // fallback until a $FILE_NAME says otherwise
		inUse:     e.IsInUse(),
		isDir:     e.IsDirectory(),
		sequence:  e.SequenceNum,
		hardLinks: e.HardLinkCount,
	}
	if si, err := e.GetStandardInformation(); err == nil && si != nil {
		row.si = si
		row.fileAttrs = si.FileAttributes
	}
	if fn, err := e.GetFileName(); err == nil && fn != nil {
		row.fn = fn
		row.name = fn.Name
		row.parent = fn.ParentDirectory & 0x0000FFFFFFFFFFFF // strip sequence bits
		row.size = fn.RealSize
		row.allocated = fn.AllocatedSize
	}
	return row
}

func (r mftRow) toHash(fullPath string) object.Object {
	m := map[string]object.Object{
		"record":         intObj(int64(r.record)),
		"parent_record":  intObj(int64(r.parent)),
		"in_use":         boolObj(r.inUse),
		"is_directory":   boolObj(r.isDir),
		"name":           stringObj(r.name),
		"path":           stringObj(fullPath),
		"size":           intObj(int64(r.size)),
		"allocated_size": intObj(int64(r.allocated)),
		"sequence":       intObj(int64(r.sequence)),
		"hard_links":     intObj(int64(r.hardLinks)),
		"file_attributes": intObj(int64(r.fileAttrs)),
	}
	addMFTTimes(m, "si", r.si != nil, siTimes(r.si))
	addMFTTimes(m, "fn", r.fn != nil, fnTimes(r.fn))
	return makeHashObject(m)
}

// macTimes bundles the four NTFS timestamps in MACB order.
type macTimes struct{ modified, accessed, mftModified, created time.Time }

func siTimes(si *libntfs.StandardInformation) macTimes {
	if si == nil {
		return macTimes{}
	}
	return macTimes{si.ModifyTime, si.AccessTime, si.MFTChangeTime, si.CreateTime}
}

func fnTimes(fn *libntfs.FileName) macTimes {
	if fn == nil {
		return macTimes{}
	}
	return macTimes{fn.ModifyTime, fn.AccessTime, fn.MFTChangeTime, fn.CreateTime}
}

func addMFTTimes(m map[string]object.Object, prefix string, present bool, t macTimes) {
	if !present {
		return
	}
	for label, tv := range map[string]time.Time{
		"modified":     t.modified,
		"accessed":     t.accessed,
		"mft_modified": t.mftModified,
		"created":      t.created,
	} {
		unix, iso := mftTimeFields(tv)
		m[prefix+"_"+label] = intObj(unix)
		m[prefix+"_"+label+"_iso"] = stringObj(iso)
	}
}

func mftTimeFields(t time.Time) (int64, string) {
	if t.IsZero() {
		return 0, ""
	}
	return t.Unix(), t.UTC().Format(time.RFC3339)
}

// reconstructMFTPaths walks each record's $FILE_NAME parent reference up to the
// root directory (record 5), producing a backslash-separated full path. Records
// whose parent chain is broken (orphans, or a partial standalone $MFT) are
// prefixed with "?". Cycles are bounded by a depth cap.
func reconstructMFTPaths(rows []mftRow) map[uint64]string {
	byRecord := make(map[uint64]mftRow, len(rows))
	for _, r := range rows {
		byRecord[r.record] = r
	}

	prefixCache := make(map[uint64]string, len(rows))
	var dirPrefix func(rec uint64, depth int) string
	dirPrefix = func(rec uint64, depth int) string {
		if rec == mftRootRecord {
			return ""
		}
		if p, ok := prefixCache[rec]; ok {
			return p
		}
		if depth > 256 {
			return "?"
		}
		r, ok := byRecord[rec]
		if !ok || r.name == "" {
			return "?"
		}
		p := dirPrefix(r.parent, depth+1) + `\` + r.name
		prefixCache[rec] = p
		return p
	}

	paths := make(map[uint64]string, len(rows))
	for _, r := range rows {
		if r.record == mftRootRecord {
			paths[r.record] = `\`
			continue
		}
		if r.name == "" {
			paths[r.record] = ""
			continue
		}
		paths[r.record] = dirPrefix(r.parent, 0) + `\` + r.name
	}
	return paths
}
