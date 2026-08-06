package builtin

import (
	"encoding/hex"

	libntfs "github.com/aoiflux/libntfs"
	"mutant/object"
)

// FsDeleted enumerates deleted files from an NTFS $MFT — a standalone $MFT file
// or a full volume image (auto-detected, like mft_parse). A record is "deleted"
// when its in-use flag is clear but its metadata still parses. For small files
// whose $DATA attribute is resident (stored inside the MFT record), the content
// is fully recoverable and returned (hex-encoded); larger files store their data
// in clusters that may be overwritten, so only the metadata is reported.
//
// Returns {source_type, deleted_count, entries:[{record, name, path, size,
// is_directory, has_data, resident, recoverable, resident_data, si_*, fn_*}]}.
func FsDeleted(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("fs_deleted: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("fs_deleted", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// Collect every entry (needed for full-path reconstruction — a deleted file's
	// parent directory may still be in use), plus recovered data for deleted ones.
	var rows []mftRow
	recovered := map[uint64]residentRecovery{}
	sourceType, _, err := walkMFT(path, func(n uint64, e *libntfs.MFTEntry) {
		rows = append(rows, mftRowFromEntry(e, n))
		if !e.IsInUse() {
			recovered[n] = recoverResidentData(e)
		}
	})
	if err != nil {
		return resultAndError(nil, newError("fs_deleted: %s", err.Error()))
	}

	paths := reconstructMFTPaths(rows)
	entries := make([]object.Object, 0)
	for _, r := range rows {
		if r.inUse {
			continue
		}
		entries = append(entries, deletedEntryHash(r, paths[r.record], recovered[r.record]))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"source_type":   stringObj(sourceType),
		"deleted_count": intObj(int64(len(entries))),
		"entries":       &object.Array{Elements: entries},
	}), nil)
}

// residentRecovery holds the outcome of trying to recover a deleted file's data
// from its (resident) $DATA attribute.
type residentRecovery struct {
	hasData  bool
	resident bool
	data     []byte
}

func recoverResidentData(e *libntfs.MFTEntry) residentRecovery {
	attr := e.FindPrimaryDataAttribute()
	if attr == nil {
		return residentRecovery{}
	}
	if attr.IsResident() && attr.Resident != nil {
		return residentRecovery{hasData: true, resident: true, data: attr.Resident.Value}
	}
	return residentRecovery{hasData: true, resident: false}
}

func deletedEntryHash(r mftRow, fullPath string, rec residentRecovery) object.Object {
	m := map[string]object.Object{
		"record":        intObj(int64(r.record)),
		"name":          stringObj(r.name),
		"path":          stringObj(fullPath),
		"size":          intObj(int64(r.size)),
		"is_directory":  boolObj(r.isDir),
		"has_data":      boolObj(rec.hasData),
		"resident":      boolObj(rec.resident),
		"recoverable":   boolObj(rec.resident && len(rec.data) > 0),
		"resident_data": stringObj(hex.EncodeToString(rec.data)), // hex, binary-safe
	}
	addMFTTimes(m, "si", r.si != nil, siTimes(r.si))
	addMFTTimes(m, "fn", r.fn != nil, fnTimes(r.fn))
	return makeHashObject(m)
}
