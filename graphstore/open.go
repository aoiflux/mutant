package graphstore

// # Reading a store without changing what it says
//
// graphene.Open takes an exclusive lock, stamps the calling process's pid into
// graphene.lock on open and again on close, and -- the part that decides this
// -- CREATES a store for any path that does not hold one. A read built on it
// would answer "0 nodes" for a mistyped path while writing two files into
// whatever directory was actually named.
//
// So a store is opened read-only. OpenReadOnly refuses a missing path and a
// path that is not a directory, admits other readers, and writes nothing into
// any file that carries what the store says.
//
// It does not leave the directory untouched, and saying that it did would be
// the kind of claim this package exists not to make. OpenReadOnly takes its
// shared lock through graphene.lock and opens that file O_CREATE, so reading a
// store that has no lock file creates a zero-byte one and moves the
// directory's mtime. That is not an exotic shape: graphene's Store.Backup
// excludes graphene.lock by design, so every store recovered through its own
// supported restore path arrives without one and would be modified by its
// first read.
//
// Hence three ways in, chosen by what is on disk before anything is opened.
//
//   - graphene.lock is present and writable. OpenReadOnly. A writer holding the
//     store is refused here rather than read around.
//
//   - graphene.lock is absent. No lock can be held through a file that does not
//     exist, so the store is opened live, which creates nothing, and the caller
//     is told the read was lock-free and why.
//
//   - graphene.lock is present and cannot be opened for writing, because the
//     media or the directory is read-only. OpenReadOnly cannot take its shared
//     lock. The store is opened live and the caller is told so -- but only
//     after the lock's own owner record has been read, because a permission
//     error is also what a live writer on read-only media looks like, and that
//     is the one case where a lock-free read would be reading a store
//     mid-change.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/disk"
)

// LockFileName is the file graphene takes a store's lock through.
const LockFileName = "graphene.lock"

// OpenForReading opens the store in dir without changing what it says, and
// reports why, when it could not take a lock. See the file header.
//
// The empty string means the ordinary locked read. Anything else is the reason
// the read was lock-free, and it is meant to reach the reader verbatim rather
// than be reduced to a boolean, because the two reasons are not equally
// comfortable and a reader is entitled to know which one they got.
//
// A path that does not exist, or is not a directory, is refused before
// anything opens it. Errors name the directory but not the caller; each caller
// prefixes its own name.
func OpenForReading(dir string) (*graphene.Graph, string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("%s does not exist", dir)
		}
		return nil, "", err
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("%s is a file; a graph store is a directory", dir)
	}

	// A store with no lock file cannot be held by anybody, and OpenReadOnly
	// would create one. Open live: it takes no lock and creates nothing.
	lockPath := filepath.Join(dir, LockFileName)
	if _, err := os.Stat(lockPath); errors.Is(err, fs.ErrNotExist) {
		live, liveErr := graphene.OpenLive(dir)
		if liveErr != nil {
			return nil, "", liveErr
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
		return nil, "", err
	}
	// Everything else is a candidate for the lock-free read, but only two
	// things make it sound: the failure has to be about permission, and the
	// lock's owner record has to say nobody is holding it. A live writer on
	// read-only media fails with a permission error too, so the first test
	// alone would read a store mid-change and call it write-protected.
	if !errors.Is(err, fs.ErrPermission) {
		return nil, "", err
	}
	if owner, readable := readLockOwner(lockPath); readable &&
		owner.present && !owner.clean && owner.pid != 0 {
		return nil, "", fmt.Errorf("%s could not be locked for reading, and its "+
			"graphene.lock records process %d as holding it without having closed it. Reading "+
			"without a lock would read a store that is being written: %w", dir, owner.pid, err)
	}
	live, liveErr := graphene.OpenLive(dir)
	if liveErr != nil {
		// Both attempts failed, and it is the second that decided the outcome:
		// the lock-free read is the one this exists to be able to do, so
		// blaming the lock here would name as fatal the exact condition the
		// fallback was written to survive.
		return nil, "", fmt.Errorf("%s could not be read with a lock (%v) and could "+
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
// same decision ReadLabelTable makes for graphene.labels: the engine is
// deciding what to do about the file, and this is deciding whether to believe
// a directory at all, which has to happen before the engine is involved.
//
// It is deliberately read without a lock. The record sits outside the locked
// byte range and is written in one 32-byte WriteAt, so a concurrent reader sees
// the old record or the new one and never a mixture.
type lockOwner struct {
	present bool
	pid     uint64
	clean   bool
}

// The owner record's layout, as graphene writes it.
//
//mutant:format graphene v0.9.0 disk/lock.go appendLockOwner, the owner record at offset 0 of graphene.lock
const (
	lockRecordSize    = 32
	lockMagic         = "GLK1"
	lockVersion       = 1
	lockPIDOffset     = 8
	lockCleanOffset   = 16
	lockVersionOffset = 4
)

// readLockOwner returns the record and whether the file could be read at all.
// An unreadable or foreign file yields a zero owner and false, which callers
// must treat as "nothing is known" rather than as "nobody is holding it".
func readLockOwner(path string) (lockOwner, bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < lockRecordSize {
		return lockOwner{}, false
	}
	if string(raw[:len(lockMagic)]) != lockMagic || raw[lockVersionOffset] != lockVersion {
		return lockOwner{}, false
	}
	return lockOwner{
		present: true,
		pid:     binary.LittleEndian.Uint64(raw[lockPIDOffset : lockPIDOffset+8]),
		clean:   raw[lockCleanOffset] == 1,
	}, true
}
