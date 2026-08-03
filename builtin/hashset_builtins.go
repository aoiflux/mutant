package builtin

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"mutant/object"
)

// hashSetStore holds loaded known-file hash sets by handle. The set maps are
// never mutated after load, so concurrent hashset_contains reads are safe once
// the handle is resolved under the lock.
var hashSetStore = struct {
	sync.Mutex
	next int64
	sets map[string]map[string]struct{}
}{sets: map[string]map[string]struct{}{}}

// HashsetLoad reads a file of hashes (one per line, or a CSV/NSRL-style file where
// the hash is the first field) into an in-memory set and returns {handle, count}.
// Hashes are normalized to lowercase; header/non-hex lines and comments are skipped.
func HashsetLoad(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("hashset_load", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	f, err := os.Open(path)
	if err != nil {
		return resultAndError(nil, newError("hashset_load: %s", err.Error()))
	}
	defer f.Close()

	set := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024) // NSRL lines can be long
	for scanner.Scan() {
		if h, ok := hashFromLine(scanner.Text()); ok {
			set[h] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return resultAndError(nil, newError("hashset_load: %s", err.Error()))
	}

	hashSetStore.Lock()
	hashSetStore.next++
	handle := fmt.Sprintf("hashset-%d", hashSetStore.next)
	hashSetStore.sets[handle] = set
	hashSetStore.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": stringObj(handle),
		"count":  intObj(int64(len(set))),
	}), nil)
}

// HashsetContains reports whether a hash is present in a loaded set (case-insensitive).
func HashsetContains(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	handle, errObj := requireStringArg("hashset_contains", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	query, errObj := requireStringArg("hashset_contains", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	hashSetStore.Lock()
	set, ok := hashSetStore.sets[handle]
	hashSetStore.Unlock()
	if !ok {
		return resultAndError(nil, newError("hashset_contains: invalid handle %q (call hashset_load first)", handle))
	}

	_, found := set[normalizeHash(query)]
	return resultAndError(boolObj(found), nil)
}

// HashsetClose frees a loaded hash set.
func HashsetClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handle, errObj := requireStringArg("hashset_close", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	hashSetStore.Lock()
	_, ok := hashSetStore.sets[handle]
	delete(hashSetStore.sets, handle)
	hashSetStore.Unlock()
	if !ok {
		return resultAndError(nil, newError("hashset_close: invalid handle %q", handle))
	}
	return resultAndError(boolObj(true), nil)
}

func normalizeHash(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "\"'"))
}

// hashFromLine extracts a hex hash from a line: the first comma/whitespace field,
// normalized. Returns ok=false for blank/comment/header lines (non-hex fields).
func hashFromLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	field := line
	if i := strings.IndexAny(line, ", \t"); i >= 0 {
		field = line[:i]
	}
	h := normalizeHash(field)
	if len(h) < 8 || !isHexString(h) {
		return "", false
	}
	return h, true
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
