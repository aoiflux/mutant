package builtin

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"mutant/object"
)

// BodyfileParse parses a Sleuth Kit (TSK) bodyfile — pipe-delimited lines of
// MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime — into an array of
// entry hashes. inode/mode/md5/name stay strings; uid/gid/size and the four MAC
// times are integers. Returns (entries, err).
func BodyfileParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("bodyfile_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	f, err := os.Open(path)
	if err != nil {
		return resultAndError(nil, newError("bodyfile_parse: %s", err.Error()))
	}
	defer f.Close()

	entries := make([]object.Object, 0)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 11 {
			continue // not a valid bodyfile row
		}
		entries = append(entries, makeHashObject(map[string]object.Object{
			"md5":    stringObj(fields[0]),
			"name":   stringObj(fields[1]),
			"inode":  stringObj(fields[2]),
			"mode":   stringObj(fields[3]),
			"uid":    intObj(parseBodyfileInt(fields[4])),
			"gid":    intObj(parseBodyfileInt(fields[5])),
			"size":   intObj(parseBodyfileInt(fields[6])),
			"atime":  intObj(parseBodyfileInt(fields[7])),
			"mtime":  intObj(parseBodyfileInt(fields[8])),
			"ctime":  intObj(parseBodyfileInt(fields[9])),
			"crtime": intObj(parseBodyfileInt(fields[10])),
		}))
	}
	if err := scanner.Err(); err != nil {
		return resultAndError(nil, newError("bodyfile_parse: %s", err.Error()))
	}
	return resultAndError(&object.Array{Elements: entries}, nil)
}

func parseBodyfileInt(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// Mactime turns parsed bodyfile entries (from bodyfile_parse) into a chronological
// timeline. For each entry it groups the four MAC times by value and emits one row
// per distinct time with a MACB flag string (m=mtime, a=atime, c=ctime, b=crtime;
// "." where that time differs). Rows are sorted by time then name. The timestamp
// field is "ts" so the result composes with timeline_merge.
func Mactime(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	entries, errObj := requireArrayArg("mactime", args[0], 1)
	if errObj != nil {
		return errObj
	}

	rows := make([]object.Object, 0)
	for i, el := range entries.Elements {
		entry, ok := el.(*object.Hash)
		if !ok {
			return newError("mactime: entry %d must be a HASH (from bodyfile_parse), got %s", i, el.Type())
		}
		// Collect each MAC time and which flags map to it.
		byTime := map[int64]map[byte]bool{}
		addTime := func(field string, flag byte) {
			if v, ok := bodyfileInt(entry, field); ok && v > 0 {
				if byTime[v] == nil {
					byTime[v] = map[byte]bool{}
				}
				byTime[v][flag] = true
			}
		}
		addTime("mtime", 'm')
		addTime("atime", 'a')
		addTime("ctime", 'c')
		addTime("crtime", 'b')

		for ts, flags := range byTime {
			rows = append(rows, makeHashObject(map[string]object.Object{
				"ts":    intObj(ts),
				"iso":   stringObj(time.Unix(ts, 0).UTC().Format(time.RFC3339)),
				"macb":  stringObj(macbString(flags)),
				"name":  hashStringOr(entry, "name"),
				"size":  hashIntOr(entry, "size"),
				"inode": hashStringOr(entry, "inode"),
				"mode":  hashStringOr(entry, "mode"),
				"uid":   hashIntOr(entry, "uid"),
				"gid":   hashIntOr(entry, "gid"),
				"md5":   hashStringOr(entry, "md5"),
			}))
		}
	}

	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := rows[i].(*object.Hash), rows[j].(*object.Hash)
		ti, _ := bodyfileInt(ri, "ts")
		tj, _ := bodyfileInt(rj, "ts")
		if ti != tj {
			return ti < tj
		}
		ni, _ := hashStringValue(ri, "name")
		nj, _ := hashStringValue(rj, "name")
		return ni < nj
	})
	return &object.Array{Elements: rows}
}

func macbString(flags map[byte]bool) string {
	out := []byte{'.', '.', '.', '.'}
	for i, f := range []byte{'m', 'a', 'c', 'b'} {
		if flags[f] {
			out[i] = f
		}
	}
	return string(out)
}

func bodyfileInt(h *object.Hash, key string) (int64, bool) {
	if v, ok := hashValueByKey(h, key).(*object.Integer); ok {
		return v.Value, true
	}
	return 0, false
}

func hashStringValue(h *object.Hash, key string) (string, bool) {
	if v, ok := hashValueByKey(h, key).(*object.String); ok {
		return v.Value, true
	}
	return "", false
}

func hashStringOr(h *object.Hash, key string) object.Object {
	if s, ok := hashStringValue(h, key); ok {
		return stringObj(s)
	}
	return stringObj("")
}

func hashIntOr(h *object.Hash, key string) object.Object {
	if v, ok := bodyfileInt(h, key); ok {
		return intObj(v)
	}
	return intObj(0)
}
