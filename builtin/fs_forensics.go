package builtin

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mutant/object"
)

func FsHash(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_hash` must be STRING, got %s", args[0].Type()))
	}

	algo := "sha256"
	if len(args) == 2 {
		algoObj, ok := args[1].(*object.String)
		if !ok {
			return resultAndError(nil, newError("argument 2 to `fs_hash` must be STRING, got %s", args[1].Type()))
		}
		algo = strings.ToLower(strings.TrimSpace(algoObj.Value))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_hash: %s", err.Error()))
	}

	h, errObj := fsHashAlgorithm(algo)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	_, _ = h.Write(data)
	digest := hex.EncodeToString(h.Sum(nil))

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":   stringObj(pathObj.Value),
		"algo":   stringObj(algo),
		"hash":   stringObj(digest),
		"size":   intObj(int64(len(data))),
		"bytes":  intObj(int64(len(data))),
		"status": stringObj("ok"),
	}), nil)
}

func FsWalk(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	rootObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_walk` must be STRING, got %s", args[0].Type()))
	}

	maxDepth := int64(-1)
	if len(args) == 2 {
		depthObj, ok := args[1].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 2 to `fs_walk` must be INTEGER, got %s", args[1].Type()))
		}
		maxDepth = depthObj.Value
	}

	root := rootObj.Value
	baseDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	entries := make([]object.Object, 0)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		currentDepth := int64(strings.Count(filepath.Clean(path), string(os.PathSeparator)) - baseDepth)
		if maxDepth >= 0 && currentDepth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		size := int64(0)
		mod := ""
		if err == nil {
			size = info.Size()
			mod = info.ModTime().Format(time.RFC3339)
		}

		entries = append(entries, makeHashObject(map[string]object.Object{
			"path":     stringObj(path),
			"name":     stringObj(d.Name()),
			"is_dir":   boolObj(d.IsDir()),
			"size":     intObj(size),
			"depth":    intObj(currentDepth),
			"mod_time": stringObj(mod),
		}))

		return nil
	})
	if err != nil {
		return resultAndError(nil, newError("fs_walk: %s", err.Error()))
	}

	sort.Slice(entries, func(i, j int) bool {
		li, _ := entries[i].(*object.Hash)
		lj, _ := entries[j].(*object.Hash)
		pi, _ := fsForensicsHashValueByKey(li, "path")
		pj, _ := fsForensicsHashValueByKey(lj, "path")
		si, _ := pi.(*object.String)
		sj, _ := pj.(*object.String)
		if si == nil || sj == nil {
			return false
		}
		return si.Value < sj.Value
	})

	return resultAndError(&object.Array{Elements: entries}, nil)
}

func FsMetadata(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_metadata` must be STRING, got %s", args[0].Type()))
	}

	info, err := os.Stat(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_metadata: %s", err.Error()))
	}

	mode := info.Mode()
	return resultAndError(makeHashObject(map[string]object.Object{
		"path":         stringObj(pathObj.Value),
		"name":         stringObj(info.Name()),
		"size":         intObj(info.Size()),
		"is_dir":       boolObj(info.IsDir()),
		"mode":         stringObj(mode.String()),
		"perm_octal":   stringObj(mode.Perm().String()),
		"mod_time":     stringObj(info.ModTime().Format(time.RFC3339)),
		"extension":    stringObj(strings.ToLower(filepath.Ext(pathObj.Value))),
		"is_read_only": boolObj(mode.Perm()&0222 == 0),
	}), nil)
}

func FsMagic(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_magic` must be STRING, got %s", args[0].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_magic: %s", err.Error()))
	}

	sigType, mime, sigBytes := detectMagic(data)
	return resultAndError(makeHashObject(map[string]object.Object{
		"path":      stringObj(pathObj.Value),
		"type":      stringObj(sigType),
		"mime":      stringObj(mime),
		"signature": stringObj(sigBytes),
	}), nil)
}

func FsExtractStrings(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_extract_strings` must be STRING, got %s", args[0].Type()))
	}

	minLen := int64(4)
	if len(args) == 2 {
		minLenObj, ok := args[1].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 2 to `fs_extract_strings` must be INTEGER, got %s", args[1].Type()))
		}
		if minLenObj.Value < 1 {
			return resultAndError(nil, newError("argument 2 to `fs_extract_strings` must be >= 1"))
		}
		minLen = minLenObj.Value
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_extract_strings: %s", err.Error()))
	}

	stringsOut := extractPrintableStrings(data, int(minLen))
	elements := make([]object.Object, len(stringsOut))
	for i, value := range stringsOut {
		elements[i] = stringObj(value)
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func FsDiff(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	pathAObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_diff` must be STRING, got %s", args[0].Type()))
	}
	pathBObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fs_diff` must be STRING, got %s", args[1].Type()))
	}

	dataA, err := os.ReadFile(pathAObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_diff: %s", err.Error()))
	}
	dataB, err := os.ReadFile(pathBObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_diff: %s", err.Error()))
	}

	hashA := sha256.Sum256(dataA)
	hashB := sha256.Sum256(dataB)
	equal := len(dataA) == len(dataB) && bytesEqual(dataA, dataB)

	firstDiff := int64(-1)
	if !equal {
		limit := len(dataA)
		if len(dataB) < limit {
			limit = len(dataB)
		}
		for i := 0; i < limit; i++ {
			if dataA[i] != dataB[i] {
				firstDiff = int64(i)
				break
			}
		}
		if firstDiff == -1 {
			firstDiff = int64(limit)
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"path_a":            stringObj(pathAObj.Value),
		"path_b":            stringObj(pathBObj.Value),
		"equal":             boolObj(equal),
		"size_a":            intObj(int64(len(dataA))),
		"size_b":            intObj(int64(len(dataB))),
		"sha256_a":          stringObj(hex.EncodeToString(hashA[:])),
		"sha256_b":          stringObj(hex.EncodeToString(hashB[:])),
		"first_diff_offset": intObj(firstDiff),
	}), nil)
}

func FsCarve(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_carve` must be STRING, got %s", args[0].Type()))
	}
	typeObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fs_carve` must be STRING, got %s", args[1].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_carve: %s", err.Error()))
	}

	target := strings.ToLower(strings.TrimSpace(typeObj.Value))
	sig, ok := carveSignature(target)
	if !ok {
		return resultAndError(nil, newError("fs_carve: unsupported type `%s`", typeObj.Value))
	}

	hits := carveOffsets(data, sig)
	elements := make([]object.Object, len(hits))
	for i, off := range hits {
		elements[i] = makeHashObject(map[string]object.Object{
			"type":   stringObj(target),
			"offset": intObj(int64(off)),
		})
	}

	return resultAndError(&object.Array{Elements: elements}, nil)
}

func FsEntropy(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_entropy` must be STRING, got %s", args[0].Type()))
	}

	data, err := os.ReadFile(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_entropy: %s", err.Error()))
	}

	ent := shannonEntropy(data)
	return resultAndError(makeHashObject(map[string]object.Object{
		"path":    stringObj(pathObj.Value),
		"bytes":   intObj(int64(len(data))),
		"entropy": &object.Float{Value: ent},
	}), nil)
}

func fsHashAlgorithm(algo string) (hash.Hash, *object.Error) {
	switch strings.ToLower(algo) {
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha256", "":
		return sha256.New(), nil
	default:
		return nil, newError("fs_hash: unsupported algorithm `%s`", algo)
	}
}

func detectMagic(data []byte) (string, string, string) {
	type magicDef struct {
		typ  string
		mime string
		sig  []byte
	}
	defs := []magicDef{
		{typ: "pe", mime: "application/vnd.microsoft.portable-executable", sig: []byte{0x4D, 0x5A}},
		{typ: "elf", mime: "application/x-elf", sig: []byte{0x7F, 0x45, 0x4C, 0x46}},
		{typ: "png", mime: "image/png", sig: []byte{0x89, 0x50, 0x4E, 0x47}},
		{typ: "zip", mime: "application/zip", sig: []byte{0x50, 0x4B, 0x03, 0x04}},
		{typ: "pdf", mime: "application/pdf", sig: []byte{0x25, 0x50, 0x44, 0x46}},
	}

	for _, def := range defs {
		if len(data) >= len(def.sig) {
			matches := true
			for i := range def.sig {
				if data[i] != def.sig[i] {
					matches = false
					break
				}
			}
			if matches {
				return def.typ, def.mime, strings.ToUpper(hex.EncodeToString(def.sig))
			}
		}
	}
	return "unknown", "application/octet-stream", ""
}

func extractPrintableStrings(data []byte, minLen int) []string {
	if minLen < 1 {
		minLen = 1
	}
	out := make([]string, 0)
	buf := make([]byte, 0, 32)

	flush := func() {
		if len(buf) >= minLen {
			out = append(out, string(buf))
		}
		buf = buf[:0]
	}

	for _, b := range data {
		if b >= 32 && b <= 126 {
			buf = append(buf, b)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func carveSignature(name string) ([]byte, bool) {
	switch name {
	case "pe":
		return []byte{0x4D, 0x5A}, true
	case "elf":
		return []byte{0x7F, 0x45, 0x4C, 0x46}, true
	case "png":
		return []byte{0x89, 0x50, 0x4E, 0x47}, true
	case "zip":
		return []byte{0x50, 0x4B, 0x03, 0x04}, true
	case "pdf":
		return []byte{0x25, 0x50, 0x44, 0x46}, true
	default:
		return nil, false
	}
}

func carveOffsets(data []byte, sig []byte) []int {
	if len(sig) == 0 || len(data) < len(sig) {
		return []int{}
	}
	out := make([]int, 0)
	for i := 0; i <= len(data)-len(sig); i++ {
		match := true
		for j := range sig {
			if data[i+j] != sig[j] {
				match = false
				break
			}
		}
		if match {
			out = append(out, i)
		}
	}
	return out
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	total := float64(len(data))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * (math.Log2(p))
	}
	return entropy
}

func fsForensicsHashValueByKey(hash *object.Hash, key string) (object.Object, bool) {
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		return nil, false
	}
	return pair.Value, true
}
