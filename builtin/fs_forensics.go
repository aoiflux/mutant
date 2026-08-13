package builtin

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
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

	// detectMagic only inspects a short header, so read a small prefix instead of
	// slurping the whole file (which could be gigabytes) to check a few bytes.
	f, err := os.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_magic: %s", err.Error()))
	}
	// 512 bytes covers the offset-based signatures (e.g. TAR's "ustar" at 257)
	// while still avoiding slurping a multi-gigabyte file to check its header.
	header := make([]byte, 512)
	n, err := io.ReadFull(f, header)
	f.Close()
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return resultAndError(nil, newError("fs_magic: %s", err.Error()))
	}

	sigType, mime, sigBytes := detectMagic(header[:n])
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
		return resultAndError(nil, newError("fs_carve: unsupported type `%s`. supported: %s", typeObj.Value, strings.Join(carveTypes(), ", ")))
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

type fileSignature struct {
	typ    string
	mime   string
	sig    []byte
	offset int // byte offset the signature sits at (0 for almost all)
}

// fileSignatures is the shared magic-number database used by both fs_magic (file
// identification) and fs_carve (embedded-file scanning). Ordered longer/more
// specific first so a short signature can't shadow a more precise one.
var fileSignatures = []fileSignature{
	// Executables & object files
	{"ole", "application/x-ole-storage", []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 0}, // doc/xls/ppt/msi/msg
	{"lnk", "application/x-ms-shortcut", []byte{0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00}, 0},
	{"png", "image/png", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, 0},
	{"sqlite", "application/vnd.sqlite3", []byte("SQLite format 3\x00"), 0},
	{"evtx", "application/x-ms-evtx", []byte("ElfFile\x00"), 0},
	{"7z", "application/x-7z-compressed", []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, 0},
	{"xz", "application/x-xz", []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, 0},
	{"rar", "application/vnd.rar", []byte{'R', 'a', 'r', '!', 0x1A, 0x07}, 0},
	{"elf", "application/x-elf", []byte{0x7F, 'E', 'L', 'F'}, 0},
	{"macho32", "application/x-mach-binary", []byte{0xFE, 0xED, 0xFA, 0xCE}, 0},
	{"macho64", "application/x-mach-binary", []byte{0xFE, 0xED, 0xFA, 0xCF}, 0},
	{"macho32le", "application/x-mach-binary", []byte{0xCE, 0xFA, 0xED, 0xFE}, 0},
	{"macho64le", "application/x-mach-binary", []byte{0xCF, 0xFA, 0xED, 0xFE}, 0},
	{"macho_universal", "application/x-mach-binary", []byte{0xCA, 0xFE, 0xBA, 0xBE}, 0},
	// Images
	{"tiff_le", "image/tiff", []byte{0x49, 0x49, 0x2A, 0x00}, 0},
	{"tiff_be", "image/tiff", []byte{0x4D, 0x4D, 0x00, 0x2A}, 0},
	{"gif", "image/gif", []byte{'G', 'I', 'F', '8'}, 0},
	{"ico", "image/x-icon", []byte{0x00, 0x00, 0x01, 0x00}, 0},
	{"psd", "image/vnd.adobe.photoshop", []byte{'8', 'B', 'P', 'S'}, 0},
	{"jpeg", "image/jpeg", []byte{0xFF, 0xD8, 0xFF}, 0},
	{"bmp", "image/bmp", []byte{'B', 'M'}, 0},
	// Archives & compression
	{"zip", "application/zip", []byte{'P', 'K', 0x03, 0x04}, 0}, // also docx/xlsx/pptx/jar/apk
	{"zstd", "application/zstd", []byte{0x28, 0xB5, 0x2F, 0xFD}, 0},
	{"lz4", "application/x-lz4", []byte{0x04, 0x22, 0x4D, 0x18}, 0},
	{"cab", "application/vnd.ms-cab-compressed", []byte{'M', 'S', 'C', 'F'}, 0},
	{"bzip2", "application/x-bzip2", []byte{'B', 'Z', 'h'}, 0},
	{"tar", "application/x-tar", []byte{'u', 's', 't', 'a', 'r'}, 257},
	{"gzip", "application/gzip", []byte{0x1F, 0x8B}, 0},
	// Documents
	{"pdf", "application/pdf", []byte{'%', 'P', 'D', 'F'}, 0},
	{"rtf", "application/rtf", []byte{'{', '\\', 'r', 't', 'f'}, 0},
	// Databases / registry / logs / captures
	{"regf", "application/x-ms-registry", []byte{'r', 'e', 'g', 'f'}, 0},
	{"prefetch_mam", "application/x-ms-prefetch", []byte{'M', 'A', 'M', 0x04}, 0},
	{"pcapng", "application/x-pcapng", []byte{0x0A, 0x0D, 0x0D, 0x0A}, 0},
	{"pcap_le", "application/vnd.tcpdump.pcap", []byte{0xD4, 0xC3, 0xB2, 0xA1}, 0},
	{"pcap_be", "application/vnd.tcpdump.pcap", []byte{0xA1, 0xB2, 0xC3, 0xD4}, 0},
	// Media
	{"matroska", "video/x-matroska", []byte{0x1A, 0x45, 0xDF, 0xA3}, 0}, // mkv/webm
	{"flac", "audio/flac", []byte{'f', 'L', 'a', 'C'}, 0},
	{"ogg", "application/ogg", []byte{'O', 'g', 'g', 'S'}, 0},
	{"mp3", "audio/mpeg", []byte{'I', 'D', '3'}, 0},
	{"mp4", "video/mp4", []byte{'f', 't', 'y', 'p'}, 4}, // also mov/m4a/heic (ISO-BMFF)
	{"riff", "application/x-riff", []byte{'R', 'I', 'F', 'F'}, 0}, // refined to wav/avi/webp below
	{"pe", "application/vnd.microsoft.portable-executable", []byte{0x4D, 0x5A}, 0},
}

func detectMagic(data []byte) (string, string, string) {
	for _, def := range fileSignatures {
		off := def.offset
		if off+len(def.sig) > len(data) || !bytesEqual(data[off:off+len(def.sig)], def.sig) {
			continue
		}
		typ := def.typ
		if typ == "riff" && len(data) >= 12 { // refine RIFF container by its form type
			switch string(data[8:12]) {
			case "WAVE":
				typ = "wav"
			case "AVI ":
				typ = "avi"
			case "WEBP":
				typ = "webp"
			}
		}
		return typ, def.mime, strings.ToUpper(hex.EncodeToString(def.sig))
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
	for _, def := range fileSignatures {
		if def.typ == name {
			return def.sig, true
		}
	}
	return nil, false
}

// carveTypes lists the distinct signature type names, for error messages.
func carveTypes() []string {
	out := make([]string, 0, len(fileSignatures))
	for _, def := range fileSignatures {
		out = append(out, def.typ)
	}
	sort.Strings(out)
	return out
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
