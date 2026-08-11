package builtin

import (
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mutant/object"
)

func DetectPersistence(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	facts, ok := args[0].(*object.Hash)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_persistence` must be HASH, got %s", args[0].Type()))
	}

	suspicious := make([]object.Object, 0)
	for _, field := range []string{"autorun_keys", "startup_files", "scheduled_tasks"} {
		if arr, ok := detectHashArrayByKey(facts, field); ok {
			for _, entry := range arr.Elements {
				strObj, ok := entry.(*object.String)
				if !ok {
					continue
				}
				value := strings.ToLower(strObj.Value)
				if strings.Contains(value, "runonce") || strings.Contains(value, "appdata") || strings.Contains(value, "temp") || strings.Contains(value, "powershell") {
					suspicious = append(suspicious, makeHashObject(map[string]object.Object{
						"category": stringObj(field),
						"entry":    stringObj(strObj.Value),
					}))
				}
			}
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"detected": boolObj(len(suspicious) > 0),
		"count":    intObj(int64(len(suspicious))),
		"hits":     &object.Array{Elements: suspicious},
	}), nil)
}

func DetectInjection(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	facts, ok := args[0].(*object.Hash)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_injection` must be HASH, got %s", args[0].Type()))
	}
	pathObj, ok := detectHashStringByKey(facts, "mem_path")
	if !ok {
		return resultAndError(nil, newError("detect_injection requires facts.mem_path STRING"))
	}

	data, err := os.ReadFile(pathObj)
	if err != nil {
		return resultAndError(nil, newError("detect_injection: %s", err.Error()))
	}

	reasons := make([]object.Object, 0)
	matched := make([]object.Object, 0)
	score := int64(0)
	shellHits := 0

	mzOffsets := carveOffsets(data, []byte{0x4d, 0x5a})
	if len(mzOffsets) > 1 {
		score += 40
		reasons = append(reasons, stringObj("multiple_pe_headers"))
	}

	for _, s := range injectionSignatures {
		hits := len(carveOffsets(data, s.sig))
		if hits > 0 {
			score += s.weight
			shellHits += hits
			matched = append(matched, makeHashObject(map[string]object.Object{
				"name":  stringObj(s.name),
				"count": intObj(int64(hits)),
			}))
		}
	}

	// GetPC via "call $+5; pop reg" — a position-independent-code hallmark that a
	// fixed byte signature can't capture (the pop register varies).
	if n := countCallPopGetPC(data); n > 0 {
		score += 30
		shellHits += n
		matched = append(matched, makeHashObject(map[string]object.Object{
			"name":  stringObj("getpc_call_pop"),
			"count": intObj(int64(n)),
		}))
	}

	// A long NOP sled is a classic exploit landing pad. Require a substantial run
	// so incidental 0x90 bytes in normal data don't trigger it.
	if run := longestByteRun(data, 0x90); run >= 16 {
		score += 25
		reasons = append(reasons, stringObj("nop_sled"))
		matched = append(matched, makeHashObject(map[string]object.Object{
			"name":  stringObj("nop_sled"),
			"count": intObj(int64(run)),
		}))
	}

	if shellHits > 0 {
		reasons = append(reasons, stringObj("shellcode_signatures"))
	}
	if score > 100 {
		score = 100
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"detected":           boolObj(score >= 60),
		"score":              intObj(score),
		"pe_headers":         intObj(int64(len(mzOffsets))),
		"shellcode_hits":     intObj(int64(shellHits)),
		"matched_signatures": &object.Array{Elements: matched},
		"reasons":            &object.Array{Elements: reasons},
	}), nil)
}

// injectionSignature is a named, weighted byte pattern characteristic of
// shellcode / injected code. Weights feed the injection score (capped at 100).
type injectionSignature struct {
	name   string
	weight int64
	sig    []byte
}

var injectionSignatures = []injectionSignature{
	{name: "getpc_fnstenv", weight: 30, sig: []byte{0xd9, 0x74, 0x24, 0xf4}},                             // fnstenv [esp-0Ch] GetPC
	{name: "peb_walk_x86", weight: 25, sig: []byte{0x64, 0xa1, 0x30, 0x00, 0x00, 0x00}},                  // mov eax, fs:[0x30]
	{name: "peb_walk_x64", weight: 25, sig: []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}}, // mov rax, gs:[0x60]
	{name: "classic_prologue", weight: 20, sig: []byte{0xfc, 0xe8}},                                      // cld; call
	{name: "xor_push", weight: 15, sig: []byte{0x31, 0xc0, 0x50, 0x68}},                                  // xor eax,eax; push eax; push imm
}

// countCallPopGetPC counts "call $+5; pop reg" GetPC sequences (E8 00000000
// followed by a POP of any 32-bit register, opcodes 0x58–0x5F).
func countCallPopGetPC(data []byte) int {
	count := 0
	sig := []byte{0xe8, 0x00, 0x00, 0x00, 0x00}
	for _, off := range carveOffsets(data, sig) {
		next := off + len(sig)
		if next < len(data) && data[next] >= 0x58 && data[next] <= 0x5f {
			count++
		}
	}
	return count
}

// longestByteRun returns the length of the longest consecutive run of b.
func longestByteRun(data []byte, b byte) int {
	best, cur := 0, 0
	for _, x := range data {
		if x == b {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 0
		}
	}
	return best
}

func DetectNetworkBeacon(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	flows, ok := args[0].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_network_beacon` must be ARRAY, got %s", args[0].Type()))
	}

	byDst := map[string]*beaconStat{}
	order := make([]string, 0)
	for idx, flowObj := range flows.Elements {
		flow, ok := flowObj.(*object.Hash)
		if !ok {
			return resultAndError(nil, newError("flow at index %d must be HASH", idx))
		}
		dst, ok := detectHashStringByKey(flow, "dst")
		if !ok {
			return resultAndError(nil, newError("flow at index %d missing STRING dst", idx))
		}
		key := strings.ToLower(dst)
		st := byDst[key]
		if st == nil {
			st = &beaconStat{}
			byDst[key] = st
			order = append(order, key)
		}
		st.count++
		if ts, ok := detectEventTimestamp(flow); ok {
			st.times = append(st.times, ts)
		}
		if sz, ok := detectEventBytes(flow); ok {
			st.sizes = append(st.sizes, sz)
		}
	}

	sort.Strings(order)
	hits := make([]object.Object, 0)
	for _, dst := range order {
		if summary, isBeacon := beaconSummary(dst, byDst[dst]); isBeacon {
			hits = append(hits, summary)
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"detected": boolObj(len(hits) > 0),
		"hits":     &object.Array{Elements: hits},
	}), nil)
}

type beaconStat struct {
	count int64
	times []float64 // event timestamps, epoch seconds
	sizes []float64 // per-event byte counts (optional)
}

// beaconSummary scores how beacon-like a destination's traffic is. With enough
// timestamps it analyzes the regularity of inter-arrival intervals (low
// coefficient of variation ⇒ periodic ⇒ beacon-like), optionally reinforced by
// consistent transfer sizes. Without timestamps it falls back to a weak,
// low-confidence frequency signal.
func beaconSummary(dst string, st *beaconStat) (object.Object, bool) {
	reasons := make([]string, 0)
	var intervalMean, intervalStddev, intervalCV, bytesCV float64
	score := int64(0)
	confidence := "low"

	haveTiming := len(st.times) >= 4
	if haveTiming {
		times := append([]float64(nil), st.times...)
		sort.Float64s(times)
		intervals := make([]float64, 0, len(times)-1)
		for i := 1; i < len(times); i++ {
			if d := times[i] - times[i-1]; d >= 0 {
				intervals = append(intervals, d)
			}
		}
		intervalMean = meanFloat(intervals)
		intervalStddev = stddevFloat(intervals, intervalMean)
		if intervalMean > 0 {
			intervalCV = intervalStddev / intervalMean
			if reg := 1.0 - intervalCV; reg > 0 {
				score = int64(reg * 100)
			}
			if intervalCV <= 0.3 {
				reasons = append(reasons, "regular_interval")
			}
		}
	} else if st.count >= 3 {
		reasons = append(reasons, "high_frequency")
		score = 50
	}

	if len(st.sizes) >= 3 {
		if m := meanFloat(st.sizes); m > 0 {
			bytesCV = stddevFloat(st.sizes, m) / m
			if bytesCV <= 0.1 {
				reasons = append(reasons, "consistent_size")
				score += 10
			}
		}
	}
	if score > 100 {
		score = 100
	}

	switch {
	case haveTiming && st.count >= 8 && intervalCV <= 0.15:
		confidence = "high"
	case haveTiming && st.count >= 4 && intervalCV <= 0.3:
		confidence = "medium"
	}

	detected := st.count >= 3
	if haveTiming {
		detected = score >= 70 && st.count >= 4
	}

	summary := makeHashObject(map[string]object.Object{
		"dst":               stringObj(dst),
		"count":             intObj(st.count),
		"score":             intObj(score),
		"confidence":        stringObj(confidence),
		"interval_mean_s":   &object.Float{Value: intervalMean},
		"interval_stddev_s": &object.Float{Value: intervalStddev},
		"interval_cv":       &object.Float{Value: intervalCV},
		"bytes_cv":          &object.Float{Value: bytesCV},
		"reasons":           detectStringArray(reasons),
	})
	return summary, detected
}

// detectEventTimestamp reads a flow's "ts" field as epoch seconds. It accepts an
// INTEGER/FLOAT (epoch seconds) or an RFC3339 STRING.
func detectEventTimestamp(flow *object.Hash) (float64, bool) {
	obj, ok := detectHashValueByKey(flow, "ts")
	if !ok {
		return 0, false
	}
	switch v := obj.(type) {
	case *object.Integer:
		return float64(v.Value), true
	case *object.Float:
		return v.Value, true
	case *object.String:
		if t, err := time.Parse(time.RFC3339Nano, v.Value); err == nil {
			return float64(t.UnixNano()) / 1e9, true
		}
		if t, err := time.Parse(time.RFC3339, v.Value); err == nil {
			return float64(t.Unix()), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// detectEventBytes reads a flow's optional "bytes" field as a number.
func detectEventBytes(flow *object.Hash) (float64, bool) {
	obj, ok := detectHashValueByKey(flow, "bytes")
	if !ok {
		return 0, false
	}
	switch v := obj.(type) {
	case *object.Integer:
		return float64(v.Value), true
	case *object.Float:
		return v.Value, true
	default:
		return 0, false
	}
}

func meanFloat(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// stddevFloat returns the sample standard deviation of xs.
func stddevFloat(xs []float64, mean float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var ss float64
	for _, x := range xs {
		d := x - mean
		ss += d * d
	}
	return math.Sqrt(ss / float64(len(xs)-1))
}

func detectStringArray(items []string) *object.Array {
	objs := make([]object.Object, len(items))
	for i, s := range items {
		objs[i] = stringObj(s)
	}
	return &object.Array{Elements: objs}
}

func DetectPrivEsc(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	facts, ok := args[0].(*object.Hash)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_priv_esc` must be HASH, got %s", args[0].Type()))
	}

	checks := []string{"token_theft", "uac_bypass", "lsass_access", "se_debug_enabled"}
	hits := make([]object.Object, 0)
	for _, check := range checks {
		if valObj, ok := detectHashValueByKey(facts, check); ok {
			if b, ok := valObj.(*object.Boolean); ok && b.Value {
				hits = append(hits, stringObj(check))
			}
		}
	}

	score := int64(len(hits) * 25)
	if score > 100 {
		score = 100
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"detected": boolObj(len(hits) > 0),
		"score":    intObj(score),
		"signals":  &object.Array{Elements: hits},
	}), nil)
}

func DetectSuspiciousFiles(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	pathsObj, ok := args[0].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `detect_suspicious_files` must be ARRAY, got %s", args[0].Type()))
	}

	hits := make([]object.Object, 0)
	for idx, pObj := range pathsObj.Elements {
		pathStr, ok := pObj.(*object.String)
		if !ok {
			return resultAndError(nil, newError("path at index %d must be STRING", idx))
		}
		data, err := os.ReadFile(pathStr.Value)
		if err != nil {
			continue
		}
		ent := shannonEntropy(data)
		typ, _, _ := detectMagic(data)
		lowerPath := strings.ToLower(pathStr.Value)
		ext := filepath.Ext(lowerPath)
		reasons := make([]string, 0)
		if ent > 7.8 {
			reasons = append(reasons, "very_high_entropy")
		} else if ent > 7.2 {
			reasons = append(reasons, "high_entropy")
		}
		if (typ == "pe" || typ == "elf") && documentExtensions[ext] {
			reasons = append(reasons, "extension_mismatch")
		}
		if hasDoubleExecutableExtension(filepath.Base(lowerPath)) {
			reasons = append(reasons, "double_extension")
		}
		if len(reasons) > 0 {
			reasonObjs := make([]object.Object, len(reasons))
			for i, r := range reasons {
				reasonObjs[i] = stringObj(r)
			}
			hits = append(hits, makeHashObject(map[string]object.Object{
				"path":    stringObj(pathStr.Value),
				"entropy": &object.Float{Value: ent},
				"type":    stringObj(typ),
				"reasons": &object.Array{Elements: reasonObjs},
			}))
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"detected": boolObj(len(hits) > 0),
		"count":    intObj(int64(len(hits))),
		"hits":     &object.Array{Elements: hits},
	}), nil)
}

// documentExtensions are non-executable extensions a file masquerading as benign
// content would use; an executable magic under one of these is a mismatch.
var documentExtensions = map[string]bool{
	".txt": true, ".log": true, ".csv": true, ".pdf": true, ".doc": true, ".docx": true,
	".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true, ".rtf": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
	".json": true, ".xml": true, ".html": true, ".htm": true,
}

// executableExtensions are extensions that run code on common platforms.
var executableExtensions = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".com": true, ".bat": true, ".cmd": true,
	".ps1": true, ".vbs": true, ".js": true, ".jar": true, ".msi": true, ".pif": true,
}

// hasDoubleExecutableExtension flags names like "invoice.pdf.exe" where an
// executable extension hides behind a document-looking one.
func hasDoubleExecutableExtension(base string) bool {
	ext := filepath.Ext(base)
	if !executableExtensions[ext] {
		return false
	}
	prev := filepath.Ext(strings.TrimSuffix(base, ext))
	return documentExtensions[prev]
}

func detectHashValueByKey(hash *object.Hash, key string) (object.Object, bool) {
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		return nil, false
	}
	return pair.Value, true
}

func detectHashStringByKey(hash *object.Hash, key string) (string, bool) {
	obj, ok := detectHashValueByKey(hash, key)
	if !ok {
		return "", false
	}
	strObj, ok := obj.(*object.String)
	if !ok {
		return "", false
	}
	return strObj.Value, true
}

func detectHashArrayByKey(hash *object.Hash, key string) (*object.Array, bool) {
	obj, ok := detectHashValueByKey(hash, key)
	if !ok {
		return nil, false
	}
	arr, ok := obj.(*object.Array)
	return arr, ok
}
