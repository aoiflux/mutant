package builtin

import (
	"os"
	"strings"

	"github.com/mandiant/GoReSym/buildid"
	"github.com/mandiant/GoReSym/buildinfo"
	"github.com/mandiant/GoReSym/objfile"

	"mutant/object"
)

// The go_* builtins recover metadata from Go-compiled binaries (PE/ELF/Mach-O)
// using Mandiant's GoReSym, including symbol recovery from *stripped* binaries via
// the pclntab. Parsing untrusted binaries can panic inside the parser, so each
// entry point recovers and returns an honest error instead of crashing the VM.

func GoBuildInfo(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("go_buildinfo: panic during analysis: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("go_buildinfo", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("go_buildinfo: %s", err.Error()))
	}

	deps := make([]object.Object, 0, len(bi.Deps))
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		deps = append(deps, makeHashObject(map[string]object.Object{
			"path":    stringObj(d.Path),
			"version": stringObj(d.Version),
			"sum":     stringObj(d.Sum),
		}))
	}

	settings := make(map[string]object.Object, len(bi.Settings))
	for _, s := range bi.Settings {
		settings[s.Key] = stringObj(s.Value)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"go_version": stringObj(bi.GoVersion),
		"path":       stringObj(bi.Path),
		"main": makeHashObject(map[string]object.Object{
			"path":    stringObj(bi.Main.Path),
			"version": stringObj(bi.Main.Version),
			"sum":     stringObj(bi.Main.Sum),
		}),
		"deps":     &object.Array{Elements: deps},
		"settings": makeHashObject(settings),
	}), nil)
}

func GoBuildID(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("go_build_id: panic during analysis: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("go_build_id", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	id, err := buildid.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("go_build_id: %s", err.Error()))
	}
	return resultAndError(stringObj(id), nil)
}

func GoSymbols(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("go_symbols: panic during analysis: %v", r))
		}
	}()

	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	path, errObj := requireStringArg("go_symbols", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	mode := "all"
	if len(args) == 2 {
		m, errObj := requireStringArg("go_symbols", args[1], 2)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		switch m {
		case "all", "user", "std":
			mode = m
		default:
			return resultAndError(nil, newError("go_symbols: mode must be \"all\", \"user\", or \"std\", got %q", m))
		}
	}

	file, err := objfile.Open(path)
	if err != nil {
		return resultAndError(nil, newError("go_symbols: %s", err.Error()))
	}
	defer file.Close()

	// Recover Go version / arch / os from build info where available.
	version, osName, arch := "", "", file.GOARCH()
	if bi, biErr := buildinfo.ReadFile(path); biErr == nil {
		version = bi.GoVersion
		for _, s := range bi.Settings {
			switch s.Key {
			case "GOOS":
				osName = s.Value
			case "GOARCH":
				arch = s.Value
			}
		}
	}
	version = normalizeGoVersion(version)

	tabs, err := file.PCLineTable("")
	if err != nil {
		return resultAndError(nil, newError("go_symbols: failed to read pclntab: %s", err.Error()))
	}
	if len(tabs) == 0 {
		return resultAndError(nil, newError("go_symbols: no pclntab candidates found (not a Go binary?)"))
	}

	// Pick the pclntab candidate whose VA resolves a valid moduledata (as GoReSym
	// does): a correct moduledata implies the correct pclntab.
	finalTab := &tabs[0]
	for i := range tabs {
		tab := &tabs[i]
		if tab.ParsedPclntab == nil || tab.ParsedPclntab.Go12line == nil {
			continue
		}
		line := tab.ParsedPclntab.Go12line
		is64 := line.Ptrsize == 8
		littleEndian := line.Binary.String() == "LittleEndian"
		_, moduleData, mdErr := file.ModuleDataTable(tab.PclntabVA, version, line.Version.String(), is64, littleEndian)
		if mdErr == nil && moduleData != nil {
			finalTab = tab
			break
		}
	}

	if finalTab.ParsedPclntab == nil {
		return resultAndError(nil, newError("go_symbols: could not parse a valid pclntab"))
	}

	funcs := make([]object.Object, 0, len(finalTab.ParsedPclntab.Funcs))
	userCount, stdCount := 0, 0
	for _, fn := range finalTab.ParsedPclntab.Funcs {
		pkg := fn.PackageName()
		std := isStdlibPackage(pkg)
		if std {
			stdCount++
		} else {
			userCount++
		}
		if mode == "user" && std {
			continue
		}
		if mode == "std" && !std {
			continue
		}
		funcs = append(funcs, makeHashObject(map[string]object.Object{
			"name":    stringObj(fn.Name),
			"package": stringObj(pkg),
			"start":   intObj(int64(fn.Entry)),
			"end":     intObj(int64(fn.End)),
			"stdlib":  boolObj(std),
		}))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"go_version":          stringObj(version),
		"arch":                stringObj(arch),
		"os":                  stringObj(osName),
		"pclntab_va":          intObj(int64(finalTab.PclntabVA)),
		"function_count":      intObj(int64(len(finalTab.ParsedPclntab.Funcs))),
		"user_function_count": intObj(int64(userCount)),
		"std_function_count":  intObj(int64(stdCount)),
		"functions":           &object.Array{Elements: funcs},
	}), nil)
}

// BinIsGo reports whether a binary was produced by the Go toolchain, a common
// malware-triage question. It checks three independent signals: the embedded Go
// build info blob, the Go build ID, and — the definitive one that survives
// stripping — the presence of a parseable pclntab (the Go runtime's function
// table). Returns {is_go, go_version, has_buildinfo, has_build_id, has_pclntab}.
func BinIsGo(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("bin_is_go: panic during analysis: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("bin_is_go", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if _, err := os.Stat(path); err != nil {
		return resultAndError(nil, newError("bin_is_go: %s", err.Error()))
	}

	hasBuildInfo, goVersion := false, ""
	if bi, err := buildinfo.ReadFile(path); err == nil {
		hasBuildInfo = true
		goVersion = bi.GoVersion
	}

	hasBuildID := false
	if id, err := buildid.ReadFile(path); err == nil && id != "" {
		hasBuildID = true
	}

	hasPclntab := false
	if file, err := objfile.Open(path); err == nil {
		if tabs, terr := file.PCLineTable(""); terr == nil {
			for i := range tabs {
				if tabs[i].ParsedPclntab != nil {
					hasPclntab = true
					break
				}
			}
		}
		file.Close()
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"is_go":         boolObj(hasBuildInfo || hasPclntab),
		"go_version":    stringObj(normalizeGoVersion(goVersion)),
		"has_buildinfo": boolObj(hasBuildInfo),
		"has_build_id":  boolObj(hasBuildID),
		"has_pclntab":   boolObj(hasPclntab),
	}), nil)
}

// GoTypes recovers type and interface definitions from a Go binary via GoReSym's
// typelink/itablink parsing — including reconstructed Go source for structs and
// interfaces where GoReSym can rebuild it. Returns {go_version, type_count,
// itab_count, types:[{va, name, kind, reconstructed}], itabs:[...]}.
func GoTypes(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("go_types: panic during analysis: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("go_types", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	file, err := objfile.Open(path)
	if err != nil {
		return resultAndError(nil, newError("go_types: %s", err.Error()))
	}
	defer file.Close()

	version := ""
	if bi, biErr := buildinfo.ReadFile(path); biErr == nil {
		version = bi.GoVersion
	}
	version = normalizeGoVersion(version)

	tabs, err := file.PCLineTable("")
	if err != nil {
		return resultAndError(nil, newError("go_types: failed to read pclntab: %s", err.Error()))
	}
	if len(tabs) == 0 {
		return resultAndError(nil, newError("go_types: no pclntab candidates found (not a Go binary?)"))
	}

	// Resolve the moduledata (type metadata lives behind it), mirroring go_symbols'
	// candidate selection.
	var md *objfile.ModuleData
	var is64, littleEndian bool
	for i := range tabs {
		tab := &tabs[i]
		if tab.ParsedPclntab == nil || tab.ParsedPclntab.Go12line == nil {
			continue
		}
		line := tab.ParsedPclntab.Go12line
		i64 := line.Ptrsize == 8
		le := line.Binary.String() == "LittleEndian"
		_, moduleData, mdErr := file.ModuleDataTable(tab.PclntabVA, version, line.Version.String(), i64, le)
		if mdErr == nil && moduleData != nil {
			md, is64, littleEndian = moduleData, i64, le
			break
		}
	}
	if md == nil {
		return resultAndError(nil, newError("go_types: could not resolve moduledata (type metadata unavailable)"))
	}

	typesToObjs := func(ts []objfile.Type) []object.Object {
		out := make([]object.Object, 0, len(ts))
		for _, tp := range ts {
			out = append(out, makeHashObject(map[string]object.Object{
				"va":            intObj(int64(tp.VA)),
				"name":          stringObj(tp.Str),
				"kind":          stringObj(tp.Kind),
				"reconstructed": stringObj(tp.Reconstructed),
			}))
		}
		return out
	}

	typeLinks, tErr := file.ParseTypeLinks(version, md, is64, littleEndian)
	itabLinks, iErr := file.ParseITabLinks(version, md, is64, littleEndian)
	if tErr != nil && iErr != nil {
		return resultAndError(nil, newError("go_types: type parsing failed: %s", tErr.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"go_version": stringObj(version),
		"type_count": intObj(int64(len(typeLinks))),
		"itab_count": intObj(int64(len(itabLinks))),
		"types":      &object.Array{Elements: typesToObjs(typeLinks)},
		"itabs":      &object.Array{Elements: typesToObjs(itabLinks)},
	}), nil)
}

// normalizeGoVersion reduces strings like "go1.21.3" or "devel go1.22-abc ..." to
// a numeric "1.21.3" form (matching GoReSym's ModuleDataTable expectation).
func normalizeGoVersion(v string) string {
	idx := strings.Index(v, "go")
	if idx == -1 {
		return v
	}
	v = strings.SplitN(v[idx+2:]+" ", " ", 2)[0]
	v = strings.SplitN(v+"-", "-", 2)[0]
	return v
}

// isStdlibPackage classifies a recovered package as Go standard library. This is
// a heuristic: third-party packages are domain-qualified (a dot in the first path
// segment, e.g. "github.com/x/y"), `main` is the program itself, and everything
// else (fmt, runtime, net/http, blank runtime internals) is treated as stdlib.
func isStdlibPackage(pkg string) bool {
	if pkg == "" {
		return true
	}
	if pkg == "main" {
		return false
	}
	first := pkg
	if i := strings.IndexByte(pkg, '/'); i >= 0 {
		first = pkg[:i]
	}
	return !strings.Contains(first, ".")
}
