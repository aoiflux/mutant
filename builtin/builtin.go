package builtin

import (
	"fmt"
	"mutant/global"
	"runtime"
	"strings"
	"unicode"

	"mutant/object"
)

type BuiltinFunction func(args ...object.Object) object.Object
type BuiltIn struct{ Fn BuiltinFunction }
type BuiltinDefinition struct {
	Name    string
	Builtin *BuiltIn
}

func (b *BuiltIn) Type() object.ObjectType { return object.BUILTIN_OBJ }
func (b *BuiltIn) Inspect() string         { return "builtin funciton" }

var Builtins = []BuiltinDefinition{
	{BuiltinNameLen, &BuiltIn{Len}},
	{BuiltinNamePutf, &BuiltIn{Putf}},
	{BuiltinNamePutln, &BuiltIn{Putln}},
	{BuiltinNameGets, &BuiltIn{Gets}},
	{BuiltinNameFirst, &BuiltIn{First}},
	{BuiltinNameLast, &BuiltIn{Last}},
	{BuiltinNameRest, &BuiltIn{Rest}},
	{BuiltinNamePush, &BuiltIn{Push}},
	{BuiltinNamePop, &BuiltIn{Pop}},
	// text matching
	{BuiltinNameTextContains, &BuiltIn{TextContains}},
	{BuiltinNameTextIndex, &BuiltIn{TextIndex}},
	{BuiltinNameTextCount, &BuiltIn{TextCount}},
	{BuiltinNameTextSplit, &BuiltIn{TextSplit}},
	{BuiltinNameTextReplace, &BuiltIn{TextReplace}},
	// fuzzy matching
	{BuiltinNameTextLevenshtein, &BuiltIn{TextLevenshtein}},
	{BuiltinNameTextSimilarity, &BuiltIn{TextSimilarity}},
	{BuiltinNameTextFuzzyFind, &BuiltIn{TextFuzzyFind}},
	{BuiltinNameTextJaroWinkler, &BuiltIn{TextJaroWinkler}},
	// regex
	{BuiltinNameRegexMatch, &BuiltIn{RegexMatch}},
	{BuiltinNameRegexFind, &BuiltIn{RegexFind}},
	{BuiltinNameRegexFindAll, &BuiltIn{RegexFindAll}},
	{BuiltinNameRegexReplace, &BuiltIn{RegexReplace}},
	{BuiltinNameRegexCaptureGroups, &BuiltIn{RegexCaptureGroups}},
	// policy engine
	{BuiltinNamePolicyEval, &BuiltIn{PolicyEval}},
	{BuiltinNamePolicyAllow, &BuiltIn{PolicyAllow}},
	{BuiltinNamePolicyRules, &BuiltIn{PolicyRules}},
	{BuiltinNamePolicyTrace, &BuiltIn{PolicyTrace}},
	{BuiltinNamePolicyLoad, &BuiltIn{PolicyLoad}},
	// cache
	{BuiltinNameCacheOpen, &BuiltIn{CacheOpen}},
	{BuiltinNameCachePut, &BuiltIn{CachePut}},
	{BuiltinNameCacheGet, &BuiltIn{CacheGet}},
	{BuiltinNameCacheDelete, &BuiltIn{CacheDelete}},
	{BuiltinNameCacheKeys, &BuiltIn{CacheKeys}},
	{BuiltinNameCacheStats, &BuiltIn{CacheStats}},
	{BuiltinNameCacheClear, &BuiltIn{CacheClear}},
	{BuiltinNameCacheClose, &BuiltIn{CacheClose}},
	// system forensics
	{BuiltinNameProcessList, &BuiltIn{ProcessList}},
	{BuiltinNameProcessTree, &BuiltIn{ProcessTree}},
	{BuiltinNameProcessOpenFiles, &BuiltIn{ProcessOpenFiles}},
	{BuiltinNameProcessThreads, &BuiltIn{ProcessThreads}},
	{BuiltinNameProcessModules, &BuiltIn{ProcessModules}},
	{BuiltinNameProcessHash, &BuiltIn{ProcessHash}},
	{BuiltinNameProcessMemoryScan, &BuiltIn{ProcessMemoryScan}},
	{BuiltinNameProcessEnv, &BuiltIn{ProcessEnv}},
	{BuiltinNameProcessKill, &BuiltIn{ProcessKill}},
	{BuiltinNameDebugStatus, &BuiltIn{DebugStatus}},
	{BuiltinNameSandboxStatus, &BuiltIn{SandboxStatus}},
	{BuiltinNameSecurityDiagnostics, &BuiltIn{SecurityDiagnostics}},
	{BuiltinNameExecString, &BuiltIn{ExecString}},
	{BuiltinNameCmdBuilder, &BuiltIn{CmdBuilder}},
	{BuiltinNameCmdAdd, &BuiltIn{CmdAdd}},
	{BuiltinNameCmdRun, &BuiltIn{CmdRun}},
	// file system
	{BuiltinNameFsRead, &BuiltIn{FsRead}},
	{BuiltinNameFsWrite, &BuiltIn{FsWrite}},
	{BuiltinNameFsAppend, &BuiltIn{FsAppend}},
	{BuiltinNameFsDelete, &BuiltIn{FsDelete}},
	{BuiltinNameFsExists, &BuiltIn{FsExists}},
	{BuiltinNameFsStat, &BuiltIn{FsStat}},
	{BuiltinNameFsList, &BuiltIn{FsList}},
	{BuiltinNameFsMkdir, &BuiltIn{FsMkdir}},
	{BuiltinNameFsCopy, &BuiltIn{FsCopy}},
	{BuiltinNameFsMove, &BuiltIn{FsMove}},
	// filesystem forensics
	{BuiltinNameFsHash, &BuiltIn{FsHash}},
	{BuiltinNameFsWalk, &BuiltIn{FsWalk}},
	{BuiltinNameFsMetadata, &BuiltIn{FsMetadata}},
	{BuiltinNameFsMagic, &BuiltIn{FsMagic}},
	{BuiltinNameFsExtractStrings, &BuiltIn{FsExtractStrings}},
	{BuiltinNameFsDiff, &BuiltIn{FsDiff}},
	{BuiltinNameFsCarve, &BuiltIn{FsCarve}},
	{BuiltinNameFsEntropy, &BuiltIn{FsEntropy}},
	// filesystem parsers
	{BuiltinNameNtfsOpen, &BuiltIn{NtfsOpen}},
	{BuiltinNameNtfsListFiles, &BuiltIn{NtfsListFiles}},
	{BuiltinNameNtfsReadFile, &BuiltIn{NtfsReadFile}},
	{BuiltinNameNtfsMetadata, &BuiltIn{NtfsMetadata}},
	{BuiltinNameNtfsClose, &BuiltIn{NtfsClose}},
	{BuiltinNameFatOpen, &BuiltIn{FatOpen}},
	{BuiltinNameFatListFiles, &BuiltIn{FatListFiles}},
	{BuiltinNameFatReadFile, &BuiltIn{FatReadFile}},
	{BuiltinNameFatMetadata, &BuiltIn{FatMetadata}},
	{BuiltinNameFatClose, &BuiltIn{FatClose}},
	{BuiltinNameXfatOpen, &BuiltIn{XFATOpen}},
	{BuiltinNameXfatListFiles, &BuiltIn{XFATListFiles}},
	{BuiltinNameXfatReadFile, &BuiltIn{XFATReadFile}},
	{BuiltinNameXfatMetadata, &BuiltIn{XFATMetadata}},
	{BuiltinNameXfatClose, &BuiltIn{XFATClose}},
	{BuiltinNameExtOpen, &BuiltIn{ExtOpen}},
	{BuiltinNameExtListFiles, &BuiltIn{ExtListFiles}},
	{BuiltinNameExtReadFile, &BuiltIn{ExtReadFile}},
	{BuiltinNameExtMetadata, &BuiltIn{ExtMetadata}},
	{BuiltinNameExtClose, &BuiltIn{ExtClose}},
	{BuiltinNameHfsOpen, &BuiltIn{HFSOpen}},
	{BuiltinNameHfsListFiles, &BuiltIn{HFSListFiles}},
	{BuiltinNameHfsReadFile, &BuiltIn{HFSReadFile}},
	{BuiltinNameHfsMetadata, &BuiltIn{HFSMetadata}},
	{BuiltinNameHfsClose, &BuiltIn{HFSClose}},
	{BuiltinNameXfsOpen, &BuiltIn{XFSOpen}},
	{BuiltinNameXfsListFiles, &BuiltIn{XFSListFiles}},
	{BuiltinNameXfsReadFile, &BuiltIn{XFSReadFile}},
	{BuiltinNameXfsMetadata, &BuiltIn{XFSMetadata}},
	{BuiltinNameXfsClose, &BuiltIn{XFSClose}},
	{BuiltinNameVhdiOpen, &BuiltIn{VHDIOpen}},
	{BuiltinNameVhdiMetadata, &BuiltIn{VHDIMetadata}},
	{BuiltinNameVhdiReadAt, &BuiltIn{VHDIReadAt}},
	{BuiltinNameVhdiMapOffset, &BuiltIn{VHDIMapOffset}},
	{BuiltinNameVhdiClose, &BuiltIn{VHDIClose}},
	{BuiltinNameEwfOpen, &BuiltIn{EWFOpen}},
	{BuiltinNameEwfMetadata, &BuiltIn{EWFMetadata}},
	{BuiltinNameEwfReadAt, &BuiltIn{EWFReadAt}},
	{BuiltinNameEwfClose, &BuiltIn{EWFClose}},
	{BuiltinNameRawOpen, &BuiltIn{RAWOpen}},
	{BuiltinNameRawMetadata, &BuiltIn{RAWMetadata}},
	{BuiltinNameRawReadAt, &BuiltIn{RAWReadAt}},
	{BuiltinNameRawClose, &BuiltIn{RAWClose}},
	{BuiltinNameTableOpen, &BuiltIn{TableOpen}},
	{BuiltinNameTableListPartitions, &BuiltIn{TableListPartitions}},
	{BuiltinNameTablePartitionInfo, &BuiltIn{TablePartitionInfo}},
	{BuiltinNameTableClose, &BuiltIn{TableClose}},
	// binary analysis
	{BuiltinNameBinPeParse, &BuiltIn{BinPEParse}},
	{BuiltinNameBinElfParse, &BuiltIn{BinELFParse}},
	{BuiltinNameBinDwarfParse, &BuiltIn{BinDWARFParse}},
	{BuiltinNameBinStrings, &BuiltIn{BinStrings}},
	{BuiltinNameBinEntropy, &BuiltIn{BinEntropy}},
	{BuiltinNameBinYaraScan, &BuiltIn{BinYaraScan}},
	{BuiltinNameBinImports, &BuiltIn{BinImports}},
	{BuiltinNameBinSections, &BuiltIn{BinSections}},
	// network
	{BuiltinNameNetResolve, &BuiltIn{NetResolve}},
	{BuiltinNameNetDial, &BuiltIn{NetDial}},
	{BuiltinNameNetSynScan, &BuiltIn{NetSynScan}},
	{BuiltinNameNetUdpScan, &BuiltIn{NetUDPScan}},
	{BuiltinNameNetBanner, &BuiltIn{NetBanner}},
	{BuiltinNameNetTlsFingerprint, &BuiltIn{NetTLSFingerprint}},
	{BuiltinNameNetDnsQuery, &BuiltIn{NetDNSQuery}},
	{BuiltinNameNetPcapAnalyze, &BuiltIn{NetPCAPAnalyze}},
	{BuiltinNameNetCaptureRaw, &BuiltIn{NetCaptureRaw}},
	{BuiltinNameNetFlowReconstruct, &BuiltIn{NetFlowReconstruct}},
	{BuiltinNameNetOsFingerprint, &BuiltIn{NetOSFingerprint}},
	// registry forensics
	{BuiltinNameRegOpen, &BuiltIn{RegOpen}},
	{BuiltinNameRegEnumKeys, &BuiltIn{RegEnumKeys}},
	{BuiltinNameRegEnumValues, &BuiltIn{RegEnumValues}},
	{BuiltinNameRegGetValue, &BuiltIn{RegGetValue}},
	{BuiltinNameRegDeletedKeys, &BuiltIn{RegDeletedKeys}},
	{BuiltinNameRegTimeline, &BuiltIn{RegTimeline}},
	{BuiltinNameRegClose, &BuiltIn{RegClose}},
	// email forensics
	{BuiltinNameEmailParse, &BuiltIn{EmailParse}},
	{BuiltinNameEmailHeaders, &BuiltIn{EmailHeaders}},
	{BuiltinNameEmailAttachments, &BuiltIn{EmailAttachments}},
	{BuiltinNameEmailSpfDkim, &BuiltIn{EmailSPFDKIM}},
	{BuiltinNameEmailUrls, &BuiltIn{EmailURLs}},
	// memory forensics
	{BuiltinNameMemMap, &BuiltIn{MemMap}},
	{BuiltinNameMemRead, &BuiltIn{MemRead}},
	{BuiltinNameMemScan, &BuiltIn{MemScan}},
	{BuiltinNameMemStrings, &BuiltIn{MemStrings}},
	{BuiltinNameMemFindPe, &BuiltIn{MemFindPE}},
	{BuiltinNameMemFindShellcode, &BuiltIn{MemFindShellcode}},
	// detection
	{BuiltinNameDetectPersistence, &BuiltIn{DetectPersistence}},
	{BuiltinNameDetectInjection, &BuiltIn{DetectInjection}},
	{BuiltinNameDetectNetworkBeacon, &BuiltIn{DetectNetworkBeacon}},
	{BuiltinNameDetectPrivEsc, &BuiltIn{DetectPrivEsc}},
	{BuiltinNameDetectSuspiciousFiles, &BuiltIn{DetectSuspiciousFiles}},
	// http
	{BuiltinNameHttpGet, &BuiltIn{HttpGet}},
	{BuiltinNameHttpPost, &BuiltIn{HttpPost}},
	{BuiltinNameHttpRequest, &BuiltIn{HttpRequest}},
	// json
	{BuiltinNameJsonStringify, &BuiltIn{JsonStringify}},
	{BuiltinNameJsonParse, &BuiltIn{JsonParse}},
	// lua
	{BuiltinNameLuaRunString, &BuiltIn{LuaRunString}},
	{BuiltinNameLuaRunFile, &BuiltIn{LuaRunFile}},
	{BuiltinNameLuaRunHttp, &BuiltIn{LuaRunHTTP}},
	// graph db
	{BuiltinNameDbOpen, &BuiltIn{DbOpen}},
	{BuiltinNameDbOpenDisk, &BuiltIn{DbOpenDisk}},
	{BuiltinNameDbClose, &BuiltIn{DbClose}},
	{BuiltinNameDbAddNode, &BuiltIn{DbAddNode}},
	{BuiltinNameDbAddEdge, &BuiltIn{DbAddEdge}},
	{BuiltinNameDbAddArtifact, &BuiltIn{DbAddArtifact}},
	{BuiltinNameDbAddRelation, &BuiltIn{DbAddRelation}},
	{BuiltinNameDbIndexProp, &BuiltIn{DbIndexProp}},
	{BuiltinNameDbQueryNodes, &BuiltIn{DbQueryNodes}},
	{BuiltinNameDbQuery, &BuiltIn{DbQuery}},
	{BuiltinNameDbBfs, &BuiltIn{DbBFS}},
	{BuiltinNameDbShortestPath, &BuiltIn{DbShortestPath}},
	{BuiltinNameDbTimeline, &BuiltIn{DbTimeline}},
	{BuiltinNameDbStats, &BuiltIn{DbStats}},
	// generic bytes/parser helpers
	{BuiltinNameBytesLen, &BuiltIn{BytesLen}},
	{BuiltinNameBytesGet, &BuiltIn{BytesGet}},
	{BuiltinNameBytesSlice, &BuiltIn{BytesSlice}},
	{BuiltinNameBytesReadU16Le, &BuiltIn{BytesReadU16LE}},
	{BuiltinNameBytesReadU16Be, &BuiltIn{BytesReadU16BE}},
	{BuiltinNameBytesReadU32Le, &BuiltIn{BytesReadU32LE}},
	{BuiltinNameBytesReadU32Be, &BuiltIn{BytesReadU32BE}},
	{BuiltinNameBytesReadU64Le, &BuiltIn{BytesReadU64LE}},
	{BuiltinNameBytesReadU64Be, &BuiltIn{BytesReadU64BE}},
	{BuiltinNameBytesWriteU16Le, &BuiltIn{BytesWriteU16LE}},
	{BuiltinNameBytesWriteU16Be, &BuiltIn{BytesWriteU16BE}},
	{BuiltinNameBytesWriteU32Le, &BuiltIn{BytesWriteU32LE}},
	{BuiltinNameBytesWriteU32Be, &BuiltIn{BytesWriteU32BE}},
	{BuiltinNameBytesWriteU64Le, &BuiltIn{BytesWriteU64LE}},
	{BuiltinNameBytesWriteU64Be, &BuiltIn{BytesWriteU64BE}},
	{BuiltinNameBytesCstrAt, &BuiltIn{BytesCStrAt}},
	{BuiltinNameBytesHex, &BuiltIn{BytesHex}},
	{BuiltinNameBytesCharFromInt, &BuiltIn{BytesCharFromInt}},
	{BuiltinNameBytesIntFromChar, &BuiltIn{BytesIntFromChar}},
	{BuiltinNameBytesCursorNew, &BuiltIn{BytesCursorNew}},
	{BuiltinNameBytesCursorTell, &BuiltIn{BytesCursorTell}},
	{BuiltinNameBytesCursorSeek, &BuiltIn{BytesCursorSeek}},
	{BuiltinNameBytesCursorEof, &BuiltIn{BytesCursorEOF}},
	{BuiltinNameBytesCursorReadU8, &BuiltIn{BytesCursorReadU8}},
	{BuiltinNameBytesCursorReadU16Le, &BuiltIn{BytesCursorReadU16LE}},
	{BuiltinNameBytesCursorReadU16Be, &BuiltIn{BytesCursorReadU16BE}},
	{BuiltinNameBytesCursorReadU32Le, &BuiltIn{BytesCursorReadU32LE}},
	{BuiltinNameBytesCursorReadU32Be, &BuiltIn{BytesCursorReadU32BE}},
	{BuiltinNameBytesCursorReadU64Le, &BuiltIn{BytesCursorReadU64LE}},
	{BuiltinNameBytesCursorReadU64Be, &BuiltIn{BytesCursorReadU64BE}},
}

var builtinsByName = buildBuiltinLookup()

func buildBuiltinLookup() map[string]*BuiltIn {
	lookup := make(map[string]*BuiltIn, len(Builtins))
	for _, entry := range Builtins {
		if entry.Name == "" {
			continue
		}
		if _, exists := lookup[entry.Name]; exists {
			continue
		}
		lookup[entry.Name] = entry.Builtin
	}
	return lookup
}

func GetBuiltinByName(name string) *BuiltIn {
	if fn, ok := builtinsByName[name]; ok {
		return fn
	}

	// Fall back to linear scan so callers that mutate Builtins at runtime still resolve.
	for _, fun := range Builtins {
		if name == fun.Name {
			return fun.Builtin
		}
	}
	return nil
}

func newError(format string, a ...any) *object.Error {
	context := "builtin"
	pcs := make([]uintptr, 16)
	n := runtime.Callers(2, pcs)
	if n > 0 {
		frames := runtime.CallersFrames(pcs[:n])
		for {
			frame, more := frames.Next()
			name := shortFunctionName(frame.Function)
			if strings.Contains(frame.Function, "mutant/builtin.") {
				if builtinName, ok := builtinNameFromFunctionName(name); ok {
					context = "builtin." + builtinName
					break
				}
			}
			if !more {
				break
			}
		}
	}
	return &object.Error{Message: fmt.Sprintf(format, a...), Context: context}
}

func shortFunctionName(name string) string {
	if idx := strings.LastIndex(name, "."); idx >= 0 && idx+1 < len(name) {
		return name[idx+1:]
	}
	return name
}

func builtinNameFromFunctionName(name string) (string, bool) {
	if name == "" || name == "newError" || strings.HasPrefix(name, "func") {
		return "", false
	}

	runes := []rune(name)
	if len(runes) == 0 || !unicode.IsUpper(runes[0]) {
		return "", false
	}

	if strings.HasPrefix(name, "Bin") && len(name) > len("Bin") {
		return camelToSnake(name[len("Bin"):]), true
	}

	return camelToSnake(name), true
}

func camelToSnake(in string) string {
	if in == "" {
		return ""
	}

	runes := []rune(in)
	var out []rune
	for i, r := range runes {
		if unicode.IsUpper(r) {
			if i > 0 {
				prev := runes[i-1]
				nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
				if unicode.IsLower(prev) || unicode.IsDigit(prev) || nextLower {
					out = append(out, '_')
				}
			}
			out = append(out, unicode.ToLower(r))
			continue
		}
		out = append(out, r)
	}

	return string(out)
}

func resultAndError(result object.Object, errObj *object.Error) object.Object {
	resultValue := result
	if resultValue == nil {
		resultValue = global.Null
	}

	errValue := object.Object(global.Null)
	if errObj != nil {
		errValue = errObj
	}
	return &object.MultiValue{Values: []object.Object{resultValue, errValue}}
}
