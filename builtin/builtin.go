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
func (b *BuiltIn) Inspect() string         { return "builtin function" }

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
	{BuiltinNameFsReadBytes, &BuiltIn{FsReadBytes}},
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
	{BuiltinNameNtfsReadFileBytes, &BuiltIn{NtfsReadFileBytes}},
	{BuiltinNameNtfsExtractFile, &BuiltIn{NtfsExtractFile}},
	{BuiltinNameNtfsHashFile, &BuiltIn{NtfsHashFile}},
	{BuiltinNameNtfsReadFileAt, &BuiltIn{NtfsReadFileAt}},
	{BuiltinNameNtfsMetadata, &BuiltIn{NtfsMetadata}},
	{BuiltinNameNtfsVerify, &BuiltIn{NtfsVerify}},
	{BuiltinNameNtfsClose, &BuiltIn{NtfsClose}},
	{BuiltinNameFatOpen, &BuiltIn{FatOpen}},
	{BuiltinNameFatListFiles, &BuiltIn{FatListFiles}},
	{BuiltinNameFatReadFile, &BuiltIn{FatReadFile}},
	{BuiltinNameFatReadFileBytes, &BuiltIn{FatReadFileBytes}},
	{BuiltinNameFatExtractFile, &BuiltIn{FatExtractFile}},
	{BuiltinNameFatHashFile, &BuiltIn{FatHashFile}},
	{BuiltinNameFatReadFileAt, &BuiltIn{FatReadFileAt}},
	{BuiltinNameFatMetadata, &BuiltIn{FatMetadata}},
	{BuiltinNameFatVerify, &BuiltIn{FatVerify}},
	{BuiltinNameFatClose, &BuiltIn{FatClose}},
	{BuiltinNameXfatOpen, &BuiltIn{XFATOpen}},
	{BuiltinNameXfatListFiles, &BuiltIn{XFATListFiles}},
	{BuiltinNameXfatReadFile, &BuiltIn{XFATReadFile}},
	{BuiltinNameXfatReadFileBytes, &BuiltIn{XFATReadFileBytes}},
	{BuiltinNameXfatExtractFile, &BuiltIn{XFATExtractFile}},
	{BuiltinNameXfatHashFile, &BuiltIn{XFATHashFile}},
	{BuiltinNameXfatReadFileAt, &BuiltIn{XFATReadFileAt}},
	{BuiltinNameXfatMetadata, &BuiltIn{XFATMetadata}},
	{BuiltinNameXfatVerify, &BuiltIn{XFATVerify}},
	{BuiltinNameXfatClose, &BuiltIn{XFATClose}},
	{BuiltinNameExtOpen, &BuiltIn{ExtOpen}},
	{BuiltinNameExtListFiles, &BuiltIn{ExtListFiles}},
	{BuiltinNameExtReadFile, &BuiltIn{ExtReadFile}},
	{BuiltinNameExtReadFileBytes, &BuiltIn{ExtReadFileBytes}},
	{BuiltinNameExtExtractFile, &BuiltIn{ExtExtractFile}},
	{BuiltinNameExtHashFile, &BuiltIn{ExtHashFile}},
	{BuiltinNameExtReadFileAt, &BuiltIn{ExtReadFileAt}},
	{BuiltinNameExtMetadata, &BuiltIn{ExtMetadata}},
	{BuiltinNameExtVerify, &BuiltIn{ExtVerify}},
	{BuiltinNameExtClose, &BuiltIn{ExtClose}},
	{BuiltinNameHfsOpen, &BuiltIn{HFSOpen}},
	{BuiltinNameHfsListFiles, &BuiltIn{HFSListFiles}},
	{BuiltinNameHfsReadFile, &BuiltIn{HFSReadFile}},
	{BuiltinNameHfsReadFileBytes, &BuiltIn{HFSReadFileBytes}},
	{BuiltinNameHfsExtractFile, &BuiltIn{HFSExtractFile}},
	{BuiltinNameHfsHashFile, &BuiltIn{HFSHashFile}},
	{BuiltinNameHfsReadFileAt, &BuiltIn{HFSReadFileAt}},
	{BuiltinNameHfsMetadata, &BuiltIn{HFSMetadata}},
	{BuiltinNameHfsVerify, &BuiltIn{HFSVerify}},
	{BuiltinNameHfsClose, &BuiltIn{HFSClose}},
	{BuiltinNameXfsOpen, &BuiltIn{XFSOpen}},
	{BuiltinNameXfsListFiles, &BuiltIn{XFSListFiles}},
	{BuiltinNameXfsReadFile, &BuiltIn{XFSReadFile}},
	{BuiltinNameXfsReadFileBytes, &BuiltIn{XFSReadFileBytes}},
	{BuiltinNameXfsExtractFile, &BuiltIn{XFSExtractFile}},
	{BuiltinNameXfsHashFile, &BuiltIn{XFSHashFile}},
	{BuiltinNameXfsReadFileAt, &BuiltIn{XFSReadFileAt}},
	{BuiltinNameXfsMetadata, &BuiltIn{XFSMetadata}},
	{BuiltinNameXfsVerify, &BuiltIn{XFSVerify}},
	{BuiltinNameXfsClose, &BuiltIn{XFSClose}},
	{BuiltinNameVhdiOpen, &BuiltIn{VHDIOpen}},
	{BuiltinNameVhdiMetadata, &BuiltIn{VHDIMetadata}},
	{BuiltinNameVhdiReadAt, &BuiltIn{VHDIReadAt}},
	{BuiltinNameVhdiReadAtBytes, &BuiltIn{VHDIReadAtBytes}},
	{BuiltinNameVhdiMapOffset, &BuiltIn{VHDIMapOffset}},
	{BuiltinNameVhdiClose, &BuiltIn{VHDIClose}},
	{BuiltinNameEwfOpen, &BuiltIn{EWFOpen}},
	{BuiltinNameEwfOpenPartial, &BuiltIn{EWFOpenPartial}},
	{BuiltinNameEwfMetadata, &BuiltIn{EWFMetadata}},
	{BuiltinNameEwfVerify, &BuiltIn{EWFVerify}},
	{BuiltinNameEwfSegments, &BuiltIn{EWFSegments}},
	{BuiltinNameEwfReadAt, &BuiltIn{EWFReadAt}},
	{BuiltinNameEwfReadAtBytes, &BuiltIn{EWFReadAtBytes}},
	{BuiltinNameEwfClose, &BuiltIn{EWFClose}},
	{BuiltinNameRawOpen, &BuiltIn{RAWOpen}},
	{BuiltinNameRawMetadata, &BuiltIn{RAWMetadata}},
	{BuiltinNameRawReadAt, &BuiltIn{RAWReadAt}},
	{BuiltinNameRawReadAtBytes, &BuiltIn{RAWReadAtBytes}},
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
	{BuiltinNameNetSynScan, &BuiltIn{NetConnectScan}}, // deprecated alias of net_connect_scan
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
	{BuiltinNameMemReadBytes, &BuiltIn{MemReadBytes}},
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
	{BuiltinNameSigmaParse, &BuiltIn{SigmaParse}},
	{BuiltinNameSigmaParseAll, &BuiltIn{SigmaParseAll}},
	{BuiltinNameSigmaMatch, &BuiltIn{SigmaMatch}},
	{BuiltinNameSigmaScan, &BuiltIn{SigmaScan}},
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
	{BuiltinNameDbCompact, &BuiltIn{DbCompact}},
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
	{BuiltinNameStringToBytes, &BuiltIn{StringToBytes}},
	{BuiltinNameBytesToString, &BuiltIn{BytesToString}},
	// secure networking: sockets, TLS, listeners (dev-sec)
	// This list's order is no longer part of the ABI. Bytecode names the
	// builtins it calls and the runtime resolves those names at load, so an
	// entry may be added anywhere, renamed (leaving an entry in Aliases), or
	// retired. Ordinals still matter to artifacts compiled before v2.5, and they
	// read the frozen snapshot in legacy_ordinals.go rather than this slice, so
	// nothing done here can rebind a call in a program already written.
	{BuiltinNameNetConnect, &BuiltIn{NetConnect}},
	{BuiltinNameNetTlsConnect, &BuiltIn{NetTLSConnect}},
	{BuiltinNameNetConnWrite, &BuiltIn{NetConnWrite}},
	{BuiltinNameNetConnRead, &BuiltIn{NetConnRead}},
	{BuiltinNameNetConnReadBytes, &BuiltIn{NetConnReadBytes}},
	{BuiltinNameNetConnClose, &BuiltIn{NetConnClose}},
	{BuiltinNameNetConnInfo, &BuiltIn{NetConnInfo}},
	{BuiltinNameNetListen, &BuiltIn{NetListen}},
	{BuiltinNameNetTlsListen, &BuiltIn{NetTLSListen}},
	{BuiltinNameNetAccept, &BuiltIn{NetAccept}},
	{BuiltinNameNetListenClose, &BuiltIn{NetListenClose}},
	{BuiltinNameNetTlsUpgradeServer, &BuiltIn{NetTLSUpgradeServer}},
	{BuiltinNameNetTlsUpgradeClient, &BuiltIn{NetTLSUpgradeClient}},
	// x509 certificate authority + leaf issuance
	{BuiltinNameTlsGenerateCa, &BuiltIn{TLSGenerateCA}},
	{BuiltinNameTlsGenerateCert, &BuiltIn{TLSGenerateCert}},
	{BuiltinNameTlsSignCert, &BuiltIn{TLSSignCert}},
	// HTTP message inspection/interception
	{BuiltinNameHttpParseRequest, &BuiltIn{HTTPParseRequest}},
	{BuiltinNameHttpParseResponse, &BuiltIn{HTTPParseResponse}},
	{BuiltinNameHttpBuildRequest, &BuiltIn{HTTPBuildRequest}},
	{BuiltinNameHttpBuildResponse, &BuiltIn{HTTPBuildResponse}},
	{BuiltinNameHttpConnReadRequest, &BuiltIn{HTTPConnReadRequest}},
	{BuiltinNameHttpConnReadResponse, &BuiltIn{HTTPConnReadResponse}},
	// concurrency (dev-sec-platform-upgrades)
	{BuiltinNameNetServe, &BuiltIn{NetServe}},
	{BuiltinNameNetSpawn, &BuiltIn{NetSpawn}},
	{BuiltinNameServeConn, serveConnBuiltin},
	{BuiltinNameServeArg, serveArgBuiltin},
	{BuiltinNameSleepMs, &BuiltIn{SleepMs}},
	{BuiltinNameTimeMs, &BuiltIn{TimeMs}},
	{BuiltinNameWsAcceptKey, &BuiltIn{WSAcceptKey}},
	{BuiltinNameWsReadFrame, &BuiltIn{WSReadFrame}},
	{BuiltinNameWsWriteFrame, &BuiltIn{WSWriteFrame}},
	{BuiltinNameHttpConnReadRequestHead, &BuiltIn{HTTPConnReadRequestHead}},
	{BuiltinNameHttpConnReadResponseHead, &BuiltIn{HTTPConnReadResponseHead}},
	// generic standard library: strings
	{BuiltinNameStrUpper, &BuiltIn{StrUpper}},
	{BuiltinNameStrLower, &BuiltIn{StrLower}},
	{BuiltinNameStrTrim, &BuiltIn{StrTrim}},
	{BuiltinNameStrTrimLeft, &BuiltIn{StrTrimLeft}},
	{BuiltinNameStrTrimRight, &BuiltIn{StrTrimRight}},
	{BuiltinNameStrTrimPrefix, &BuiltIn{StrTrimPrefix}},
	{BuiltinNameStrTrimSuffix, &BuiltIn{StrTrimSuffix}},
	{BuiltinNameStrStartsWith, &BuiltIn{StrStartsWith}},
	{BuiltinNameStrEndsWith, &BuiltIn{StrEndsWith}},
	{BuiltinNameStrJoin, &BuiltIn{StrJoin}},
	{BuiltinNameStrRepeat, &BuiltIn{StrRepeat}},
	{BuiltinNameStrPadLeft, &BuiltIn{StrPadLeft}},
	{BuiltinNameStrPadRight, &BuiltIn{StrPadRight}},
	{BuiltinNameStrReverse, &BuiltIn{StrReverse}},
	{BuiltinNameStrSubstr, &BuiltIn{StrSubstr}},
	{BuiltinNameStrCharAt, &BuiltIn{StrCharAt}},
	{BuiltinNameStrFormat, &BuiltIn{StrFormat}},
	{BuiltinNameStrTitle, &BuiltIn{StrTitle}},
	// generic standard library: hashing & IDs
	{BuiltinNameHashMD5, &BuiltIn{HashMD5}},
	{BuiltinNameHashSHA1, &BuiltIn{HashSHA1}},
	{BuiltinNameHashSHA256, &BuiltIn{HashSHA256}},
	{BuiltinNameHashSHA512, &BuiltIn{HashSHA512}},
	{BuiltinNameHashCRC32, &BuiltIn{HashCRC32}},
	{BuiltinNameHashBlake2, &BuiltIn{HashBlake2}},
	{BuiltinNameHMAC, &BuiltIn{HMAC}},
	{BuiltinNameUUIDv4, &BuiltIn{UUIDv4}},
	{BuiltinNameUUIDv7, &BuiltIn{UUIDv7}},
	{BuiltinNameRandomHex, &BuiltIn{RandomHex}},
	{BuiltinNameNanoID, &BuiltIn{NanoID}},
	// generic standard library: math
	{BuiltinNameAbs, &BuiltIn{Abs}},
	{BuiltinNameMin, &BuiltIn{Min}},
	{BuiltinNameMax, &BuiltIn{Max}},
	{BuiltinNameClamp, &BuiltIn{Clamp}},
	{BuiltinNamePow, &BuiltIn{Pow}},
	{BuiltinNameSqrt, &BuiltIn{Sqrt}},
	{BuiltinNameMod, &BuiltIn{Mod}},
	{BuiltinNameFloor, &BuiltIn{Floor}},
	{BuiltinNameCeil, &BuiltIn{Ceil}},
	{BuiltinNameRound, &BuiltIn{Round}},
	{BuiltinNameSum, &BuiltIn{Sum}},
	{BuiltinNameAvg, &BuiltIn{Avg}},
	{BuiltinNameRand, &BuiltIn{Rand}},
	{BuiltinNameRandInt, &BuiltIn{RandInt}},
	{BuiltinNameRandBytes, &BuiltIn{RandBytes}},
	{BuiltinNameMathPi, &BuiltIn{MathPi}},
	{BuiltinNameMathE, &BuiltIn{MathE}},
	// generic standard library: encoding
	{BuiltinNameBase64Encode, &BuiltIn{Base64Encode}},
	{BuiltinNameBase64Decode, &BuiltIn{Base64Decode}},
	{BuiltinNameBase64DecodeBytes, &BuiltIn{Base64DecodeBytes}},
	{BuiltinNameBase64URLEncode, &BuiltIn{Base64URLEncode}},
	{BuiltinNameBase64URLDecode, &BuiltIn{Base64URLDecode}},
	{BuiltinNameBase32Encode, &BuiltIn{Base32Encode}},
	{BuiltinNameBase32Decode, &BuiltIn{Base32Decode}},
	{BuiltinNameHexEncode, &BuiltIn{HexEncode}},
	{BuiltinNameHexDecode, &BuiltIn{HexDecode}},
	{BuiltinNameHexDecodeBytes, &BuiltIn{HexDecodeBytes}},
	{BuiltinNameURLEncode, &BuiltIn{URLEncode}},
	{BuiltinNameURLDecode, &BuiltIn{URLDecode}},
	{BuiltinNameGzip, &BuiltIn{Gzip}},
	{BuiltinNameGunzip, &BuiltIn{Gunzip}},
	{BuiltinNameGunzipBytes, &BuiltIn{GunzipBytes}},
	{BuiltinNameZlibCompress, &BuiltIn{ZlibCompress}},
	{BuiltinNameZlibDecompress, &BuiltIn{ZlibDecompress}},
	{BuiltinNameZlibDecompressBytes, &BuiltIn{ZlibDecompressBytes}},
	// structured data: the formats that are not JSON
	{BuiltinNameCsvParse, &BuiltIn{CsvParse}},
	{BuiltinNameCsvStringify, &BuiltIn{CsvStringify}},
	{BuiltinNameXmlParse, &BuiltIn{XmlParse}},
	{BuiltinNameXmlFind, &BuiltIn{XmlFind}},
	{BuiltinNameNdjsonParse, &BuiltIn{NdjsonParse}},
	{BuiltinNameNdjsonStringify, &BuiltIn{NdjsonStringify}},
	{BuiltinNameYamlParse, &BuiltIn{YamlParse}},
	{BuiltinNameYamlParseAll, &BuiltIn{YamlParseAll}},
	{BuiltinNameYamlStringify, &BuiltIn{YamlStringify}},
	{BuiltinNameTomlParse, &BuiltIn{TomlParse}},
	{BuiltinNameTomlStringify, &BuiltIn{TomlStringify}},
	{BuiltinNameCborParse, &BuiltIn{CborParse}},
	{BuiltinNameCborEncode, &BuiltIn{CborEncode}},
	{BuiltinNameMsgpackParse, &BuiltIn{MsgpackParse}},
	{BuiltinNameMsgpackEncode, &BuiltIn{MsgpackEncode}},
	{BuiltinNameProtobufParse, &BuiltIn{ProtobufParse}},
	{BuiltinNameDerParse, &BuiltIn{DerParse}},
	// archives
	{BuiltinNameZipOpen, &BuiltIn{ZipOpen}},
	{BuiltinNameZipEntries, &BuiltIn{ZipEntries}},
	{BuiltinNameZipRead, &BuiltIn{ZipRead}},
	{BuiltinNameZipReadBytes, &BuiltIn{ZipReadBytes}},
	{BuiltinNameZipClose, &BuiltIn{ZipClose}},
	{BuiltinNameTarOpen, &BuiltIn{TarOpen}},
	{BuiltinNameTarEntries, &BuiltIn{TarEntries}},
	{BuiltinNameTarRead, &BuiltIn{TarRead}},
	{BuiltinNameTarReadBytes, &BuiltIn{TarReadBytes}},
	{BuiltinNameTarClose, &BuiltIn{TarClose}},
	{BuiltinNameToBase, &BuiltIn{ToBase}},
	{BuiltinNameFromBase, &BuiltIn{FromBase}},
	// generic standard library: type conversion
	{BuiltinNameToInt, &BuiltIn{ToInt}},
	{BuiltinNameToFloat, &BuiltIn{ToFloat}},
	{BuiltinNameToString, &BuiltIn{ToString}},
	{BuiltinNameToBool, &BuiltIn{ToBool}},
	{BuiltinNameParseInt, &BuiltIn{ParseInt}},
	{BuiltinNameParseFloat, &BuiltIn{ParseFloat}},
	{BuiltinNameTypeOf, &BuiltIn{TypeOf}},
	{BuiltinNameIsNull, &BuiltIn{IsNull}},
	{BuiltinNameError, &BuiltIn{Error}},
	// generic standard library: time & date
	{BuiltinNameTimeNow, &BuiltIn{TimeNow}},
	{BuiltinNameTimeUnix, &BuiltIn{TimeUnix}},
	{BuiltinNameTimeFormat, &BuiltIn{TimeFormat}},
	{BuiltinNameTimeParse, &BuiltIn{TimeParse}},
	{BuiltinNameTimeDiff, &BuiltIn{TimeDiff}},
	{BuiltinNameTimeAdd, &BuiltIn{TimeAdd}},
	// generic standard library: collections
	{BuiltinNameSort, &BuiltIn{Sort}},
	{BuiltinNameReverseArray, &BuiltIn{ReverseArray}},
	{BuiltinNameContains, &BuiltIn{Contains}},
	{BuiltinNameIndexOf, &BuiltIn{IndexOf}},
	{BuiltinNameSlice, &BuiltIn{Slice}},
	{BuiltinNameConcat, &BuiltIn{Concat}},
	{BuiltinNameFlatten, &BuiltIn{Flatten}},
	{BuiltinNameUnique, &BuiltIn{Unique}},
	{BuiltinNameRange, &BuiltIn{Range}},
	{BuiltinNameZip, &BuiltIn{Zip}},
	{BuiltinNameKeys, &BuiltIn{Keys}},
	{BuiltinNameValues, &BuiltIn{Values}},
	{BuiltinNameEntries, &BuiltIn{Entries}},
	{BuiltinNameHasKey, &BuiltIn{HasKey}},
	{BuiltinNameGet, &BuiltIn{Get}},
	{BuiltinNameSet, &BuiltIn{Set}},
	{BuiltinNameMerge, &BuiltIn{Merge}},
	{BuiltinNameDelete, &BuiltIn{Delete}},
	// security: Go binary analysis via GoReSym
	{BuiltinNameGoBuildInfo, &BuiltIn{GoBuildInfo}},
	{BuiltinNameGoBuildID, &BuiltIn{GoBuildID}},
	{BuiltinNameGoSymbols, &BuiltIn{GoSymbols}},
	// security: IOC / network intelligence
	{BuiltinNameDefang, &BuiltIn{Defang}},
	{BuiltinNameRefang, &BuiltIn{Refang}},
	{BuiltinNameIPIsPrivate, &BuiltIn{IPIsPrivate}},
	{BuiltinNameIPInCIDR, &BuiltIn{IPInCIDR}},
	{BuiltinNameCIDRHosts, &BuiltIn{CIDRHosts}},
	{BuiltinNameIPVersion, &BuiltIn{IPVersion}},
	{BuiltinNameIPToInt, &BuiltIn{IPToInt}},
	{BuiltinNameIntToIP, &BuiltIn{IntToIP}},
	{BuiltinNameDomainExtract, &BuiltIn{DomainExtract}},
	{BuiltinNameTLDExtract, &BuiltIn{TLDExtract}},
	{BuiltinNameIsValidDomain, &BuiltIn{IsValidDomain}},
	{BuiltinNameExtractIOCs, &BuiltIn{ExtractIOCs}},
	// forensic: hash sets
	{BuiltinNameHashsetLoad, &BuiltIn{HashsetLoad}},
	{BuiltinNameHashsetContains, &BuiltIn{HashsetContains}},
	{BuiltinNameHashsetClose, &BuiltIn{HashsetClose}},
	// forensic: timeline
	{BuiltinNameTimestampNormalize, &BuiltIn{TimestampNormalize}},
	{BuiltinNameTimelineSort, &BuiltIn{TimelineSort}},
	{BuiltinNameTimelineMerge, &BuiltIn{TimelineMerge}},
	{BuiltinNameBodyfileParse, &BuiltIn{BodyfileParse}},
	{BuiltinNameMactime, &BuiltIn{Mactime}},
	// forensic: schema interchange
	{BuiltinNameEventsFrom, &BuiltIn{EventsFrom}},
	{BuiltinNameEventKinds, &BuiltIn{EventKinds}},
	{BuiltinNameEcsEvent, &BuiltIn{EcsEvent}},
	{BuiltinNameOcsfEvent, &BuiltIn{OcsfEvent}},
	{BuiltinNameTimesketchEvent, &BuiltIn{TimesketchEvent}},
	{BuiltinNameStixBundle, &BuiltIn{StixBundle}},
	{BuiltinNameStixPattern, &BuiltIn{StixPattern}},
	// reporting
	{BuiltinNameReportNew, &BuiltIn{ReportNew}},
	{BuiltinNameReportSection, &BuiltIn{ReportSection}},
	{BuiltinNameReportText, &BuiltIn{ReportText}},
	{BuiltinNameReportList, &BuiltIn{ReportList}},
	{BuiltinNameReportTable, &BuiltIn{ReportTable}},
	{BuiltinNameReportRender, &BuiltIn{ReportRender}},
	{BuiltinNameReportWrite, &BuiltIn{ReportWrite}},
	// forensic: Windows artifacts
	{BuiltinNameLnkParse, &BuiltIn{LnkParse}},
	// forensic: real registry hive parsing
	{BuiltinNameHiveOpen, &BuiltIn{HiveOpen}},
	{BuiltinNameHiveClose, &BuiltIn{HiveClose}},
	{BuiltinNameHiveKeyInfo, &BuiltIn{HiveKeyInfo}},
	{BuiltinNameHiveListKeys, &BuiltIn{HiveListKeys}},
	{BuiltinNameHiveListValues, &BuiltIn{HiveListValues}},
	{BuiltinNameHiveGetValue, &BuiltIn{HiveGetValue}},
	{BuiltinNameAmcacheParse, &BuiltIn{AmcacheParse}},
	{BuiltinNameShimcacheParse, &BuiltIn{ShimcacheParse}},
	// forensic: macOS/iOS artifacts
	{BuiltinNamePlistParse, &BuiltIn{PlistParse}},
	// security: fingerprinting
	{BuiltinNameImphash, &BuiltIn{Imphash}},
	{BuiltinNameNTHash, &BuiltIn{NTHash}},
	{BuiltinNameLMHash, &BuiltIn{LMHash}},
	// security: crypto
	{BuiltinNameX509Parse, &BuiltIn{X509Parse}},
	{BuiltinNameJWTDecode, &BuiltIn{JWTDecode}},
	{BuiltinNameAESEncrypt, &BuiltIn{AESEncrypt}},
	{BuiltinNameAESDecrypt, &BuiltIn{AESDecrypt}},
	{BuiltinNameAESDecryptBytes, &BuiltIn{AESDecryptBytes}},
	{BuiltinNamePEMDecode, &BuiltIn{PEMDecode}},
	// forensic: Windows artifacts
	{BuiltinNamePrefetchParse, &BuiltIn{PrefetchParse}},
	{BuiltinNameMftParse, &BuiltIn{MftParse}},
	{BuiltinNameEvtxParse, &BuiltIn{EvtxParse}},
	{BuiltinNameEvtxParseBytes, &BuiltIn{EvtxParseBytes}},
	// binary analysis: Mach-O
	{BuiltinNameBinMachoParse, &BuiltIn{BinMachOParse}},
	// forensic: Windows jump lists
	{BuiltinNameJumplistParse, &BuiltIn{JumplistParse}},
	// forensic: Unix syslog
	{BuiltinNameSyslogParse, &BuiltIn{SyslogParse}},
	// security: Go binary analysis
	{BuiltinNameGoTypes, &BuiltIn{GoTypes}},
	{BuiltinNameBinIsGo, &BuiltIn{BinIsGo}},
	// forensic: SQLite / browser artifacts
	{BuiltinNameSqliteQuery, &BuiltIn{SqliteQuery}},
	{BuiltinNameSqliteQueryBytes, &BuiltIn{SqliteQueryBytes}},
	{BuiltinNameBrowserHistory, &BuiltIn{BrowserHistory}},
	{BuiltinNameBrowserCookies, &BuiltIn{BrowserCookies}},
	{BuiltinNameBrowserDownloads, &BuiltIn{BrowserDownloads}},
	// forensic: filesystem recovery
	{BuiltinNameFsDeleted, &BuiltIn{FsDeleted}},
	// security: TLS fingerprinting
	{BuiltinNameJA3, &BuiltIn{JA3}},
	// collections: higher-order (executor-native)
	{BuiltinNameMap, mapBuiltin},
	{BuiltinNameFilter, filterBuiltin},
	{BuiltinNameReduce, reduceBuiltin},
	{BuiltinNameEach, eachBuiltin},
	{BuiltinNameSortBy, sortByBuiltin},

	// net: truthful primary name for the connect-scan (net_syn_scan alias above)
	{BuiltinNameNetConnectScan, &BuiltIn{NetConnectScan}},

	// collections: parallel higher-order (executor-native)
	{BuiltinNamePMap, pmapBuiltin},
	{BuiltinNamePEach, peachBuiltin},
	{BuiltinNameSpawn, spawnBuiltin},
	{BuiltinNameWithResource, withResourceBuiltin},
	{BuiltinNameTaskWait, &BuiltIn{TaskWait}},
	{BuiltinNameTaskDone, &BuiltIn{TaskDone}},
	{BuiltinNameChanNew, &BuiltIn{ChanNew}},
	{BuiltinNameChanSend, &BuiltIn{ChanSend}},
	{BuiltinNameChanRecv, &BuiltIn{ChanRecv}},
	{BuiltinNameChanTryRecv, &BuiltIn{ChanTryRecv}},
	{BuiltinNameChanClose, &BuiltIn{ChanClose}},
	// testing: named tests, fixtures and assertions (executor-native)
	{BuiltinNameTest, testBuiltin},
	{BuiltinNameBeforeEach, beforeEachBuiltin},
	{BuiltinNameAfterEach, afterEachBuiltin},
	{BuiltinNameAssert, assertBuiltin},
	{BuiltinNameAssertEq, assertEqBuiltin},
	{BuiltinNameAssertNe, assertNeBuiltin},
	{BuiltinNameAssertContains, assertContainsBuiltin},
	{BuiltinNameAssertErr, assertErrBuiltin},
	{BuiltinNameAssertOk, assertOkBuiltin},
	{BuiltinNameFail, failBuiltin},
	{BuiltinNameCaseOpen, &BuiltIn{CaseOpen}},
	{BuiltinNameCaseNote, &BuiltIn{CaseNote}},
	{BuiltinNameCaseEvidence, &BuiltIn{CaseEvidence}},
	{BuiltinNameCaseVerify, &BuiltIn{CaseVerify}},
	{BuiltinNameCaseManifest, &BuiltIn{CaseManifest}},
	{BuiltinNameCaseWrite, &BuiltIn{CaseWrite}},
	{BuiltinNameCaseManifestVerify, &BuiltIn{CaseManifestVerify}},
	{BuiltinNameCaseReport, &BuiltIn{CaseReport}},
	{BuiltinNameCaseBundle, &BuiltIn{CaseBundle}},
	{BuiltinNameCaseClose, &BuiltIn{CaseClose}},
	{BuiltinNameAuditHead, &BuiltIn{AuditHead}},
	{BuiltinNameAuditWrite, &BuiltIn{AuditWrite}},
	{BuiltinNameAuditVerify, &BuiltIn{AuditVerify}},
}

// registerHelpBuiltin appends `help` to the builtin set. It is done in init()
// rather than in the Builtins literal to avoid an initialization cycle (Help
// reads Builtins/builtinsByName to render topics). Appending keeps every existing
// builtin's slice index stable, so previously compiled bytecode stays valid.
func init() {
	def := BuiltinDefinition{Name: BuiltinNameHelp, Builtin: &BuiltIn{Help}}
	Builtins = append(Builtins, def)
	if _, exists := builtinsByName[def.Name]; !exists {
		builtinsByName[def.Name] = def.Builtin
	}
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
