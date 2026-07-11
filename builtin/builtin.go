package builtin

import (
	"fmt"
	"mutant/global"

	"mutant/object"
)

type BuiltinFunction func(args ...object.Object) object.Object
type BuiltIn struct{ Fn BuiltinFunction }

func (b *BuiltIn) Type() object.ObjectType { return object.BUILTIN_OBJ }
func (b *BuiltIn) Inspect() string         { return "builtin funciton" }

var Builtins = []struct {
	Name    string
	Builtin *BuiltIn
}{
	{"len", &BuiltIn{Len}},
	{"putf", &BuiltIn{Putf}},
	{"putln", &BuiltIn{Putln}},
	{"gets", &BuiltIn{Gets}},
	{"first", &BuiltIn{First}},
	{"last", &BuiltIn{Last}},
	{"rest", &BuiltIn{Rest}},
	{"push", &BuiltIn{Push}},
	{"pop", &BuiltIn{Pop}},
	// text matching
	{"text_contains", &BuiltIn{TextContains}},
	{"text_index", &BuiltIn{TextIndex}},
	{"text_count", &BuiltIn{TextCount}},
	{"text_split", &BuiltIn{TextSplit}},
	{"text_replace", &BuiltIn{TextReplace}},
	// fuzzy matching
	{"text_levenshtein", &BuiltIn{TextLevenshtein}},
	{"text_similarity", &BuiltIn{TextSimilarity}},
	{"text_fuzzy_find", &BuiltIn{TextFuzzyFind}},
	{"text_jaro_winkler", &BuiltIn{TextJaroWinkler}},
	// regex
	{"regex_match", &BuiltIn{RegexMatch}},
	{"regex_find", &BuiltIn{RegexFind}},
	{"regex_find_all", &BuiltIn{RegexFindAll}},
	{"regex_replace", &BuiltIn{RegexReplace}},
	{"regex_capture_groups", &BuiltIn{RegexCaptureGroups}},
	// policy engine
	{"policy_eval", &BuiltIn{PolicyEval}},
	{"policy_allow", &BuiltIn{PolicyAllow}},
	{"policy_rules", &BuiltIn{PolicyRules}},
	{"policy_trace", &BuiltIn{PolicyTrace}},
	{"policy_load", &BuiltIn{PolicyLoad}},
	// cache
	{"cache_open", &BuiltIn{CacheOpen}},
	{"cache_put", &BuiltIn{CachePut}},
	{"cache_get", &BuiltIn{CacheGet}},
	{"cache_delete", &BuiltIn{CacheDelete}},
	{"cache_keys", &BuiltIn{CacheKeys}},
	{"cache_stats", &BuiltIn{CacheStats}},
	{"cache_clear", &BuiltIn{CacheClear}},
	// system forensics
	{"process_list", &BuiltIn{ProcessList}},
	{"process_tree", &BuiltIn{ProcessTree}},
	{"process_open_files", &BuiltIn{ProcessOpenFiles}},
	{"process_threads", &BuiltIn{ProcessThreads}},
	{"process_modules", &BuiltIn{ProcessModules}},
	{"process_hash", &BuiltIn{ProcessHash}},
	{"process_memory_scan", &BuiltIn{ProcessMemoryScan}},
	{"process_env", &BuiltIn{ProcessEnv}},
	{"process_kill", &BuiltIn{ProcessKill}},
	{"debug_status", &BuiltIn{DebugStatus}},
	{"sandbox_status", &BuiltIn{SandboxStatus}},
	{"security_diagnostics", &BuiltIn{SecurityDiagnostics}},
	{"exec_string", &BuiltIn{ExecString}},
	{"cmd_builder", &BuiltIn{CmdBuilder}},
	{"cmd_add", &BuiltIn{CmdAdd}},
	{"cmd_run", &BuiltIn{CmdRun}},
	// file system
	{"fs_read", &BuiltIn{FsRead}},
	{"fs_write", &BuiltIn{FsWrite}},
	{"fs_append", &BuiltIn{FsAppend}},
	{"fs_delete", &BuiltIn{FsDelete}},
	{"fs_exists", &BuiltIn{FsExists}},
	{"fs_stat", &BuiltIn{FsStat}},
	{"fs_list", &BuiltIn{FsList}},
	{"fs_mkdir", &BuiltIn{FsMkdir}},
	{"fs_copy", &BuiltIn{FsCopy}},
	{"fs_move", &BuiltIn{FsMove}},
	// filesystem forensics
	{"fs_hash", &BuiltIn{FsHash}},
	{"fs_walk", &BuiltIn{FsWalk}},
	{"fs_metadata", &BuiltIn{FsMetadata}},
	{"fs_magic", &BuiltIn{FsMagic}},
	{"fs_extract_strings", &BuiltIn{FsExtractStrings}},
	{"fs_diff", &BuiltIn{FsDiff}},
	{"fs_carve", &BuiltIn{FsCarve}},
	{"fs_entropy", &BuiltIn{FsEntropy}},
	// binary analysis
	{"bin_pe_parse", &BuiltIn{BinPEParse}},
	{"bin_elf_parse", &BuiltIn{BinELFParse}},
	{"bin_dwarf_parse", &BuiltIn{BinDWARFParse}},
	{"bin_strings", &BuiltIn{BinStrings}},
	{"bin_entropy", &BuiltIn{BinEntropy}},
	{"bin_yara_scan", &BuiltIn{BinYaraScan}},
	{"bin_imports", &BuiltIn{BinImports}},
	{"bin_sections", &BuiltIn{BinSections}},
	// network
	{"net_resolve", &BuiltIn{NetResolve}},
	{"net_dial", &BuiltIn{NetDial}},
	{"net_syn_scan", &BuiltIn{NetSynScan}},
	{"net_udp_scan", &BuiltIn{NetUDPScan}},
	{"net_banner", &BuiltIn{NetBanner}},
	{"net_tls_fingerprint", &BuiltIn{NetTLSFingerprint}},
	{"net_dns_query", &BuiltIn{NetDNSQuery}},
	{"net_pcap_analyze", &BuiltIn{NetPCAPAnalyze}},
	{"net_capture_raw", &BuiltIn{NetCaptureRaw}},
	{"net_flow_reconstruct", &BuiltIn{NetFlowReconstruct}},
	{"net_os_fingerprint", &BuiltIn{NetOSFingerprint}},
	// registry forensics
	{"reg_open_hive", &BuiltIn{RegOpenHive}},
	{"reg_enum_keys", &BuiltIn{RegEnumKeys}},
	{"reg_enum_values", &BuiltIn{RegEnumValues}},
	{"reg_get_value", &BuiltIn{RegGetValue}},
	{"reg_deleted_keys", &BuiltIn{RegDeletedKeys}},
	{"reg_timeline", &BuiltIn{RegTimeline}},
	// email forensics
	{"email_parse", &BuiltIn{EmailParse}},
	{"email_headers", &BuiltIn{EmailHeaders}},
	{"email_attachments", &BuiltIn{EmailAttachments}},
	{"email_spf_dkim", &BuiltIn{EmailSPFDKIM}},
	{"email_urls", &BuiltIn{EmailURLs}},
	// memory forensics
	{"mem_map", &BuiltIn{MemMap}},
	{"mem_read", &BuiltIn{MemRead}},
	{"mem_scan", &BuiltIn{MemScan}},
	{"mem_strings", &BuiltIn{MemStrings}},
	{"mem_find_pe", &BuiltIn{MemFindPE}},
	{"mem_find_shellcode", &BuiltIn{MemFindShellcode}},
	// detection
	{"detect_persistence", &BuiltIn{DetectPersistence}},
	{"detect_injection", &BuiltIn{DetectInjection}},
	{"detect_network_beacon", &BuiltIn{DetectNetworkBeacon}},
	{"detect_priv_esc", &BuiltIn{DetectPrivEsc}},
	{"detect_suspicious_files", &BuiltIn{DetectSuspiciousFiles}},
	// http
	{"http_get", &BuiltIn{HttpGet}},
	{"http_post", &BuiltIn{HttpPost}},
	{"http_request", &BuiltIn{HttpRequest}},
	// json
	{"json_stringify", &BuiltIn{JsonStringify}},
	{"json_parse", &BuiltIn{JsonParse}},
	// lua
	{"lua_run_string", &BuiltIn{LuaRunString}},
	{"lua_run_file", &BuiltIn{LuaRunFile}},
	{"lua_run_http", &BuiltIn{LuaRunHTTP}},
	// graph db
	{"db_open", &BuiltIn{DbOpen}},
	{"db_open_disk", &BuiltIn{DbOpenDisk}},
	{"db_close", &BuiltIn{DbClose}},
	{"db_add_node", &BuiltIn{DbAddNode}},
	{"db_add_edge", &BuiltIn{DbAddEdge}},
	{"db_add_artifact", &BuiltIn{DbAddArtifact}},
	{"db_add_relation", &BuiltIn{DbAddRelation}},
	{"db_index_prop", &BuiltIn{DbIndexProp}},
	{"db_query_nodes", &BuiltIn{DbQueryNodes}},
	{"db_query", &BuiltIn{DbQuery}},
	{"db_bfs", &BuiltIn{DbBFS}},
	{"db_shortest_path", &BuiltIn{DbShortestPath}},
	{"db_timeline", &BuiltIn{DbTimeline}},
	{"db_stats", &BuiltIn{DbStats}},
	// generic bytes/parser helpers
	{"bytes_len", &BuiltIn{BytesLen}},
	{"bytes_get", &BuiltIn{BytesGet}},
	{"bytes_slice", &BuiltIn{BytesSlice}},
	{"bytes_read_u16_le", &BuiltIn{BytesReadU16LE}},
	{"bytes_read_u16_be", &BuiltIn{BytesReadU16BE}},
	{"bytes_read_u32_le", &BuiltIn{BytesReadU32LE}},
	{"bytes_read_u32_be", &BuiltIn{BytesReadU32BE}},
	{"bytes_read_u64_le", &BuiltIn{BytesReadU64LE}},
	{"bytes_read_u64_be", &BuiltIn{BytesReadU64BE}},
	{"bytes_write_u16_le", &BuiltIn{BytesWriteU16LE}},
	{"bytes_write_u16_be", &BuiltIn{BytesWriteU16BE}},
	{"bytes_write_u32_le", &BuiltIn{BytesWriteU32LE}},
	{"bytes_write_u32_be", &BuiltIn{BytesWriteU32BE}},
	{"bytes_write_u64_le", &BuiltIn{BytesWriteU64LE}},
	{"bytes_write_u64_be", &BuiltIn{BytesWriteU64BE}},
	{"bytes_cstr_at", &BuiltIn{BytesCStrAt}},
	{"bytes_hex", &BuiltIn{BytesHex}},
	{"bytes_char_from_int", &BuiltIn{BytesCharFromInt}},
	{"bytes_int_from_char", &BuiltIn{BytesIntFromChar}},
	{"bytes_cursor_new", &BuiltIn{BytesCursorNew}},
	{"bytes_cursor_tell", &BuiltIn{BytesCursorTell}},
	{"bytes_cursor_seek", &BuiltIn{BytesCursorSeek}},
	{"bytes_cursor_eof", &BuiltIn{BytesCursorEOF}},
	{"bytes_cursor_read_u8", &BuiltIn{BytesCursorReadU8}},
	{"bytes_cursor_read_u16_le", &BuiltIn{BytesCursorReadU16LE}},
	{"bytes_cursor_read_u16_be", &BuiltIn{BytesCursorReadU16BE}},
	{"bytes_cursor_read_u32_le", &BuiltIn{BytesCursorReadU32LE}},
	{"bytes_cursor_read_u32_be", &BuiltIn{BytesCursorReadU32BE}},
	{"bytes_cursor_read_u64_le", &BuiltIn{BytesCursorReadU64LE}},
	{"bytes_cursor_read_u64_be", &BuiltIn{BytesCursorReadU64BE}},
}

func GetBuiltinByName(name string) *BuiltIn {
	for _, fun := range Builtins {
		if name == fun.Name {
			return fun.Builtin
		}
	}
	return nil
}

func newError(format string, a ...any) *object.Error {
	return &object.Error{Message: fmt.Sprintf(format, a...), Context: "builtin"}
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
