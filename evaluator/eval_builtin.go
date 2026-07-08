package evaluator

import (
	"mutant/builtin"
)

var builtins = map[string]*builtin.BuiltIn{
	"len":                  builtin.GetBuiltinByName("len"),
	"first":                builtin.GetBuiltinByName("first"),
	"last":                 builtin.GetBuiltinByName("last"),
	"rest":                 builtin.GetBuiltinByName("rest"),
	"push":                 builtin.GetBuiltinByName("push"),
	"putf":                 builtin.GetBuiltinByName("putf"),
	"putln":                builtin.GetBuiltinByName("putln"),
	"debug_status":         builtin.GetBuiltinByName("debug_status"),
	"sandbox_status":       builtin.GetBuiltinByName("sandbox_status"),
	"security_diagnostics": builtin.GetBuiltinByName("security_diagnostics"),
	"exec_string":          builtin.GetBuiltinByName("exec_string"),
	"cmd_builder":          builtin.GetBuiltinByName("cmd_builder"),
	"cmd_add":              builtin.GetBuiltinByName("cmd_add"),
	"cmd_run":              builtin.GetBuiltinByName("cmd_run"), // file system
	"fs_read":              builtin.GetBuiltinByName("fs_read"),
	"fs_write":             builtin.GetBuiltinByName("fs_write"),
	"fs_append":            builtin.GetBuiltinByName("fs_append"),
	"fs_delete":            builtin.GetBuiltinByName("fs_delete"),
	"fs_exists":            builtin.GetBuiltinByName("fs_exists"),
	"fs_stat":              builtin.GetBuiltinByName("fs_stat"),
	"fs_list":              builtin.GetBuiltinByName("fs_list"),
	"fs_mkdir":             builtin.GetBuiltinByName("fs_mkdir"),
	"fs_copy":              builtin.GetBuiltinByName("fs_copy"),
	"fs_move":              builtin.GetBuiltinByName("fs_move"),
	// network
	"net_resolve": builtin.GetBuiltinByName("net_resolve"),
	"net_dial":    builtin.GetBuiltinByName("net_dial"),
	// http
	"http_get":     builtin.GetBuiltinByName("http_get"),
	"http_post":    builtin.GetBuiltinByName("http_post"),
	"http_request": builtin.GetBuiltinByName("http_request"),
	// json
	"json_stringify": builtin.GetBuiltinByName("json_stringify"),
	"json_parse":     builtin.GetBuiltinByName("json_parse"),
	// graph db
	"db_open":          builtin.GetBuiltinByName("db_open"),
	"db_open_disk":     builtin.GetBuiltinByName("db_open_disk"),
	"db_close":         builtin.GetBuiltinByName("db_close"),
	"db_add_node":      builtin.GetBuiltinByName("db_add_node"),
	"db_add_edge":      builtin.GetBuiltinByName("db_add_edge"),
	"db_index_prop":    builtin.GetBuiltinByName("db_index_prop"),
	"db_query_nodes":   builtin.GetBuiltinByName("db_query_nodes"),
	"db_bfs":           builtin.GetBuiltinByName("db_bfs"),
	"db_shortest_path": builtin.GetBuiltinByName("db_shortest_path"),
	"db_stats":         builtin.GetBuiltinByName("db_stats")}
