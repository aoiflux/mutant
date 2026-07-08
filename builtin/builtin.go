package builtin

import (
	"fmt"

	"mutant/object"
)

type BuiltinFunction func(args ...object.Object) object.Object
type BuiltIn struct{ Fn BuiltinFunction }

func (b *BuiltIn) Type() object.ObjectType { return object.BUILTIN_OBJ }
func (b *BuiltIn) Inspect() string         { return "builtin funciton" }

var Builtins = []struct {
	Name               string
	Builtin            *BuiltIn
	RequiredCapability string
}{
	{"len", &BuiltIn{Len}, ""},
	{"putf", &BuiltIn{Putf}, ""},
	{"putln", &BuiltIn{Putln}, ""},
	{"gets", &BuiltIn{Gets}, ""},
	{"first", &BuiltIn{First}, ""},
	{"last", &BuiltIn{Last}, ""},
	{"rest", &BuiltIn{Rest}, ""},
	{"push", &BuiltIn{Push}, ""},
	{"pop", &BuiltIn{Pop}, ""},
	{"debug_status", &BuiltIn{DebugStatus}, ""},
	{"sandbox_status", &BuiltIn{SandboxStatus}, ""},
	{"security_diagnostics", &BuiltIn{SecurityDiagnostics}, ""},
	{"exec_string", &BuiltIn{ExecString}, "command_exec"},
	{"cmd_builder", &BuiltIn{CmdBuilder}, "command_exec"},
	{"cmd_add", &BuiltIn{CmdAdd}, "command_exec"},
	{"cmd_run", &BuiltIn{CmdRun}, "command_exec"},
	// file system
	{"fs_read", &BuiltIn{FsRead}, "filesystem"},
	{"fs_write", &BuiltIn{FsWrite}, "filesystem"},
	{"fs_append", &BuiltIn{FsAppend}, "filesystem"},
	{"fs_delete", &BuiltIn{FsDelete}, "filesystem"},
	{"fs_exists", &BuiltIn{FsExists}, "filesystem"},
	{"fs_stat", &BuiltIn{FsStat}, "filesystem"},
	{"fs_list", &BuiltIn{FsList}, "filesystem"},
	{"fs_mkdir", &BuiltIn{FsMkdir}, "filesystem"},
	{"fs_copy", &BuiltIn{FsCopy}, "filesystem"},
	{"fs_move", &BuiltIn{FsMove}, "filesystem"},
	// network
	{"net_resolve", &BuiltIn{NetResolve}, "network"},
	{"net_dial", &BuiltIn{NetDial}, "network"},
	// http
	{"http_get", &BuiltIn{HttpGet}, "network"},
	{"http_post", &BuiltIn{HttpPost}, "network"},
	{"http_request", &BuiltIn{HttpRequest}, "network"},
	// json
	{"json_stringify", &BuiltIn{JsonStringify}, ""},
	{"json_parse", &BuiltIn{JsonParse}, ""},
	// lua
	{"lua_run_string", &BuiltIn{LuaRunString}, ""},
	{"lua_run_file", &BuiltIn{LuaRunFile}, "filesystem"},
	{"lua_run_http", &BuiltIn{LuaRunHTTP}, "network"},
	// graph db
	{"db_open", &BuiltIn{DbOpen}, ""},
	{"db_open_disk", &BuiltIn{DbOpenDisk}, ""},
	{"db_close", &BuiltIn{DbClose}, ""},
	{"db_add_node", &BuiltIn{DbAddNode}, ""},
	{"db_add_edge", &BuiltIn{DbAddEdge}, ""},
	{"db_index_prop", &BuiltIn{DbIndexProp}, ""},
	{"db_query_nodes", &BuiltIn{DbQueryNodes}, ""},
	{"db_bfs", &BuiltIn{DbBFS}, ""},
	{"db_shortest_path", &BuiltIn{DbShortestPath}, ""},
	{"db_stats", &BuiltIn{DbStats}, ""},
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
	return &object.Error{Message: fmt.Sprintf(format, a...)}
}
