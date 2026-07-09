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
	// network
	{"net_resolve", &BuiltIn{NetResolve}},
	{"net_dial", &BuiltIn{NetDial}},
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
	{"db_index_prop", &BuiltIn{DbIndexProp}},
	{"db_query_nodes", &BuiltIn{DbQueryNodes}},
	{"db_bfs", &BuiltIn{DbBFS}},
	{"db_shortest_path", &BuiltIn{DbShortestPath}},
	{"db_stats", &BuiltIn{DbStats}},
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
