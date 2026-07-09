package builtin

import (
	"io"
	"os"
	"time"

	"mutant/object"
)

func FsRead(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `fs_read` must be STRING, got %s", args[0].Type()))
	}
	data, err := os.ReadFile(path.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_read: %s", err.Error()))
	}
	return resultAndError(stringObj(string(data)), nil)
}

func FsWrite(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_write` must be STRING, got %s", args[0].Type()))
	}
	content, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fs_write` must be STRING, got %s", args[1].Type()))
	}
	err := os.WriteFile(path.Value, []byte(content.Value), 0644)
	if err != nil {
		return resultAndError(nil, newError("fs_write: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func FsAppend(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_append` must be STRING, got %s", args[0].Type()))
	}
	content, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fs_append` must be STRING, got %s", args[1].Type()))
	}
	f, err := os.OpenFile(path.Value, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return resultAndError(nil, newError("fs_append2: %s", err.Error()))
	}
	defer f.Close()
	_, err = f.WriteString(content.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_append: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func FsDelete(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `fs_delete` must be STRING, got %s", args[0].Type()))
	}
	err := os.Remove(path.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_delete: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func FsList(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `fs_list` must be STRING, got %s", args[0].Type()))
	}
	entries, err := os.ReadDir(path.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_list: %s", err.Error()))
	}

	elements := make([]object.Object, 0, len(entries))
	for _, entry := range entries {
		info, infoErr := entry.Info()
		size := int64(0)
		if infoErr == nil {
			size = info.Size()
		}
		elements = append(elements, makeHashObject(map[string]object.Object{
			"name":   stringObj(entry.Name()),
			"size":   intObj(size),
			"is_dir": boolObj(entry.IsDir()),
		}))
	}

	return resultAndError(&object.Array{Elements: elements}, nil)
}

func FsExists(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `fs_exists` must be STRING, got %s", args[0].Type()))
	}
	_, err := os.Stat(path.Value)
	return resultAndError(boolObj(!os.IsNotExist(err)), nil)
}

func FsStat(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `fs_stat` must be STRING, got %s", args[0].Type()))
	}
	info, err := os.Stat(path.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_stat: %s", err.Error()))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"name":     stringObj(info.Name()),
		"size":     intObj(info.Size()),
		"is_dir":   boolObj(info.IsDir()),
		"mod_time": stringObj(info.ModTime().Format(time.RFC3339)),
	}), nil)
}

func FsMkdir(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `fs_mkdir` must be STRING, got %s", args[0].Type()))
	}
	err := os.MkdirAll(path.Value, 0755)
	if err != nil {
		return resultAndError(nil, newError("fs_mkdir: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func FsCopy(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	src, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_copy` must be STRING, got %s", args[0].Type()))
	}
	dst, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fs_copy` must be STRING, got %s", args[1].Type()))
	}

	in, err := os.Open(src.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_copy: %s", err.Error()))
	}
	defer in.Close()

	out, err := os.Create(dst.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_copy: %s", err.Error()))
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return resultAndError(nil, newError("fs_copy: %s", err.Error()))
	}
	if err := out.Close(); err != nil {
		return resultAndError(nil, newError("fs_copy: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

func FsMove(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	src, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `fs_move` must be STRING, got %s", args[0].Type()))
	}
	dst, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `fs_move` must be STRING, got %s", args[1].Type()))
	}
	err := os.Rename(src.Value, dst.Value)
	if err != nil {
		return resultAndError(nil, newError("fs_move: %s", err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

// fsOkOrError returns a {ok, error} Hash. err may be nil.
func fsOkOrError(err error) object.Object {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	return makeHashObject(map[string]object.Object{
		"ok":    boolObj(err == nil),
		"error": stringObj(errMsg),
	})
}
