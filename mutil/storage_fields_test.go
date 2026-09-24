package mutil

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"mutant/object"
)

// Every value the VM stores goes through EncryptObject and comes back through
// DecryptObject, and both rebuild scalar objects from their bytes rather than
// copying them. A field added to one of those types and not threaded through
// both functions therefore vanishes the first time the value is stored in a
// variable -- which is how the Classified mark on object.Bytes passed six
// builtin tests and did nothing in a real program.
//
// This test does not know which fields exist. It sets every exported field of
// every type the two functions rebuild to a value that is not the zero value,
// stores and loads it, and requires the result to be deeply equal to what went
// in. A field added tomorrow is covered the day it is added.
//
// storedByValue lists the types EncryptObject rebuilds rather than passing
// through by pointer. A type added to that switch belongs here too.
var storedByValue = []object.Object{
	&object.Integer{},
	&object.String{},
	&object.Bytes{},
	&object.Boolean{},
	&object.Float{},
	&object.Array{},
	&object.Hash{},
	&object.Struct{},
	&object.EnumValue{},
	&object.Closure{},
	&object.LuaPatch{},
	&object.MultiValue{},
	&object.Error{},
}

// storageFillDepth bounds how deep the filler follows nested values; object
// graphs can refer to themselves through interfaces.
const storageFillDepth = 4

func TestEveryObjectFieldSurvivesStorage(t *testing.T) {
	const password, length = "storage-field-test", 1234
	for _, proto := range storedByValue {
		value := reflect.New(reflect.TypeOf(proto).Elem())
		fillExported(value.Elem(), 0)
		original := value.Interface().(object.Object)

		stored, err := EncryptObject(original, length, password)
		if err != nil {
			t.Errorf("%T: EncryptObject: %v", original, err)
			continue
		}
		loaded, err := DecryptObject(stored, length, password)
		if err != nil {
			t.Errorf("%T: DecryptObject: %v", original, err)
			continue
		}
		if !reflect.DeepEqual(original, loaded) {
			t.Errorf("%T does not survive storage: %s", original, describeFieldLoss(original, loaded))
		}
	}
}

// fillExported sets every exported field reachable from v to a non-zero value.
func fillExported(v reflect.Value, depth int) {
	if depth > storageFillDepth || !v.CanSet() {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(fmt.Sprintf("s%d", depth))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(7 + depth))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(7 + depth))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillExported(s.Index(0), depth+1)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		key := reflect.New(v.Type().Key()).Elem()
		fillExported(key, depth+1)
		val := reflect.New(v.Type().Elem()).Elem()
		fillExported(val, depth+1)
		m.SetMapIndex(key, val)
		v.Set(m)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fillExported(p.Elem(), depth+1)
		v.Set(p)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fillExported(v.Field(i), depth+1)
			}
		}
	case reflect.Interface:
		// Any object.Object slot gets a stored-by-value scalar, so nested
		// containers exercise the recursion too.
		if reflect.TypeOf((*object.Object)(nil)).Elem() == v.Type() {
			v.Set(reflect.ValueOf(&object.Integer{Value: int64(40 + depth)}))
		}
	}
}

// describeFieldLoss names the top-level fields that differ, which is the first
// thing a reader needs when this fails.
func describeFieldLoss(want, got object.Object) string {
	wv, gv := reflect.ValueOf(want).Elem(), reflect.ValueOf(got)
	if gv.Kind() == reflect.Pointer {
		gv = gv.Elem()
	}
	if wv.Type() != gv.Type() {
		return fmt.Sprintf("stored as %T, loaded as %T", want, got)
	}
	var lost []string
	for i := 0; i < wv.NumField(); i++ {
		f := wv.Type().Field(i)
		if f.IsExported() && !reflect.DeepEqual(wv.Field(i).Interface(), gv.Field(i).Interface()) {
			lost = append(lost, fmt.Sprintf("%s: stored %#v, loaded %#v", f.Name, wv.Field(i).Interface(), gv.Field(i).Interface()))
		}
	}
	if len(lost) == 0 {
		return "an unexported field or a nested value differs"
	}
	return strings.Join(lost, "; ")
}
