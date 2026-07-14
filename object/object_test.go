package object

import "testing"

func TestStringHashKey(t *testing.T) {
	hello1 := &String{Value: "Hello World"}
	hello2 := &String{Value: "Hello World"}

	diff1 := &String{Value: "My name is johnny"}
	diff2 := &String{Value: "My name is johnny"}

	if hello1.HashKey() != hello2.HashKey() {
		t.Errorf("strings with same content have different hash keys")
	}
	if diff1.HashKey() != diff2.HashKey() {
		t.Errorf("strings with same content have different hash keys")
	}
	if hello1.HashKey() == diff1.HashKey() {
		t.Errorf("strings with different content have same hash keys")
	}
}

func TestMultiValueInspectOmitsTrailingNullForSingleResult(t *testing.T) {
	mv := &MultiValue{Values: []Object{&Integer{Value: 4}, &Null{}}}

	if got := mv.Inspect(); got != "4" {
		t.Fatalf("unexpected inspect output: got=%q want=%q", got, "4")
	}
}
