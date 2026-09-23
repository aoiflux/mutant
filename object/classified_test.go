package object

import (
	"strings"
	"testing"
)

func testMark(uid string, tags, labels []string) *Classification {
	return &Classification{RecordUID: uid, Tags: tags, Labels: labels}
}

func TestJoiningClassificationsKeepsEveryRecordAndClass(t *testing.T) {
	pii := testMark("rec-a", []string{"t-pii"}, []string{"pii"})
	restricted := testMark("rec-b", []string{"t-restricted", "t-pii"}, []string{"restricted", "pii"})

	if JoinClassification(nil, nil) != nil {
		t.Fatal("two unmarked buffers joined into a marked one")
	}
	if JoinClassification(pii, nil) != pii || JoinClassification(nil, pii) != pii {
		t.Fatal("a mark on either side is not the mark of the join")
	}
	if JoinClassification(pii, pii) != pii {
		t.Fatal("a buffer joined to itself changed its mark")
	}

	joined := JoinClassification(pii, restricted)
	if !strings.Contains(joined.RecordUID, "rec-a") || !strings.Contains(joined.RecordUID, "rec-b") {
		t.Fatalf("the join names %q, not both records", joined.RecordUID)
	}
	if strings.Join(joined.Tags, ",") != "t-pii,t-restricted" || strings.Join(joined.Labels, ",") != "pii,restricted" {
		t.Fatalf("the join carries tags %v labels %v; want each class once", joined.Tags, joined.Labels)
	}
	if len(pii.Tags) != 1 || len(restricted.Tags) != 2 {
		t.Fatal("joining modified a mark it was given")
	}
}

// A global held in the wrapper memory mode, and a stack slot that has been
// encrypted for being idle, both come back marked.
func TestSecureMemoryKeepsTheMark(t *testing.T) {
	mark := testMark("rec", []string{"t"}, []string{"pii"})

	global, err := NewSecureGlobal(&Bytes{Value: []byte("secret"), Classified: mark}, 7)
	if err != nil {
		t.Fatal(err)
	}
	got, err := global.Get()
	if err != nil {
		t.Fatal(err)
	}
	if b := got.(*Bytes); b.Classified != mark || string(b.Value) != "secret" {
		t.Fatalf("a secure global came back as %q marked %+v", b.Value, b.Classified)
	}
	if err := global.Set(&Bytes{Value: []byte("plain")}); err != nil {
		t.Fatal(err)
	}
	got, _ = global.Get()
	if got.(*Bytes).Classified != nil {
		t.Fatal("an unmarked buffer stored over a marked one came back marked")
	}

	stack := NewSecureStack(1, 7)
	stack.encryptAfter = -1
	if err := stack.Set(0, &Bytes{Value: []byte("secret"), Classified: mark}); err != nil {
		t.Fatal(err)
	}
	stack.AutoProtect()
	if _, encrypted := stack.data[0].(*Encrypted); !encrypted {
		t.Fatal("the idle slot was not encrypted, so this test checked nothing")
	}
	got, err = stack.Get(0)
	if err != nil {
		t.Fatal(err)
	}
	if b := got.(*Bytes); b.Classified != mark || string(b.Value) != "secret" {
		t.Fatalf("an encrypted stack slot came back as %q marked %+v", b.Value, b.Classified)
	}
}
