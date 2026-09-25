package builtin

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// M26-DAT-002. report_table and report_list rendered each cell to text as it
// was added -- a buffer as its hex -- so the report that reached report_render
// and report_write, the named sinks, held no marked buffer for them to find, and
// a classified buffer put in a table was rendered and written out whole. The
// builders now refuse it where it goes in, the way the sinks do.
func TestAReportBuilderRefusesAClassifiedBuffer(t *testing.T) {
	plaintext := []byte("SECRET-PLAINTEXT")
	secret := &object.Bytes{Value: plaintext, Classified: &object.Classification{
		RecordUID: strings.Repeat("ab", 16), Tags: []string{"00"}, Labels: []string{"pii"},
	}}
	leaked := hex.EncodeToString(plaintext)

	if _, errObj := unwrapPairNoFatal(ReportRender(makeHashObject(map[string]object.Object{
		"title": stringObj("t"), "x": secret}), stringObj("html"))); errObj == nil {
		t.Fatal("precondition: report_render accepted a classified buffer handed to it directly")
	}

	report := mustHash(t, ReportNew(stringObj("case notes")))
	for name, call := range map[string]func() object.Object{
		BuiltinNameReportTable: func() object.Object {
			return ReportTable(report, &object.Array{Elements: []object.Object{
				&object.Array{Elements: []object.Object{stringObj("content"), secret}},
			}})
		},
		BuiltinNameReportList: func() object.Object {
			return ReportList(report, &object.Array{Elements: []object.Object{secret}})
		},
	} {
		value, errObj := unwrapPairNoFatal(call())
		if errObj == nil {
			// Accepted: show where the plaintext would have gone.
			rendered, _ := unwrapPairNoFatal(ReportRender(value, stringObj("html")))
			path := filepath.Join(t.TempDir(), "report.csv")
			ReportWrite(value, stringObj(path))
			written, _ := os.ReadFile(path)
			t.Errorf("%s accepted a classified buffer; rendered it %t, wrote it to disk %t", name,
				rendered != nil && strings.Contains(rendered.Inspect(), leaked), strings.Contains(string(written), leaked))
			continue
		}
		if !strings.Contains(errObj.Message, "classified") || strings.Contains(errObj.Message, leaked) {
			t.Errorf("%s: the refusal does not say why, or repeats the plaintext: %s", name, errObj.Message)
		}
	}
}
