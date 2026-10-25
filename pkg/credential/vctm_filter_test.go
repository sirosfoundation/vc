package credential

import (
	"testing"
)

// claimpath.TestTreeFilter covers what a VCTM lets through.
func TestFilterAgainstVCTM_NilVCTM(t *testing.T) {
	doc := map[string]any{"anything": 1}
	got, err := FilterAgainstVCTM(doc, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty result for nil VCTM, got %v", got)
	}
}
