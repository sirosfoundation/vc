package credential

import (
	"fmt"

	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// FilterAgainstVCTM returns a copy of doc containing only the claims the
// VCTM's claim paths declare (claimpath.Tree.Filter). This is the
// anti-PII-leak choke point for credentials whose document data is
// assembled from an external source (e.g. a presented credential's own
// claims): even if upstream forwards more claims than intended, only
// VCTM-declared paths reach the issuer.
//
// A path [address, locality] lets address.locality through and drops
// address.street. A path [address] keeps all of address. An array keeps
// each element at its index, so an indexed VCTM path selects the same
// element in the filtered document as in doc.
func FilterAgainstVCTM(doc map[string]any, vctm *sdjwtvc.VCTM) (map[string]any, error) {
	if vctm == nil {
		return map[string]any{}, nil
	}
	tree, err := vctm.ClaimTree()
	if err != nil {
		return nil, fmt.Errorf("VCTM %s: %w", vctm.VCT, err)
	}
	return tree.Filter(doc)
}
