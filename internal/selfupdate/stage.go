package selfupdate

import (
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ReceiptPolicy verifies a release receipt for this node. Per-source
// receipts use the existing root-delegated release path. Update receipts
// signed automatically under a scoped binary update delegation use the same
// mandatory scope and current-root verification.
type ReceiptPolicy struct {
	Roots        trust.Keyring
	Environment  string
	Cell         string
	Architecture string
}

// Verifier is the receipt check Stage applies before any byte is kept.
type Verifier interface {
	Verify(receiptWire, delegationWire []byte, now time.Time) (release.VerifiedBinary, error)
}

// ReleaseReceipt returns the signed receipt and delegation a staged release
// was verified with, once the release's ownership and bytes verify. The
// baked release has neither, so it fails.
func (layout Layout) ReleaseReceipt(digest string) (receiptWire, delegationWire []byte, err error) {
	if err := layout.VerifyRelease(digest); err != nil {
		return nil, nil, err
	}
	wires := make([][]byte, 2)
	for index, name := range []string{receiptFile, delegationFile} {
		path := filepath.Join(layout.ReleaseDir(digest), name)
		if err := layout.checkOwned(path, false); err != nil {
			return nil, nil, err
		}
		if wires[index], err = readBounded(path, trust.MaxEnvelopeBytes); err != nil {
			return nil, nil, err
		}
	}
	return wires[0], wires[1], nil
}
