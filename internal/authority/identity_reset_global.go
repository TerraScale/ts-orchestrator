package authority

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// IdentityResetGlobalLease pins the home region's opaque global predecessor.
// Its root-signed replacement uses the same transaction and deployment.
type IdentityResetGlobalLease struct {
	PreviousSequence uint64 `json:"previous_sequence"`
	PreviousSHA256   string `json:"previous_sha256"`
	EpochFloor       uint64 `json:"epoch_floor"`
	Epoch            uint64 `json:"epoch"`
}

func (pin IdentityResetGlobalLease) validate(reset IdentityReset) error {
	if reset.Scope == protocol.GlobalScope || reset.LastSequence > ^uint64(0)-2 || pin.PreviousSequence > reset.LastSequence ||
		pin.PreviousSequence == 0 && (pin.PreviousSHA256 != "" || pin.EpochFloor != 0) ||
		pin.PreviousSequence != 0 && (!validTerminalDigest(pin.PreviousSHA256) || pin.EpochFloor == 0) ||
		pin.Epoch <= pin.EpochFloor || pin.Epoch == ^uint64(0) {
		return errors.New("identity reset global lease has invalid opaque predecessor or epoch")
	}
	return nil
}
