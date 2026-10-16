package cli

import (
	"bytes"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func readFounderIdentity(path string) (bootstrapstart.BakedIdentity, error) {
	wire, err := readBoundedRegular(path, 4096)
	if err != nil {
		return bootstrapstart.BakedIdentity{}, err
	}
	var identity bootstrapstart.BakedIdentity
	if err := protocol.DecodeStrict(wire, &identity, 4096); err != nil {
		return bootstrapstart.BakedIdentity{}, err
	}
	canonical, err := protocol.EncodeJSON(identity)
	if err != nil || !bytes.Equal(wire, canonical) || identity.SchemaVersion != 1 {
		return bootstrapstart.BakedIdentity{}, errors.New("founder identity must be canonical version-1 JSON")
	}
	return identity, nil
}
