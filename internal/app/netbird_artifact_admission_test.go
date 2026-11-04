package app

import (
	"encoding/binary"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

func netbirdArtifactELF(architecture string) []byte {
	body := netbirdStageELF("verified " + architecture + " client")
	if architecture == "arm64" {
		binary.LittleEndian.PutUint16(body[18:], 183)
	}
	return body
}

func netbirdArtifactTestPin(t *testing.T) client.Pin {
	t.Helper()
	pin := netbirdStageTestPin(t, netbirdArtifactELF("amd64"))
	pin.Archives.Arm64.BinarySHA256 = netbirdStageDigest(netbirdArtifactELF("arm64"))
	return pin
}
