//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"testing"
)

func TestQualificationCommandKeysAreSeparateAndWiped(t *testing.T) {
	_, authority := startDeliveryTestNATS(t)
	if len(authority.commandSigners) == 0 {
		t.Fatal("planned command trust absent")
	}
	var privateCopies [][]byte
	for _, signer := range authority.commandSigners {
		if !bytes.Contains(signer.PrivatePEM, []byte("PRIVATE KEY")) {
			t.Fatal("runner signing private key missing")
		}
		for _, member := range authority.memberships {
			if signer.PublicKey == member.PublicKey {
				t.Fatal("command signer reused membership identity")
			}
		}
		privateCopies = append(privateCopies, signer.PrivatePEM)
	}
	authority.close()
	for _, private := range privateCopies {
		for _, value := range private {
			if value != 0 {
				t.Fatal("command private key survived close")
			}
		}
	}
}
