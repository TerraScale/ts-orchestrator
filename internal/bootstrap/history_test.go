package bootstrap

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (authority testBootstrapAuthority) delegationForInterval(t *testing.T, issuedAt, expiresAt time.Time) trust.Envelope {
	t.Helper()
	peerPublic, err := trust.EncodeDelegatedPublicKey(authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, authority.peerPublic), SubjectPublicKey: peerPublic,
		Capabilities: []trust.Capability{{
			Domain: peerReceiptDomain, DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: string(oci.RegionGRU),
			Environment: "production", Role: "controller", Slots: []string{"peer-b"}, Actions: []string{"sign"},
		}},
	}, issuedAt, expiresAt, authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return delegation
}
