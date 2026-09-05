package vmcontrolseed

import (
	"encoding/json"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"testing"
)

func TestMaterialRejectsSameTLSKeyWithDifferentPEM(t *testing.T) {
	materials, err := GenerateGRU("identity-test", []Guest{{ID: "gru-one", Address: "10.77.0.10", MembershipPublicKey: membershipPublic(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range materials {
			m.Clear()
		}
	}()
	for _, role := range []string{"reader", "provisioner", "snapshot"} {
		t.Run(role, func(t *testing.T) {
			m := materials["gru-one"].Clone()
			defer m.Clear()
			var c initialgrant.Config
			if err := json.Unmarshal([]byte(m.Settings), &c); err != nil {
				t.Fatal(err)
			}
			certificate := append(append([]byte(nil), m.Files[CertificatePath]...), '\n')
			key := append(append([]byte(nil), m.Files[PrivateKeyPath]...), '\n')
			if role == "reader" {
				m.Files[AuthorityCertificatePath] = certificate
				m.Files[AuthorityPrivateKeyPath] = key
				c.AuthorityReader.CertificateSHA256 = digest(certificate)
			} else if role == "snapshot" {
				m.Files[SnapshotCertificatePath] = certificate
				m.Files[SnapshotPrivateKeyPath] = key
				c.Regional.SnapshotReader.TLS.CertificateSHA256 = digest(certificate)
				c.Global.SnapshotReader.TLS.CertificateSHA256 = digest(certificate)
			} else {
				m.Files[ProvisionerCertificatePath] = certificate
				m.Files[ProvisionerPrivateKeyPath] = key
				c.Regional.Provisioner.TLS.CertificateSHA256 = digest(certificate)
				c.Global.Provisioner.TLS.CertificateSHA256 = digest(certificate)
			}
			data, _ := json.Marshal(c)
			m.Settings = string(data)
			if err := m.Validate(); err == nil {
				t.Fatal("same TLS key accepted with differently encoded certificate/private key")
			}
		})
	}
}
