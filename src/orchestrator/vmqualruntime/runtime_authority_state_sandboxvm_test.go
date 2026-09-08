//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualartifact"
)

func TestQualificationArtifactCAIsStableAcrossStagedRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-admission")
	var firstCA, firstCertificate []byte
	for attempt := range 2 {
		certificate, ca, err := vmqualartifact.GenerateCertificate(artifactReleaseHostname, time.Now().UTC(), backupFixtureHostname)
		if err != nil {
			t.Fatal(err)
		}
		certificate, ca, err = persistQualificationArtifactTLS(path, "qualified-run", certificate, ca)
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			firstCA, firstCertificate = ca, certificate.Certificate[0]
		} else if !bytes.Equal(ca, firstCA) || !bytes.Equal(certificate.Certificate[0], firstCertificate) {
			t.Fatal("restart invalidated artifact trust installed in an admitted guest")
		}
	}
}

func TestQualificationAuthorityRestartPreservesEveryGuestIdentity(t *testing.T) {
	config := vmnet.DefaultConfig()
	plan, err := vmnet.Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private-admission")
	create := func(plan vmnet.NetworkPlan) *qualificationNATSAuthority {
		t.Helper()
		value, err := newQualificationNATSAuthority(plan)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	first, err := persistQualificationAuthority(path, plan, create(plan))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.close)
	second, err := persistQualificationAuthority(path, plan, create(plan))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.close)
	if !bytes.Equal(first.ca, second.ca) || !bytes.Equal(first.server.Certificate[0], second.server.Certificate[0]) || first.controller.publicKey != second.controller.publicKey {
		t.Fatal("restart changed root transport admission")
	}
	for host, identity := range first.guests {
		restored := second.guests[host]
		if restored.publicKey != identity.publicKey || !bytes.Equal(restored.certificate, identity.certificate) || first.memberships[host].PublicKey != second.memberships[host].PublicKey {
			t.Fatalf("restart changed guest %s admission", host)
		}
		message := []byte("authenticated restart probe")
		signature, err := restored.pair.Sign(message)
		if err != nil || identity.pair.Verify(message, signature) != nil {
			t.Fatalf("restored NKey could not authenticate %s: %v", host, err)
		}
	}
	for candidate, identity := range first.commandSigners {
		if second.commandSigners[candidate].PublicKey != identity.PublicKey {
			t.Fatalf("restart changed command signer %s", candidate)
		}
	}
	config.RunID = "0123456789abcdef0123456789abcdef"
	otherPlan, err := vmnet.Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistQualificationAuthority(path, otherPlan, create(otherPlan)); err == nil {
		t.Fatal("reused another run's private transport admission")
	}
	if err := os.WriteFile(filepath.Join(path, "transport-authority.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := persistQualificationAuthority(path, plan, create(plan)); err == nil {
		t.Fatal("regenerated missing fields in a corrupt committed authority")
	}
}
