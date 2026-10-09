package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestInstallContinuitySignVerifyAndFinalRecheck(t *testing.T) {
	proof, rootPrivateKey, roots, now := installContinuityFixture(t)
	envelope, err := SignInstallContinuity(proof, now, now.Add(time.Hour), rootPrivateKey)
	if err != nil {
		t.Fatalf("SignInstallContinuity() error = %v", err)
	}
	verified := verifyInstallContinuityFixture(t, envelope, proof, roots, now)
	if !verified.IsVerified() || verified.Digest() != digestBytes(mustContinuityWire(t, envelope)) ||
		verified.SelectorGeneration() != proof.SelectorGeneration {
		t.Fatalf("verified proof did not preserve exact selected identity: %+v", verified)
	}
	if err := verified.FinalRecheck(now.Add(30*time.Minute), proof.SelectorGeneration,
		verified.SelectorSHA256()); err != nil {
		t.Fatalf("FinalRecheck() error = %v", err)
	}
	if err := verified.FinalRecheck(now.Add(30*time.Minute), proof.SelectorGeneration+1,
		verified.SelectorSHA256()); err == nil {
		t.Fatal("final recheck accepted a different selector generation")
	}
	if err := verified.FinalRecheck(now.Add(30*time.Minute), proof.SelectorGeneration,
		digestBytes([]byte("different selector"))); err == nil {
		t.Fatal("final recheck accepted a different selector wire")
	}
	if err := verified.FinalRecheck(now.Add(time.Hour), proof.SelectorGeneration,
		verified.SelectorSHA256()); err == nil {
		t.Fatal("final recheck accepted an expired root signature")
	}
	copy := verified.Continuity()
	copy.MaterialSHA256["client.creds"] = digestBytes([]byte("mutated"))
	if verified.Continuity().MaterialSHA256["client.creds"] == copy.MaterialSHA256["client.creds"] {
		t.Fatal("Continuity() exposed its internal material map")
	}
}

func TestInstallContinuityRejectsWrongBindingsAndProofType(t *testing.T) {
	proof, rootPrivateKey, roots, now := installContinuityFixture(t)
	envelope, err := SignInstallContinuity(proof, now, now.Add(time.Hour), rootPrivateKey)
	if err != nil {
		t.Fatalf("SignInstallContinuity() error = %v", err)
	}
	base := installContinuityExpectation(t, proof, envelope)
	for _, test := range []struct {
		name   string
		mutate func(*InstallContinuityExpectation)
	}{
		{name: "accepted marker", mutate: func(expected *InstallContinuityExpectation) {
			expected.Install.AcceptedMarkerSHA256 = digestBytes([]byte("other marker"))
		}},
		{name: "ledger result", mutate: func(expected *InstallContinuityExpectation) {
			expected.Install.ResultSHA256 = digestBytes([]byte("other result"))
		}},
		{name: "instance", mutate: func(expected *InstallContinuityExpectation) {
			expected.Install.InstanceOCID = "ocid1.instance.oc1..other"
		}},
		{name: "credential inventory", mutate: func(expected *InstallContinuityExpectation) {
			expected.Install.CredentialSHA256 = digestBytes([]byte("other credentials"))
		}},
		{name: "selected generation", mutate: func(expected *InstallContinuityExpectation) {
			expected.SelectorGeneration++
		}},
		{name: "selector proof pin", mutate: func(expected *InstallContinuityExpectation) {
			expected.PinnedContinuitySHA256 = digestBytes([]byte("other continuity proof"))
		}},
		{name: "malformed selector snapshot", mutate: func(expected *InstallContinuityExpectation) {
			expected.SelectorSHA256 = "invalid"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			expected := base
			expected.Install = cloneInstallContinuity(base.Install)
			test.mutate(&expected)
			if _, err := VerifyCurrentInstallContinuity(envelope, roots, expected, now,
				InstallContinuityTrustPolicy()); err == nil {
				t.Fatal("VerifyCurrentInstallContinuity() accepted a wrong binding")
			}
		})
	}

	wrongDomain := envelope
	wrongDomain.Scope.Domain = "terrascale.bootstrap.manifest"
	wrongDomainExpectation := base
	wrongDomainExpectation.PinnedContinuitySHA256 = digestBytes(mustContinuityWire(t, wrongDomain))
	if _, err := VerifyCurrentInstallContinuity(wrongDomain, roots, wrongDomainExpectation, now,
		InstallContinuityTrustPolicy()); err == nil {
		t.Fatal("manifest-domain signature was accepted as an install-continuity proof")
	}
}

func TestInstallContinuityBoundsCredentialExpiryAndCurrentInterval(t *testing.T) {
	proof, rootPrivateKey, roots, now := installContinuityFixture(t)
	if _, err := SignInstallContinuity(proof, now, proof.CredentialValidUntil.Add(time.Nanosecond),
		rootPrivateKey); err == nil {
		t.Fatal("signer allowed proof validity past the installed credential cutoff")
	}
	envelope, err := SignInstallContinuity(proof, now, now.Add(time.Hour), rootPrivateKey)
	if err != nil {
		t.Fatalf("SignInstallContinuity() error = %v", err)
	}
	expected := installContinuityExpectation(t, proof, envelope)
	if _, err := VerifyCurrentInstallContinuity(envelope, roots, expected, now.Add(time.Hour),
		InstallContinuityTrustPolicy()); err == nil {
		t.Fatal("current verifier accepted an expired root signature")
	}
	if _, err := VerifyCurrentInstallContinuity(envelope, roots, expected, proof.CredentialValidUntil,
		InstallContinuityTrustPolicy()); err == nil {
		t.Fatal("current verifier accepted expired installed credentials")
	}
}

func TestInstallContinuityRejectsMalformedAndOversizedPayloads(t *testing.T) {
	proof, rootPrivateKey, roots, now := installContinuityFixture(t)
	baseEnvelope, err := SignInstallContinuity(proof, now, now.Add(time.Hour), rootPrivateKey)
	if err != nil {
		t.Fatalf("SignInstallContinuity() error = %v", err)
	}
	expected := installContinuityExpectation(t, proof, baseEnvelope)

	malformedPayload, err := trust.Sign([]byte(`{"schemaVersion":1,"unknown":true}`),
		installContinuityScope(proof), now, now.Add(time.Hour), rootPrivateKey)
	if err != nil {
		t.Fatalf("sign malformed typed payload: %v", err)
	}
	malformedExpected := expected
	malformedExpected.PinnedContinuitySHA256 = digestBytes(mustContinuityWire(t, malformedPayload))
	if _, err := VerifyCurrentInstallContinuity(malformedPayload, roots, malformedExpected, now,
		InstallContinuityTrustPolicy()); err == nil {
		t.Fatal("verifier accepted unknown proof payload members")
	}

	largePayload := []byte(`{"padding":"` + strings.Repeat("x", MaxInstallContinuityBytes) + `"}`)
	oversizedPayload, err := trust.Sign(largePayload, installContinuityScope(proof), now,
		now.Add(time.Hour), rootPrivateKey)
	if err != nil {
		t.Fatalf("sign oversized test payload: %v", err)
	}
	if _, err := VerifyCurrentInstallContinuity(oversizedPayload, roots, expected, now,
		InstallContinuityTrustPolicy()); err == nil {
		t.Fatal("verifier accepted an oversized signed payload")
	}

	oversizedEnvelope := baseEnvelope
	oversizedEnvelope.Signature = strings.Repeat("x", MaxInstallContinuityWireBytes)
	if _, err := VerifyCurrentInstallContinuity(oversizedEnvelope, roots, expected, now,
		InstallContinuityTrustPolicy()); err == nil {
		t.Fatal("verifier accepted an oversized signed envelope")
	}
}

func TestInstallContinuityCredentialDigestIsDeterministicAndValidated(t *testing.T) {
	first := map[string]string{"a.creds": digestBytes([]byte("a")), "b.pem": digestBytes([]byte("b"))}
	second := map[string]string{"b.pem": digestBytes([]byte("b")), "a.creds": digestBytes([]byte("a"))}
	firstDigest, err := InstallContinuityCredentialDigest(first)
	if err != nil {
		t.Fatalf("InstallContinuityCredentialDigest(first) error = %v", err)
	}
	secondDigest, err := InstallContinuityCredentialDigest(second)
	if err != nil {
		t.Fatalf("InstallContinuityCredentialDigest(second) error = %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("map insertion order changed digest: %s != %s", firstDigest, secondDigest)
	}
	if _, err := InstallContinuityCredentialDigest(map[string]string{"../bad": digestBytes([]byte("a"))}); err == nil {
		t.Fatal("credential digest accepted an invalid file name")
	}
}

func installContinuityFixture(t *testing.T) (InstallContinuity, ed25519.PrivateKey, trust.Keyring, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 26, 12, 0, 0, 0, time.UTC)
	materials := map[string]string{
		"client.creds": digestBytes([]byte("controller jwt and seed")),
		"client.pem":   digestBytes([]byte("client cert")),
	}
	credentialDigest, err := InstallContinuityCredentialDigest(materials)
	if err != nil {
		t.Fatal(err)
	}
	proof := InstallContinuity{
		SchemaVersion: InstallContinuitySchemaVersion,
		DeploymentID:  "0000000000F9PR1WNVDTEXS31Z", Environment: "production", ClusterID: "0000000000RMSAJ9B0JFV7ESHN",
		Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", Slot: "controller-a",
		GenesisAnchorSHA256:  digestBytes([]byte("genesis anchor")),
		AcceptedMarkerSHA256: digestBytes([]byte("accepted marker")),
		ManifestSHA256:       digestBytes([]byte("manifest")), ResultSHA256: digestBytes([]byte("ledger result")),
		ReceiptSHA256: digestBytes([]byte("instance receipt")), ImageReceiptSHA256: digestBytes([]byte("image receipt")),
		ImageOCID: "ocid1.image.oc1..image", InstanceOCID: "ocid1.instance.oc1..instance",
		PrimaryVNICOCID: "ocid1.vnic.oc1..vnic", PrimaryPrivateIP: "10.0.0.2",
		LedgerAttempt: 1, LedgerGeneration: 2, AcceptedAt: now.Add(-time.Hour),
		BinarySHA256: digestBytes([]byte("installed binary")), MaterialSHA256: materials,
		CredentialSHA256: credentialDigest, CredentialValidUntil: now.Add(2 * time.Hour),
		SelectorGeneration: 3,
	}
	return proof, privateKey, trust.Keyring{keyID: publicKey}, now
}

func installContinuityExpectation(t *testing.T, proof InstallContinuity,
	envelope trust.Envelope,
) InstallContinuityExpectation {
	t.Helper()
	selectorWire := []byte("canonical selected selector wire")
	return InstallContinuityExpectation{
		Install: cloneInstallContinuity(proof), SelectorGeneration: proof.SelectorGeneration,
		SelectorSHA256: digestBytes(selectorWire), PinnedContinuitySHA256: digestBytes(mustContinuityWire(t, envelope)),
	}
}

func verifyInstallContinuityFixture(t *testing.T, envelope trust.Envelope, proof InstallContinuity,
	roots trust.Keyring, now time.Time,
) VerifiedInstallContinuity {
	t.Helper()
	verified, err := VerifyCurrentInstallContinuity(envelope, roots,
		installContinuityExpectation(t, proof, envelope), now, InstallContinuityTrustPolicy())
	if err != nil {
		t.Fatalf("VerifyCurrentInstallContinuity() error = %v", err)
	}
	return verified
}

func mustContinuityWire(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// A proof for an install that adopted a material generation binds the
// generation's fingerprint, and only through the domain-separated digest.
func TestInstallContinuityBindsAMaterialGeneration(t *testing.T) {
	proof, rootPrivateKey, roots, now := installContinuityFixture(t)
	fingerprint := strings.Repeat("ab", 32)
	digest, err := InstallContinuityGenerationDigest(fingerprint)
	if err != nil || digest == fingerprint {
		t.Fatalf("generation digest %q: %v", digest, err)
	}
	if _, err := InstallContinuityGenerationDigest("not a fingerprint"); err == nil {
		t.Fatal("a malformed fingerprint was accepted")
	}
	proof.MaterialGenerationSHA256, proof.CredentialSHA256 = fingerprint, digest
	envelope, err := SignInstallContinuity(proof, now, now.Add(time.Hour), rootPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifyInstallContinuityFixture(t, envelope, proof, roots, now)
	for name, change := range map[string]func(*InstallContinuity){
		"the manifest credential digest with a generation": func(proof *InstallContinuity) {
			proof.CredentialSHA256, _ = InstallContinuityCredentialDigest(proof.MaterialSHA256)
		},
		"the generation digest without a generation": func(proof *InstallContinuity) { proof.MaterialGenerationSHA256 = "" },
		"another generation": func(proof *InstallContinuity) {
			proof.MaterialGenerationSHA256 = strings.Repeat("cd", 32)
		},
	} {
		changed := proof
		change(&changed)
		if _, err := SignInstallContinuity(changed, now, now.Add(time.Hour), rootPrivateKey); err == nil {
			t.Errorf("signed %s", name)
		}
	}
}
