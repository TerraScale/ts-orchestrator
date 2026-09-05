package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func TestCandidatePreparationProducerBindsSignedInitialManifestWithoutCycle(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	now := time.Now().UTC()
	input := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{
		{Name: "orchestrator", Version: "1.2.3", ArtifactURL: "https://releases.terrascale.tech/orchestrator", SignatureURL: "https://releases.terrascale.tech/orchestrator.sig", Sha256: strings.Repeat("a", 64), User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100},
		{Name: "terrabase", Version: "1.2.3", ArtifactURL: "https://releases.terrascale.tech/terrabase", SignatureURL: "https://releases.terrascale.tech/terrabase.sig", Sha256: strings.Repeat("b", 64), User: "terrascale-terrabase", DataVolume: "/var/lib/terrascale/terrabase", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100},
	}}
	sourceRaw, err := hostmanifest.CanonicalHostManifestJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	sourceSigned, err := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "first-gru", NodeID: "gru-1", Manifest: sourceRaw, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	source, err := nodebootstrap.NewBootstrapAuthority("gru-1", public, sourceSigned)
	if err != nil {
		t.Fatal(err)
	}
	sourceDigest, err := hostmanifest.HostManifestSha256(input)
	if err != nil {
		t.Fatal(err)
	}
	grant := transitiongrant.Grant{Version: 1, TransitionID: "transition-1", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Source: transitiongrant.SourceIdentity{NodeID: "gru-1", ServerName: "gru-store", InitialGrantSHA256: source.Digest(), StoreScopeSHA256: strings.Repeat("c", 64)}, TargetEpoch: 2, MinimumControlEpoch: 1, Peers: []transitiongrant.Peer{{Region: "gru", NodeID: "gru-1", ServerName: "gru-store", BootstrapGrantSHA256: source.Digest(), PreparedManifestSHA256: sourceDigest}}}
	var configs []transitiongrant.Config
	for _, region := range []string{"sfo", "fra"} {
		config := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: grant.TransitionID, NodeID: region + "-1", Region: region, ServerName: region + "-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: "/etc/terrascale/candidate/grant.json", GrantPublicKeyFile: "/etc/terrascale/candidate/owner.pem"}
		manifest, err := PlanControlCandidateManifest(input, config)
		if err != nil {
			t.Fatal(err)
		}
		if input.Components[0].Configuration != "" {
			t.Fatal("producer mutated caller manifest")
		}
		again, err := PlanControlCandidateManifest(manifest, config)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hostmanifest.CanonicalHostManifestJSON(manifest)
		if err != nil {
			t.Fatal(err)
		}
		repeat, err := hostmanifest.CanonicalHostManifestJSON(again)
		if err != nil || !bytes.Equal(raw, repeat) {
			t.Fatal("preparation manifest not stable")
		}
		for i, c := range manifest.Components {
			if c.ArtifactURL != input.Components[i].ArtifactURL || c.SignatureURL != input.Components[i].SignatureURL || c.Sha256 != input.Components[i].Sha256 {
				t.Fatal("artifact identity altered")
			}
		}
		signed, err := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "first-" + region, NodeID: config.NodeID, Manifest: raw, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		peer, err := PlanControlCandidatePeer(config, public, signed)
		if err != nil {
			t.Fatal(err)
		}
		grant.Peers = append(grant.Peers, peer)
		configs = append(configs, config)
		changed := config
		changed.TransitionID = "different-transition"
		if _, err := PlanControlCandidatePeer(changed, public, signed); err == nil {
			t.Fatal("accepted transition outside signed manifest")
		}
		changed = config
		changed.GrantFile = "/etc/terrascale/candidate/other.json"
		if _, err := PlanControlCandidatePeer(changed, public, signed); err == nil {
			t.Fatal("accepted changed grant location")
		}
		signed[len(signed)-2] ^= 1
		if _, err := PlanControlCandidatePeer(config, public, signed); err == nil {
			t.Fatal("accepted modified bootstrap signature")
		}
	}
	signed, err := transitiongrant.SignGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := transitiongrant.VerifyGrant(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range configs {
		p := grant.Peers[i+1]
		if err := verified.CheckCandidate(now, c, p.BootstrapGrantSHA256, p.PreparedManifestSHA256); err != nil {
			t.Fatal(err)
		}
	}
	invalid := configs[0]
	invalid.Region = "gru"
	invalid.NodeID = "gru-1"
	if _, err := PlanControlCandidateManifest(input, invalid); err == nil {
		t.Fatal("initial GRU was changed into a candidate")
	}
	if _, err := PlanControlCandidateManifest(hostmanifest.HostManifest{Components: input.Components[1:]}, configs[0]); err == nil {
		t.Fatal("accepted absent orchestrator")
	}
}
