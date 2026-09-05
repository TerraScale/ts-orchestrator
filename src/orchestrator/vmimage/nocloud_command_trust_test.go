package vmimage

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestNoCloudCommandTrustLoadsWithProductionVerifier(t *testing.T) {
	spec := validNoCloudSpec(t)
	material, err := canonicalTSNodeBootstrap(spec.TSNode, ArchitectureARM64)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		AuthorityBucket  string `json:"authorityBucket"`
		CommandTrustKeys []struct {
			CandidateID   string `json:"candidateId"`
			PublicKeyFile string `json:"publicKeyFile"`
		} `json:"commandTrustKeys"`
	}
	if err := json.Unmarshal(material.config, &config); err != nil {
		t.Fatal(err)
	}
	if config.AuthorityBucket != "ORCH_LEADERS" || len(config.CommandTrustKeys) != 1 || config.CommandTrustKeys[0].CandidateID != "gru-controller-gru-member-1" {
		t.Fatal("wire configuration lost command trust binding")
	}
	seed, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, file := range seed.RootFiles {
		if file.Path != config.CommandTrustKeys[0].PublicKeyFile {
			continue
		}
		if file.Mode != 0444 || file.Owner != "" || file.Validate() != nil || bytes.Contains(file.Content, []byte("PRIVATE KEY")) {
			t.Fatal("invalid public command key rootfile")
		}
		path := filepath.Join(t.TempDir(), "public.pem")
		if err := os.WriteFile(path, file.Content, 0444); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	if len(paths) != 1 {
		t.Fatal("command public key file missing")
	}
	if _, err := security.LoadCommandSignatureVerifierPEM(paths); err != nil {
		t.Fatal(err)
	}
}

func TestNoCloudCommandTrustRejectsMissingPrivateAndDuplicateKeys(t *testing.T) {
	for _, mutate := range []func(*TSNodeBootstrap){
		func(b *TSNodeBootstrap) { b.Config.AuthorityBucket = "" },
		func(b *TSNodeBootstrap) { b.Config.CommandTrustKeys = nil },
		func(b *TSNodeBootstrap) { b.Config.CommandTrustKeys[0].PublicKeyPEM = b.MembershipIdentityPrivateKey },
		func(b *TSNodeBootstrap) {
			b.Config.CommandTrustKeys = append(b.Config.CommandTrustKeys, b.Config.CommandTrustKeys[0])
		},
		func(b *TSNodeBootstrap) {
			duplicate := b.Config.CommandTrustKeys[0]
			duplicate.CandidateID = "other"
			b.Config.CommandTrustKeys = append(b.Config.CommandTrustKeys, duplicate)
		},
	} {
		spec := validNoCloudSpec(t)
		mutate(&spec.TSNode)
		if _, err := BuildNoCloudSeed(spec); err == nil {
			t.Fatal("invalid command trust accepted")
		}
	}
}
