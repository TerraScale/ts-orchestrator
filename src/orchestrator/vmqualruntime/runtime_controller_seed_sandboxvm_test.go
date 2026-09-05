//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

func TestGuestBootstrapSignsConfiguredGRUManifest(t *testing.T) {
	plan, err := vmnet.Plan(vmnet.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newQualificationNATSAuthority(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.close()
	var guests []vmcontrolseed.Guest
	for _, region := range plan.Regions {
		if region.Code != vmnet.GRU {
			continue
		}
		for _, guest := range region.Guests {
			guests = append(guests, vmcontrolseed.Guest{ID: guest.ID, Address: guest.Address, CommandPrivateKey: authority.commandSigners["gru-controller-"+guest.ID].PrivatePEM})
		}
	}
	seeds, err := vmcontrolseed.GenerateGRU(plan.RunID, guests)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, seed := range seeds {
			seed.Clear()
		}
	}()
	artifacts := []guestArtifactInput{{manifest: vmimage.GuestArtifact{Component: "orchestrator", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}}, {manifest: vmimage.GuestArtifact{Component: "terrabase", Version: "1.0.0", SHA256: strings.Repeat("b", 64)}}, {manifest: vmimage.GuestArtifact{Component: "ts-node", Version: "1.0.0", SHA256: strings.Repeat("c", 64)}, binary: []byte("signed binary fixture"), signature: make([]byte, ed25519.SignatureSize)}}
	manifest, err := desiredHostManifest(artifacts, 8443)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := vmqualbootstrap.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	services := &qualificationRuntimeServices{plan: plan, natsAuthority: authority, controlSeeds: seeds, artifacts: artifacts, manifest: manifest, bootstrapIssuer: issuer}
	for _, guest := range guests {
		result, _, err := services.Bootstrap(vmqual.Guest{ID: guest.ID, Region: vmnet.GRU})
		if err != nil {
			t.Fatal(err)
		}
		defer result.Controller.Clear()
		if len(result.MembershipPins) != len(guests) || bytes.Equal(result.Controller.Files[vmcontrolseed.CAPath], result.NATSIdentity.TLSCA) {
			t.Fatal("guest control scope or transport separation lost")
		}
		grant, err := hostagent.VerifyBootstrapGrant(guest.ID, result.InitialGrant.PublicKeyPEM, result.InitialGrant.SignedGrant)
		if err != nil {
			t.Fatal(err)
		}
		granted, err := hostmanifest.CanonicalHostManifestJSON(grant.Manifest)
		if err != nil || !bytes.Equal(granted, result.DesiredHostManifest) {
			t.Fatal("grant does not bind full configured manifest")
		}
		configured, err := hostmanifest.ParseHostManifest(result.DesiredHostManifest)
		if err != nil {
			t.Fatal(err)
		}
		if configured.Components[0].Arguments != "run --config @config" || configured.Components[0].Configuration != result.Controller.Settings || !strings.HasPrefix(configured.Components[0].Version, "ctl-") {
			t.Fatal("configured immutable launch missing")
		}
		again, _, err := services.Bootstrap(vmqual.Guest{ID: guest.ID, Region: vmnet.GRU})
		if err != nil {
			t.Fatal(err)
		}
		defer again.Controller.Clear()
		if !bytes.Equal(result.DesiredHostManifest, again.DesiredHostManifest) {
			t.Fatal("bootstrap manifest changed")
		}
	}
	if _, _, err := services.Bootstrap(vmqual.Guest{ID: "sfo-member-1", Region: vmnet.SFO}); err == nil || !strings.Contains(err.Error(), "admitted allocation") {
		t.Fatalf("non-GRU bootstrap: %v", err)
	}
}
