package region

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func TestSignedReadAccessRequiresCurrentOwnedFoundation(t *testing.T) {
	store, client, write := foundationProtocolStore(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: entityid.New(), Cell: "GRU", Environment: "production", Role: "foundation", Slot: entityid.New()}
	reader := &SignedFootprint{client: client, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", Prefix: "bootstrap"},
		scope: scope, expires: now.Add(2 * time.Hour), roots: roots, tenancy: "ocid1.tenancy.oc1..test",
		home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1, OCIRegion: "eu-frankfurt-1"}}
	grant := FoundationGrant{InstallationID: reader.home.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: reader.tenancy,
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "scenario"}
	for _, entry := range []struct{ cell, region string }{{"GRU", "sa-saopaulo-1"}, {"FRA", "eu-frankfurt-1"}} {
		vault := "ocid1.vault.oc1." + entry.region + ".owned"
		grant.Regions = append(grant.Regions, FoundationIntent{Generation: 1,
			Plan: map[string]any{"cell": entry.cell, "region": entry.region, "tenancy_id": reader.tenancy,
				"parent_compartment_id": grant.ParentCompartmentID, "shared_compartment_id": grant.SharedCompartmentID,
				"resource_ids": map[string]any{"control_compartment": "ocid1.compartment.oc1..control", "vault": vault, "key": "ocid1.key.oc1." + entry.region + ".owned"}},
			ReadAccess: &ReadAccessIntent{URLs: []string{"https://" + entry.cell + ".example.test"}, UsageToken: vaultsecret.Ref{Vault: vault, Name: "usage-token"}}})
	}
	publish := func(signedScope trust.Scope, expiry time.Time, pin bool) {
		t.Helper()
		payload, err := trust.EncodePayload(grant)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, signedScope, now.Add(-time.Minute), expiry, private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if pin {
			digest := sha256.Sum256(wire)
			reader.home.GrantSHA256 = hex.EncodeToString(digest[:])
		}
		write("bootstrap/"+foundationGrantObject, wire)
	}
	publish(scope, now.Add(time.Hour), true)
	resolver := FoundationResolver{Footprint: reader, Store: store}
	if _, err := resolver.ReadAccess(t.Context(), ""); !errors.Is(err, ErrReadAccessPending) {
		t.Fatalf("missing durable record must stay pending: %v", err)
	}
	records, etags := map[string]FoundationRecord{}, map[string]string{}
	for _, intent := range grant.Regions {
		wire, err := json.Marshal(intent.Plan, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(wire)
		cell := intent.Plan["cell"].(string)
		ids := map[string]string{}
		for key, id := range intent.Plan["resource_ids"].(map[string]any) {
			ids[key] = id.(string)
		}
		record := FoundationRecord{SchemaVersion: 1, Cell: cell, OCIRegion: intent.Plan["region"].(string), TenancyID: reader.tenancy,
			ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID,
			Generation: 1, IntentDigest: hex.EncodeToString(digest[:]), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled",
			StartedAt: now, UpdatedAt: now, CompletedAt: now, ResourceIDs: ids}
		etag, err := store.CompareAndSwap(t.Context(), record, "")
		if err != nil {
			t.Fatal(err)
		}
		records[cell], etags[cell] = record, etag
	}
	access, err := resolver.ReadAccess(t.Context(), "")
	if err != nil || !access.IsVerified() || access.Cell() != "FRA" || access.OCIRegion() != "eu-frankfurt-1" || access.UsageToken() != grant.Regions[1].ReadAccess.UsageToken || !access.ExpiresAt().Equal(now.Add(time.Hour)) {
		t.Fatalf("signed home selection failed: access=%+v err=%v", access, err)
	}
	urls := access.URLs()
	urls[0] = "https://changed.example.test"
	if access.URLs()[0] != grant.Regions[1].ReadAccess.URLs[0] {
		t.Fatal("read access exposed mutable signed destinations")
	}
	if selected, err := resolver.ReadAccess(t.Context(), "GRU"); err != nil || selected.Cell() != "GRU" {
		t.Fatalf("explicit signed region failed: %v", err)
	}
	if _, err := resolver.ReadAccess(t.Context(), "SFO"); !errors.Is(err, ErrReadAccessPending) {
		t.Fatalf("unsigned region must stay pending: %v", err)
	}
	original := grant.Regions[1].ReadAccess
	for _, scenario := range []string{"no access", "foreign Vault", "plaintext", "credential URL", "path URL", "query URL", "bad port", "wrong signature scope", "expired", "changed pinned wire"} {
		t.Run(scenario, func(t *testing.T) {
			changed := *original
			changed.URLs = append([]string(nil), original.URLs...)
			grant.Regions[1].ReadAccess = &changed
			signedScope, expiry, pin := scope, now.Add(time.Hour), true
			switch scenario {
			case "no access":
				grant.Regions[1].ReadAccess = nil
			case "foreign Vault":
				changed.UsageToken.Vault = "ocid1.vault.oc1.eu-frankfurt-1.foreign"
			case "plaintext":
				changed.URLs[0] = "http://FRA.example.test"
			case "credential URL":
				changed.URLs[0] = "https://user:password@FRA.example.test"
			case "path URL":
				changed.URLs[0] += "/other"
			case "query URL":
				changed.URLs[0] += "?token=value"
			case "bad port":
				changed.URLs[0] += ":65536"
			case "wrong signature scope":
				signedScope.Cell = "FRA"
			case "expired":
				expiry = now.Add(-time.Second)
			case "changed pinned wire":
				changed.URLs[0] = "https://changed.example.test"
				pin = false
			}
			publish(signedScope, expiry, pin)
			if _, err := resolver.ReadAccess(t.Context(), "FRA"); err == nil {
				t.Fatal("unverified regional read access was returned")
			} else if scenario == "no access" && !errors.Is(err, ErrReadAccessPending) {
				t.Fatalf("absent signed access must stay pending: %v", err)
			}
			grant.Regions[1].ReadAccess = original
			publish(scope, now.Add(time.Hour), true)
		})
	}
	for _, scenario := range []string{"foreign current Vault", "stale generation", "unreconciled"} {
		t.Run(scenario, func(t *testing.T) {
			changed := records["FRA"]
			changed.ResourceIDs = maps.Clone(changed.ResourceIDs)
			switch scenario {
			case "foreign current Vault":
				changed.ResourceIDs["vault"] = "ocid1.vault.oc1.eu-frankfurt-1.foreign"
			case "stale generation":
				changed.Generation++
			case "unreconciled":
				changed.Stage, changed.BlockedReason, changed.CompletedAt = "blocked", "foundation-unavailable", time.Time{}
			}
			etag, err := store.CompareAndSwap(t.Context(), changed, etags["FRA"])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ReadAccess(t.Context(), "FRA"); err == nil {
				t.Fatal("read access outlived its current owned reconciled record")
			}
			etags["FRA"], err = store.CompareAndSwap(t.Context(), records["FRA"], etag)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
