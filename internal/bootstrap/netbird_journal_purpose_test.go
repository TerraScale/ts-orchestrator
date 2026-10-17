package bootstrap

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// This public intent fixture grants no signed source, native or issuer authority.
func journalPurposeIntent() NetBirdJournalPurpose {
	installation := entityid.Derive("journal-purpose-test-installation")
	allocation := func(role, slot string) NetBirdJournalAllocation {
		id := entityid.Derive("foundation-host-slot", installation, "GRU", role, slot)
		return NetBirdJournalAllocation{SlotID: id, OperationID: entityid.Derive("foundation-host-operation", installation, id),
			ProfileSHA256: strings.Repeat("a", 64), RecipeSHA256: strings.Repeat("b", 64)}
	}
	return NetBirdJournalPurpose{Purpose: NetBirdAccountJournalPurpose, InstallationID: installation,
		DeploymentID: entityid.Derive("journal-purpose-test-deployment"), ClusterID: entityid.Derive("journal-purpose-test-cluster"),
		Environment: "production", Cell: "GRU", SourcePlanSHA256: strings.Repeat("c", 64), SourceGeneration: 1,
		Manager: allocation("netbird-manager", "netbird-manager"), Writer: allocation("controller", "controller-a"),
		Storage: StorageDomain{Namespace: "ns", HeadBucket: "gru-1-head", LedgerBucket: "gru-1-ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "bootstrap"},
		Object:  "orchestrator/regions/v1/GRU.json", Actions: []string{"reserve", "complete"}, ExpiresAt: time.Now().UTC().Add(time.Minute),
		Underlay: NetBirdJournalUnderlayRecipe{ManagerVCNKey: "netbird_manager_vcn", ManagerSubnetKey: "netbird_manager_subnet", ManagerRouteTableKey: "netbird_manager_route",
			ManagerGatewayKey: "netbird_manager_local_peering_gateway", ManagerSecurityKey: "netbird_manager_security_list", ManagerNSGKey: "netbird_manager_nsg",
			WriterVCNKey: "vcn", WriterSubnetKey: "subnet", WriterRouteTableKey: "route_table", WriterGatewayKey: "netbird_writer_local_peering_gateway", WriterSecurityKey: "security_list", WriterNSGKey: "network_security_group",
			ManagerNetworkCIDR: "10.40.1.0/24", WriterNetworkCIDR: "10.40.0.0/24", WriterSubnetCIDR: "10.40.0.0/25", ManagerPrivateIP: "10.40.1.10", WriterPrivateIP: "10.40.0.10", Protocol: "6", Port: 443}}
}

func TestNetBirdJournalPurposeRejectsAuthorityExpansion(t *testing.T) {
	purpose := journalPurposeIntent()
	if err := purpose.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*NetBirdJournalPurpose){
		"extra action":              func(p *NetBirdJournalPurpose) { p.Actions = append(p.Actions, "retry") },
		"reordered actions":         func(p *NetBirdJournalPurpose) { p.Actions[0], p.Actions[1] = p.Actions[1], p.Actions[0] },
		"other object":              func(p *NetBirdJournalPurpose) { p.Object = "orchestrator/regions/v1/FRA.json" },
		"other allocation":          func(p *NetBirdJournalPurpose) { p.Writer = p.Manager },
		"other port":                func(p *NetBirdJournalPurpose) { p.Underlay.Port = 8443 },
		"public writer":             func(p *NetBirdJournalPurpose) { p.Underlay.WriterPrivateIP = "192.0.2.10" },
		"overlapping networks":      func(p *NetBirdJournalPurpose) { p.Underlay.ManagerNetworkCIDR = p.Underlay.WriterNetworkCIDR },
		"different logical gateway": func(p *NetBirdJournalPurpose) { p.Underlay.WriterGatewayKey = "internet_gateway" },
		"missing finite cap":        func(p *NetBirdJournalPurpose) { p.ExpiresAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := purpose.Clone()
			alter(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("expanded or substituted journal intent accepted")
			}
		})
	}
	if purpose.Actions[0] != "reserve" {
		t.Fatal("public clone changed retained actions")
	}
}

func TestNetBirdJournalPurposePublicIntentCannotMintCapability(t *testing.T) {
	intent := journalPurposeIntent()
	if _, err := intent.Digest(); err != nil {
		t.Fatal(err)
	}
	var proof VerifiedNetBirdJournalPurpose
	if proof.IsVerified() || proof.Revalidate(t.Context()) == nil || proof.MatchesStartup(t.Context(), DerivedStartupAuthority{}) == nil {
		t.Fatal("public intent or zero startup minted a verified journal purpose")
	}
	if _, err := proof.Limit(t.Context(), intent.ExpiresAt); err == nil {
		t.Fatal("expiry alone minted a verified journal purpose")
	}
	if _, err := (VerifiedStartupTemplate{}).NetBirdJournalPurposeForOperation(t.Context(), t.Context()); err == nil {
		t.Fatal("unsigned startup minted a journal purpose")
	}
}
