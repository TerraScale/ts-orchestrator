package managedmaterial

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

func admittedInitialFixture(t *testing.T) (placement.Intent, PreparationReceipt) {
	t.Helper()
	service, spec, _, _ := preparationFixture(t)
	root := "/srv/terrabase-managed"
	for index, member := range spec.Members {
		path, err := host.ManagedMaterialPath(root, host.ManagedMemberBinding{Scope: host.MemberScope{
			ClusterID: spec.Scope.ClusterID, TenantID: spec.Scope.TenantID,
			DatabaseID: spec.Scope.DatabaseID, ShardID: spec.Scope.ShardID,
			MemberID: member.MemberID, Incarnation: member.Incarnation,
		}, HostAttempt: 1})
		if err != nil {
			t.Fatal(err)
		}
		spec.Members[index].MaterialDirectory = path
	}
	receipt, err := service.PrepareInitial(t.Context(), 9, "partition-a", spec, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	intent := placement.Intent{SchemaVersion: placement.IntentSchemaVersion, DatabaseID: spec.PlacementDatabaseID,
		PartitionID: "partition-a", ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1,
		CanonicalRoster: placement.CanonicalRoster{ClusterID: spec.Scope.ClusterID, TenantID: spec.Scope.TenantID,
			DatabaseID: spec.Scope.DatabaseID, ShardID: spec.Scope.ShardID,
			Authority: placement.AuthorityReference{Version: 2, Epoch: spec.Scope.Epoch,
				ConfigurationID: receipt.AuthorityConfigurationID, CertificateSHA256: receipt.AuthoritySHA256,
				TrustedKeySHA256: receipt.TrustedKeySHA256}},
		ManagedHostProfiles: []placement.ManagedHostProfile{{Region: oci.RegionGRU,
			Compute:            placement.ComputeTuple{Shape: "VM.Standard.E4.Flex", WholeOCPUs: 1, MemoryInGBs: 6},
			ProcessMemoryBytes: 4 << 30, MemoryHeadroomBytes: 1 << 30,
			CgroupMemoryMaxBytes: 4 << 30, SystemReserveBytes: 1 << 30,
			AllocatableMemoryBytes: 5 << 30}}}
	for index, member := range spec.Members {
		peer := spec.Members[index^1]
		pins := receipt.Members[index]
		targetDigest, err := spec.LiveS3.Digest()
		if err != nil {
			t.Fatal(err)
		}
		intent.CanonicalRoster.Rows = append(intent.CanonicalRoster.Rows, placement.CanonicalRosterRow{
			Region: oci.RegionGRU, SeatID: member.SeatID, FailureDomain: member.FailureDomain,
			MemberID: member.MemberID, Incarnation: member.Incarnation,
			TLSLeafSHA256: pins.TLSLeafSHA256, ServerName: member.ServerName})
		intent.RuntimeManifests = append(intent.RuntimeManifests, placement.RuntimeManifest{
			Region: oci.RegionGRU, SeatID: member.SeatID,
			ArtifactDigest: strings.Repeat("d", 64), SourceDigest: strings.Repeat("e", 64),
			ManagedRuntimeRoot: root, FileSystemUUID: "018f0000-0000-7000-8000-00000000000" + strconv.Itoa(index+1),
			FileSystemType: "ext4", TrustedKeySHA256: receipt.TrustedKeySHA256,
			ServerCertificateSHA256: pins.Files["server.crt"], ServerPrivateKeySHA256: pins.Files["server.key"],
			ClientCARootsSHA256:                 pins.Files["client-ca.pem"],
			ClientManagedMaterialManifestSHA256: pins.Files["client-managed-manifest.json"],
			LiveS3ConfigSHA256:                  pins.Files["signed-v2-s3-config.json"],
			LiveS3TargetSHA256:                  targetDigest,
			LiveS3Credential:                    spec.LiveS3.Credential,
			ReplicationListenAddress:            net.JoinHostPort(member.ReplicationIP, strconv.Itoa(int(member.ReplicationPort))),
			ReplicationPeerMemberID:             peer.MemberID,
			ReplicationPeerAddress:              net.JoinHostPort(peer.ReplicationIP, strconv.Itoa(int(peer.ReplicationPort))),
			ReplicationServerCASHA256:           pins.Files["server-ca.pem"],
		})
	}
	return intent, receipt
}

func TestVerifyIntentAgainstReceiptRejectsMaterialAndPrivateIPSubstitution(t *testing.T) {
	intent, receipt := admittedInitialFixture(t)
	if err := VerifyIntentAgainstReceipt(intent, receipt); err != nil {
		t.Fatalf("matching committed initial material was rejected: %v", err)
	}
	foreignRegion := receipt
	foreignRegion.Spec.LiveS3.Region = "us-sanjose-1"
	if err := VerifyIntentAgainstReceipt(intent, foreignRegion); err == nil {
		t.Fatal("receipt with foreign live S3 region was admitted")
	}
	for _, test := range []struct {
		name string
		edit func(*placement.Intent)
	}{
		{"authority", func(value *placement.Intent) {
			value.CanonicalRoster.Authority.CertificateSHA256 = strings.Repeat("a", 64)
		}},
		{"leaf", func(value *placement.Intent) { value.CanonicalRoster.Rows[0].TLSLeafSHA256 = strings.Repeat("a", 64) }},
		{"server key", func(value *placement.Intent) {
			value.RuntimeManifests[0].ServerPrivateKeySHA256 = strings.Repeat("a", 64)
		}},
		{"private IP", func(value *placement.Intent) { value.RuntimeManifests[0].ReplicationListenAddress = "10.0.0.99:9443" }},
		{"peer IP", func(value *placement.Intent) { value.RuntimeManifests[0].ReplicationPeerAddress = "10.0.0.99:9443" }},
		{"material path", func(value *placement.Intent) { value.RuntimeManifests[0].ManagedRuntimeRoot = "/srv/other-managed" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := intent
			changed.CanonicalRoster.Rows = append([]placement.CanonicalRosterRow(nil), intent.CanonicalRoster.Rows...)
			changed.RuntimeManifests = append([]placement.RuntimeManifest(nil), intent.RuntimeManifests...)
			test.edit(&changed)
			if err := VerifyIntentAgainstReceipt(changed, receipt); err == nil {
				t.Fatal("substituted initial material was admitted")
			}
		})
	}
}
