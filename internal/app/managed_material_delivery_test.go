package app

import (
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

func TestDesiredMaterialMatchesReceiptPinsSQLAndBackupDigests(t *testing.T) {
	const (
		configuration = "1111111111111111111111111111111111111111111111111111111111111111"
		certificate   = "2222222222222222222222222222222222222222222222222222222222222222"
		leaf          = "3333333333333333333333333333333333333333333333333333333333333333"
		sqlBundle     = "4444444444444444444444444444444444444444444444444444444444444444"
	)
	manifest := placement.RuntimeManifest{
		Region: oci.RegionGRU, SeatID: "000000000082AXF7GZQT1D126Y", ArtifactDigest: strings.Repeat("d", 64),
		SourceDigest: strings.Repeat("e", 64), TrustedKeySHA256: strings.Repeat("f", 64),
		ServerCertificateSHA256: strings.Repeat("1", 64), ServerPrivateKeySHA256: strings.Repeat("2", 64),
		ClientCARootsSHA256: strings.Repeat("3", 64), ClientManagedMaterialManifestSHA256: strings.Repeat("5", 64),
		SQLSchemaBundleSHA256: sqlBundle, LiveS3ConfigSHA256: strings.Repeat("6", 64),
		LiveS3TargetSHA256: strings.Repeat("7", 64), ReplicationListenAddress: "10.0.0.11:7000",
		BackupManifestSHA256: strings.Repeat("a", 64), BackupS3ConfigSHA256: strings.Repeat("b", 64),
		BackupS3TargetSHA256: strings.Repeat("c", 64), BackupS3CredentialSHA256: strings.Repeat("d", 64),
		BackupDataKeySHA256: strings.Repeat("e", 64), BackupOwner: true,
		BackupS3Credential:      oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.backup", VersionNumber: 4},
		BackupDataKey:           oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.backupkey", VersionNumber: 5},
		ReplicationPeerMemberID: "20000000000000000000000002",
		ReplicationPeerAddress:  "10.0.0.12:7001", ReplicationServerCASHA256: strings.Repeat("8", 64),
	}
	intent := placement.Intent{ActiveRegions: []oci.Region{oci.RegionGRU},
		CanonicalRoster:  placement.CanonicalRoster{Authority: placement.AuthorityReference{Epoch: 1}},
		RuntimeManifests: []placement.RuntimeManifest{manifest}}
	seat := managedmaterial.InitialMember{SeatID: manifest.SeatID, MemberID: "20000000000000000000000001",
		Incarnation: "01010101010101010101010101010101"}
	receipt := managedmaterial.PreparationReceipt{
		AuthorityConfigurationID: configuration, AuthoritySHA256: certificate,
		Spec: managedmaterial.InitialSpec{Scope: managedmaterial.AuthorityScope{
			ClusterID: "01081G81860W40J2GB1G6GW3RG", TenantID: "0G000000000000000000000001",
			DatabaseID: "10000000000000000000000001", ShardID: 7,
		}, Members: [2]managedmaterial.InitialMember{seat}},
		Members: [2]managedmaterial.MemberPins{{MemberID: seat.MemberID, TLSLeafSHA256: leaf}},
	}
	launch := &host.ManagedMemberLaunch{
		Member: host.ManagedMemberBinding{Scope: host.MemberScope{
			ClusterID: receipt.Spec.Scope.ClusterID, TenantID: receipt.Spec.Scope.TenantID,
			DatabaseID: receipt.Spec.Scope.DatabaseID, ShardID: receipt.Spec.Scope.ShardID,
			MemberID: seat.MemberID, Incarnation: seat.Incarnation,
		}},
		Authority: host.MemberAuthority{Epoch: 1, ConfigurationID: configuration,
			CertificateSHA256: certificate, TLSLeafSHA256: leaf},
		SourceDigest: manifest.SourceDigest,
		Runtime: &host.ManagedRuntimePins{
			TrustedKeySHA256:                    manifest.TrustedKeySHA256,
			ServerCertificateSHA256:             manifest.ServerCertificateSHA256,
			ServerPrivateKeySHA256:              manifest.ServerPrivateKeySHA256,
			ClientCARootsSHA256:                 manifest.ClientCARootsSHA256,
			ClientManagedMaterialManifestSHA256: manifest.ClientManagedMaterialManifestSHA256,
			SQLSchemaBundleSHA256:               manifest.SQLSchemaBundleSHA256,
			LiveS3ConfigSHA256:                  manifest.LiveS3ConfigSHA256, LiveS3TargetSHA256: manifest.LiveS3TargetSHA256,
			BackupManifestSHA256:     manifest.BackupManifestSHA256,
			BackupS3ConfigSHA256:     manifest.BackupS3ConfigSHA256,
			BackupS3TargetSHA256:     manifest.BackupS3TargetSHA256,
			BackupS3CredentialSHA256: manifest.BackupS3CredentialSHA256,
			BackupDataKeySHA256:      manifest.BackupDataKeySHA256,
			BackupOwner:              manifest.BackupOwner, BackupS3Credential: manifest.BackupS3Credential,
			BackupDataKey:             manifest.BackupDataKey,
			ReplicationListenAddress:  manifest.ReplicationListenAddress,
			ReplicationPeerMemberID:   manifest.ReplicationPeerMemberID,
			ReplicationPeerAddress:    manifest.ReplicationPeerAddress,
			ReplicationServerCASHA256: manifest.ReplicationServerCASHA256,
		},
	}
	desired := host.Desired{Digest: manifest.ArtifactDigest, ManagedMember: launch}
	if !desiredMaterialMatchesReceipt(desired, intent, receipt, 0, false) {
		t.Fatal("host desired with the receipt-pinned SQL bundle was rejected")
	}
	launch.Runtime.SQLSchemaBundleSHA256 = strings.Repeat("9", 64)
	if desiredMaterialMatchesReceipt(desired, intent, receipt, 0, false) {
		t.Fatal("host desired with a substituted SQL bundle pin was admitted")
	}
	launch.Runtime.SQLSchemaBundleSHA256 = manifest.SQLSchemaBundleSHA256
	launch.Runtime.BackupS3Credential.VersionNumber++
	if desiredMaterialMatchesReceipt(desired, intent, receipt, 0, false) {
		t.Fatal("host desired with a substituted backup credential version was admitted")
	}
}
