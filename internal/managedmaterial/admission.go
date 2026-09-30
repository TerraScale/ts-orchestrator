package managedmaterial

import (
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

var initialHostFiles = [...]string{
	"authority.tbca", "trusted-public-key", "server.crt", "server.key",
	"server-ca.pem", "client-ca.pem", "client-chain.pem", "client-private-key.pem",
	"client-api-keys.json", "client-config.json", "client-managed-manifest.json",
	"signed-v2-s3-config.json",
}

func initialHostFileNames(spec InitialSpec) []string {
	names := slices.Clone(initialHostFiles[:])
	if len(spec.SQLTables) > 0 {
		names = append(names, sqlSchemaBundleFileName)
	}
	if spec.Backup != nil {
		names = append(names, backupManifestName, backupConfigName)
	}
	return names
}

// VerifyIntentAgainstReceipt requires an initial placement to use the exact
// material committed in R3. The caller must first authenticate the receipt and
// read its exact OCI object version through PreparationService.Current.
func VerifyIntentAgainstReceipt(intent placement.Intent, receipt PreparationReceipt) error {
	if err := intent.ValidateForAdmission(); err != nil {
		return err
	}
	spec := receipt.Spec
	roster := intent.CanonicalRoster
	liveTargetDigest, liveErr := spec.LiveS3.Digest()
	if intent.Generation != 1 || receipt.Generation != 1 || intent.DatabaseID != spec.PlacementDatabaseID ||
		intent.PartitionID != receipt.PartitionID || intent.PartitionID != spec.PartitionID || len(intent.ActiveRegions) != 1 ||
		!strings.EqualFold(string(intent.ActiveRegions[0]), receipt.Cell) || len(roster.Rows) != 2 ||
		len(intent.RuntimeManifests) != 2 || roster.ClusterID != spec.Scope.ClusterID ||
		roster.TenantID != spec.Scope.TenantID || roster.DatabaseID != spec.Scope.DatabaseID ||
		roster.ShardID != spec.Scope.ShardID || roster.Authority.Version != 2 ||
		roster.Authority.Epoch != spec.Scope.Epoch ||
		roster.Authority.ConfigurationID != receipt.AuthorityConfigurationID ||
		roster.Authority.CertificateSHA256 != receipt.AuthoritySHA256 ||
		roster.Authority.TrustedKeySHA256 != receipt.TrustedKeySHA256 || liveErr != nil {
		return ErrMaterialConflict
	}
	region, err := intent.ActiveRegions[0].OCIRegion()
	if err != nil || spec.LiveS3.Region != region {
		return ErrMaterialConflict
	}
	for _, seat := range spec.Members {
		index := -1
		for candidate, row := range roster.Rows {
			if row.SeatID == seat.SeatID {
				index = candidate
				break
			}
		}
		if index < 0 {
			return ErrMaterialConflict
		}
		row, manifest := roster.Rows[index], intent.RuntimeManifests[index]
		var pins MemberPins
		found := false
		for memberIndex, member := range spec.Members {
			if member.SeatID == seat.SeatID {
				pins = receipt.Members[memberIndex]
				found = true
			}
		}
		files := initialHostFileNames(spec)
		if !found || row.Region != intent.ActiveRegions[0] || row.MemberID != seat.MemberID ||
			row.Incarnation != seat.Incarnation || row.ServerName != seat.ServerName ||
			row.FailureDomain != seat.FailureDomain || row.TLSLeafSHA256 != pins.TLSLeafSHA256 ||
			pins.MemberID != seat.MemberID || len(pins.Files) != len(files) ||
			manifest.SeatID != seat.SeatID || manifest.Region != row.Region ||
			manifest.TrustedKeySHA256 != receipt.TrustedKeySHA256 ||
			manifest.ServerCertificateSHA256 != pins.Files["server.crt"] ||
			manifest.ServerPrivateKeySHA256 != pins.Files["server.key"] ||
			manifest.ClientCARootsSHA256 != pins.Files["client-ca.pem"] ||
			manifest.ClientManagedMaterialManifestSHA256 != pins.Files["client-managed-manifest.json"] ||
			manifest.LiveS3ConfigSHA256 != pins.Files["signed-v2-s3-config.json"] ||
			manifest.SQLSchemaBundleSHA256 != pins.Files[sqlSchemaBundleFileName] ||
			manifest.LiveS3TargetSHA256 != liveTargetDigest ||
			manifest.LiveS3Credential != spec.LiveS3.Credential ||
			!backupRuntimeMatchesSpec(manifest, spec, pins, seat) ||
			manifest.ReplicationServerCASHA256 != pins.Files["server-ca.pem"] ||
			manifest.ReplicationListenAddress != net.JoinHostPort(seat.ReplicationIP, strconv.Itoa(int(seat.ReplicationPort))) {
			return ErrMaterialConflict
		}
		for _, name := range files {
			if !lowerHexDigest(pins.Files[name]) {
				return ErrMaterialConflict
			}
		}
		binding := host.ManagedMemberBinding{Scope: host.MemberScope{
			ClusterID: spec.Scope.ClusterID, TenantID: spec.Scope.TenantID,
			DatabaseID: spec.Scope.DatabaseID, ShardID: spec.Scope.ShardID,
			MemberID: seat.MemberID, Incarnation: seat.Incarnation,
		}, HostAttempt: 1}
		materialPath, err := host.ManagedMaterialPath(manifest.ManagedRuntimeRoot, binding)
		if err != nil || materialPath != seat.MaterialDirectory {
			return ErrMaterialConflict
		}
		peer := spec.Members[0]
		if peer.MemberID == seat.MemberID {
			peer = spec.Members[1]
		}
		if manifest.ReplicationPeerMemberID != peer.MemberID ||
			manifest.ReplicationPeerAddress != net.JoinHostPort(peer.ReplicationIP, strconv.Itoa(int(peer.ReplicationPort))) {
			return ErrMaterialConflict
		}
	}
	if roster.Rows[0].SeatID == roster.Rows[1].SeatID {
		return errors.New("managed placement repeats one prepared seat")
	}
	return nil
}

func backupRuntimeMatchesSpec(manifest placement.RuntimeManifest, spec InitialSpec,
	pins MemberPins, seat InitialMember,
) bool {
	if spec.Backup == nil {
		return manifest.BackupManifestSHA256 == "" && manifest.BackupS3ConfigSHA256 == "" &&
			manifest.BackupS3TargetSHA256 == "" && manifest.BackupS3CredentialSHA256 == "" &&
			manifest.BackupDataKeySHA256 == "" && !manifest.BackupOwner &&
			manifest.BackupS3Credential == (oci.SecretVersionReference{}) &&
			manifest.BackupDataKey == (oci.SecretVersionReference{})
	}
	targetDigest, err := spec.Backup.Target.Digest()
	if err != nil || manifest.BackupManifestSHA256 != pins.Files[backupManifestName] ||
		manifest.BackupS3ConfigSHA256 != pins.Files[backupConfigName] ||
		manifest.BackupS3TargetSHA256 != targetDigest ||
		manifest.BackupS3CredentialSHA256 != spec.Backup.Target.CredentialSHA256 ||
		manifest.BackupDataKeySHA256 != spec.Backup.DataKeySHA256 ||
		manifest.BackupOwner != (seat.MemberID == spec.Backup.OwnerMemberID) {
		return false
	}
	if manifest.BackupOwner {
		return manifest.BackupS3Credential == spec.Backup.Target.Credential &&
			manifest.BackupDataKey == spec.Backup.DataKey
	}
	return manifest.BackupS3Credential == (oci.SecretVersionReference{}) &&
		manifest.BackupDataKey == (oci.SecretVersionReference{})
}
