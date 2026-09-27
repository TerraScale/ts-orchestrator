package managedmaterial

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

var initialHostFiles = [...]string{
	"authority.tbca", "trusted-public-key", "server.crt", "server.key",
	"server-ca.pem", "client-ca.pem", "client-chain.pem", "client-private-key.pem",
	"client-api-keys.json", "client-config.json", "client-managed-manifest.json",
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
	if intent.Generation != 1 || receipt.Generation != 1 || intent.DatabaseID != spec.PlacementDatabaseID ||
		intent.PartitionID != receipt.PartitionID || intent.PartitionID != spec.PartitionID || len(intent.ActiveRegions) != 1 ||
		!strings.EqualFold(string(intent.ActiveRegions[0]), receipt.Cell) || len(roster.Rows) != 2 ||
		len(intent.RuntimeManifests) != 2 || roster.ClusterID != spec.Scope.ClusterID ||
		roster.TenantID != spec.Scope.TenantID || roster.DatabaseID != spec.Scope.DatabaseID ||
		roster.ShardID != spec.Scope.ShardID || roster.Authority.Version != 2 ||
		roster.Authority.Epoch != spec.Scope.Epoch ||
		roster.Authority.ConfigurationID != receipt.AuthorityConfigurationID ||
		roster.Authority.CertificateSHA256 != receipt.AuthoritySHA256 ||
		roster.Authority.TrustedKeySHA256 != receipt.TrustedKeySHA256 {
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
		if !found || row.Region != intent.ActiveRegions[0] || row.MemberID != seat.MemberID ||
			row.Incarnation != seat.Incarnation || row.ServerName != seat.ServerName ||
			row.FailureDomain != seat.FailureDomain || row.TLSLeafSHA256 != pins.TLSLeafSHA256 ||
			pins.MemberID != seat.MemberID || len(pins.Files) != len(initialHostFiles) ||
			manifest.SeatID != seat.SeatID || manifest.Region != row.Region ||
			manifest.TrustedKeySHA256 != receipt.TrustedKeySHA256 ||
			manifest.ServerCertificateSHA256 != pins.Files["server.crt"] ||
			manifest.ServerPrivateKeySHA256 != pins.Files["server.key"] ||
			manifest.ClientCARootsSHA256 != pins.Files["client-ca.pem"] ||
			manifest.ClientManagedMaterialManifestSHA256 != pins.Files["client-managed-manifest.json"] ||
			manifest.ReplicationServerCASHA256 != pins.Files["server-ca.pem"] ||
			manifest.ReplicationListenAddress != net.JoinHostPort(seat.ReplicationIP, strconv.Itoa(int(seat.ReplicationPort))) {
			return ErrMaterialConflict
		}
		for _, name := range initialHostFiles {
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
