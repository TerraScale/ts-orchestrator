package managedmaterial

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// ManagedFileSystemType is the only filesystem the host volume initializer
// can create on a blank retained volume.
const ManagedFileSystemType = "ext4"

// DeploymentDocumentFields is the generation-one schema of every collection
// in a first managed deployment: one optional UTF-8 "title" field, enough for
// the documented client walkthrough. Later schema changes use the catalog
// successor path.
var DeploymentDocumentFields = []CatalogUTF8Field{{ID: 1, Name: "title"}}

// DeploymentMember is one placement seat of a first managed deployment. The
// operator supplies the network and fault-domain pins; identities are
// generated once and retained by the caller so reruns sign the same spec.
type DeploymentMember struct {
	SeatID         string `json:"seat_id"`
	MemberID       string `json:"member_id"`
	Incarnation    string `json:"incarnation"`
	ServerName     string `json:"server_name"`
	FailureDomain  string `json:"failure_domain"`
	PrivateIP      string `json:"private_ip"`
	FileSystemUUID string `json:"filesystem_uuid"`
}

// InitialDeployment is everything a generation-one TerraBase placement needs
// besides controller-produced material. Members are in placement seat order:
// the permanent seat first, then the elastic seat.
type InitialDeployment struct {
	Region              oci.Region          `json:"region"`
	PlacementDatabaseID string              `json:"placement_database_id"`
	PartitionID         string              `json:"partition_id"`
	Scope               AuthorityScope      `json:"scope"`
	LiveS3              LiveS3Target        `json:"live_s3"`
	CollectionIDs       []string            `json:"collection_ids"`
	Members             [2]DeploymentMember `json:"members"`
	ReplicationPort     uint16              `json:"replication_port"`
	ClientPort          uint16              `json:"client_port"`
	ManagedRuntimeRoot  string              `json:"managed_runtime_root"`
}

// RuntimeArtifact is the admitted TerraBase executable pinned by placement.
type RuntimeArtifact struct {
	Digest       string
	SourceDigest string
}

// NewDeploymentIdentity fills fresh random cluster, tenant, database, member,
// incarnation, filesystem and collection identities. Callers persist the
// result before any signed effect so a retry never generates a second scope.
func NewDeploymentIdentity(deployment InitialDeployment, collections int) (InitialDeployment, error) {
	if collections < 1 || collections > 16 {
		return InitialDeployment{}, errors.New("a managed deployment needs 1 to 16 collections")
	}
	cluster := uuid.New()
	deployment.Scope = AuthorityScope{ClusterID: strings.ReplaceAll(cluster.String(), "-", ""),
		TenantID: uuid.New().String(), DatabaseID: uuid.New().String(), ShardID: 1, Epoch: 1}
	for index := range deployment.Members {
		incarnation := uuid.New()
		deployment.Members[index].MemberID = uuid.New().String()
		deployment.Members[index].Incarnation = strings.ReplaceAll(incarnation.String(), "-", "")
		deployment.Members[index].FileSystemUUID = uuid.New().String()
	}
	deployment.CollectionIDs = make([]string, collections)
	for index := range deployment.CollectionIDs {
		deployment.CollectionIDs[index] = uuid.New().String()
	}
	return deployment, nil
}

// Validate checks every operator and identity pin before any signing step.
func (deployment InitialDeployment) Validate() error {
	seats, err := placement.RegionSeatIDs(deployment.Region)
	if err != nil {
		return err
	}
	ociRegion, err := deployment.Region.OCIRegion()
	if err != nil {
		return err
	}
	if !repositoryToken.MatchString(deployment.PlacementDatabaseID) || !repositoryToken.MatchString(deployment.PartitionID) {
		return errors.New("placement database and partition IDs must be lower-case tokens")
	}
	if err := deployment.LiveS3.Validate(); err != nil {
		return err
	}
	if deployment.LiveS3.Region != ociRegion {
		return errors.New("live S3 target region differs from the placement region")
	}
	if deployment.ReplicationPort == 0 || deployment.ClientPort == 0 || deployment.ReplicationPort == deployment.ClientPort {
		return errors.New("replication and client ports must be distinct and nonzero")
	}
	if _, err := canonicalUUID(deployment.Scope.TenantID); err != nil {
		return err
	}
	if _, err := canonicalUUID(deployment.Scope.DatabaseID); err != nil {
		return err
	}
	if !lowerHexIdentity(deployment.Scope.ClusterID) || deployment.Scope.ShardID == 0 || deployment.Scope.Epoch != 1 {
		return errors.New("deployment shard scope is invalid")
	}
	if len(deployment.CollectionIDs) == 0 {
		return errors.New("deployment needs at least one collection")
	}
	for _, id := range deployment.CollectionIDs {
		if _, err := canonicalUUID(id); err != nil {
			return err
		}
	}
	for index, member := range deployment.Members {
		ip, err := netip.ParseAddr(member.PrivateIP)
		if member.SeatID != seats[index] || !validServerName(member.ServerName) ||
			!validFailureDomain(member.FailureDomain) || err != nil || !ip.Is4() || !validPrivateIP(member.PrivateIP) ||
			!lowerHexIdentity(member.Incarnation) || !validFileSystemUUID(member.FileSystemUUID) {
			return fmt.Errorf("deployment member %d is incomplete or out of seat order", index)
		}
		if _, err := canonicalUUID(member.MemberID); err != nil {
			return err
		}
	}
	first, second := deployment.Members[0], deployment.Members[1]
	if first.MemberID == second.MemberID || first.PrivateIP == second.PrivateIP ||
		first.FailureDomain == second.FailureDomain || first.ServerName == second.ServerName ||
		first.FileSystemUUID == second.FileSystemUUID || first.Incarnation == second.Incarnation {
		return errors.New("deployment members repeat an identity, address or fault domain")
	}
	if len(deployment.ManagedRuntimeRoot) > 54 {
		return errors.New("managed runtime root exceeds the placement path bound")
	}
	for index := range deployment.Members {
		if _, err := host.ManagedMountPath(deployment.ManagedRuntimeRoot, deployment.binding(index)); err != nil {
			return fmt.Errorf("managed runtime root: %w", err)
		}
	}
	return nil
}

func (deployment InitialDeployment) binding(index int) host.ManagedMemberBinding {
	member := deployment.Members[index]
	return host.ManagedMemberBinding{Scope: host.MemberScope{
		ClusterID: deployment.Scope.ClusterID, TenantID: deployment.Scope.TenantID,
		DatabaseID: deployment.Scope.DatabaseID, ShardID: deployment.Scope.ShardID,
		MemberID: member.MemberID, Incarnation: member.Incarnation,
	}, HostAttempt: 1}
}

// DraftSpec returns the unsigned generation-one material spec. Members are
// ordered by member ID (TerraBase authority order); catalogs are
// DeploymentDocumentFields schemas ordered by collection UUID bytes.
func (deployment InitialDeployment) DraftSpec() (InitialSpec, error) {
	if err := deployment.Validate(); err != nil {
		return InitialSpec{}, err
	}
	collections := slices.Clone(deployment.CollectionIDs)
	slices.SortFunc(collections, func(left, right string) int {
		a, _ := uuid.Parse(left)
		b, _ := uuid.Parse(right)
		return bytes.Compare(a[:], b[:])
	})
	spec := InitialSpec{PlacementDatabaseID: deployment.PlacementDatabaseID, PartitionID: deployment.PartitionID,
		Scope: deployment.Scope, LiveS3: deployment.LiveS3}
	for _, id := range collections {
		catalog, err := InitialCatalog(id, DeploymentDocumentFields)
		if err != nil {
			return InitialSpec{}, err
		}
		spec.Catalogs = append(spec.Catalogs, InitialCatalogInput{CollectionID: id, CanonicalCatalog: catalog.Bytes})
	}
	for index, member := range deployment.Members {
		material, err := host.ManagedMaterialPath(deployment.ManagedRuntimeRoot, deployment.binding(index))
		if err != nil {
			return InitialSpec{}, err
		}
		spec.Members[index] = InitialMember{SeatID: member.SeatID, MemberID: member.MemberID,
			Incarnation: member.Incarnation, ServerName: member.ServerName, FailureDomain: member.FailureDomain,
			MaterialDirectory: material, ReplicationIP: member.PrivateIP, ReplicationPort: deployment.ReplicationPort,
			ClientIP: member.PrivateIP, ClientPort: deployment.ClientPort}
	}
	if spec.Members[0].MemberID > spec.Members[1].MemberID {
		spec.Members[0], spec.Members[1] = spec.Members[1], spec.Members[0]
	}
	return spec, nil
}

// MatchesSpec requires a retained signed spec to be exactly this
// deployment's draft plus its recipient grant.
func (deployment InitialDeployment) MatchesSpec(spec InitialSpec) error {
	draft, err := deployment.DraftSpec()
	if err != nil {
		return err
	}
	unsigned := spec
	unsigned.Recipient = RecipientGrant{}
	want, err := protocol.EncodeJSON(draft)
	if err != nil {
		return err
	}
	got, err := protocol.EncodeJSON(unsigned)
	if err != nil || !bytes.Equal(want, got) {
		return fmt.Errorf("%w: retained material spec differs from the deployment plan", ErrMaterialConflict)
	}
	return nil
}

// SignRecipientGrant binds one owner-held X25519 recipient to the exact
// draft. The signer must be the recipient signer pinned by the controllers.
func SignRecipientGrant(draft InitialSpec, recipient *ecdh.PrivateKey, signer ed25519.PrivateKey,
	expiresAt, now time.Time,
) (InitialSpec, error) {
	if recipient == nil || recipient.Curve() != ecdh.X25519() || len(signer) != ed25519.PrivateKeySize {
		return InitialSpec{}, errors.New("recipient grant needs an X25519 recipient and Ed25519 signer")
	}
	if len(draft.Recipient.PublicKey) != 0 || !draft.Recipient.ExpiresAt.IsZero() || len(draft.Recipient.Signature) != 0 {
		return InitialSpec{}, errors.New("draft material spec already carries a recipient grant")
	}
	spec := draft
	spec.Recipient = RecipientGrant{PublicKey: recipient.PublicKey().Bytes(), ExpiresAt: expiresAt.UTC().Truncate(time.Second)}
	spec.Recipient.Signature = ed25519.Sign(signer, RecipientGrantMessage(spec))
	if err := validateInitialSpec(spec, signer.Public().(ed25519.PublicKey), now); err != nil {
		return InitialSpec{}, err
	}
	return spec, nil
}

// VerifyRecipientGrant checks a retained signed spec against the pinned
// recipient signer without requiring the grant to still be current.
func VerifyRecipientGrant(spec InitialSpec, signer ed25519.PublicKey) error {
	if len(signer) != ed25519.PublicKeySize || len(spec.Recipient.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(signer, RecipientGrantMessage(spec), spec.Recipient.Signature) {
		return errors.New("retained material spec recipient grant is not signed by the pinned signer")
	}
	return nil
}

// RenderInitialPlacement derives the complete schema-5 placement intent from
// an authenticated preparation receipt. Every material digest comes from the
// receipt; the operator contributes only the artifact, compute profile and
// the identities already bound into the signed spec.
func RenderInitialPlacement(receipt PreparationReceipt, deployment InitialDeployment,
	artifact RuntimeArtifact, profile placement.ManagedHostProfile,
) (placement.Intent, error) {
	if err := deployment.Validate(); err != nil {
		return placement.Intent{}, err
	}
	if !strings.EqualFold(receipt.Cell, string(deployment.Region)) || profile.Region != deployment.Region ||
		!lowerHexDigest(artifact.Digest) || !lowerHexDigest(artifact.SourceDigest) {
		return placement.Intent{}, errors.New("placement render inputs differ from the prepared region or artifact")
	}
	spec := receipt.Spec
	if err := deployment.MatchesSpec(spec); err != nil {
		return placement.Intent{}, err
	}
	targetDigest, err := spec.LiveS3.Digest()
	if err != nil {
		return placement.Intent{}, err
	}
	intent := placement.Intent{SchemaVersion: placement.IntentSchemaVersion,
		DatabaseID: spec.PlacementDatabaseID, PartitionID: spec.PartitionID,
		ActiveRegions: []oci.Region{deployment.Region}, Generation: 1,
		CanonicalRoster: placement.CanonicalRoster{ClusterID: spec.Scope.ClusterID, TenantID: spec.Scope.TenantID,
			DatabaseID: spec.Scope.DatabaseID, ShardID: spec.Scope.ShardID,
			Authority: placement.AuthorityReference{Version: 2, Epoch: spec.Scope.Epoch,
				ConfigurationID: receipt.AuthorityConfigurationID, CertificateSHA256: receipt.AuthoritySHA256,
				TrustedKeySHA256: receipt.TrustedKeySHA256}},
		ManagedHostProfiles: []placement.ManagedHostProfile{profile}}
	for _, member := range deployment.Members {
		index := slices.IndexFunc(spec.Members[:], func(seat InitialMember) bool { return seat.SeatID == member.SeatID })
		if index < 0 || spec.Members[index].MemberID != member.MemberID {
			return placement.Intent{}, ErrMaterialConflict
		}
		seat, peer, pins := spec.Members[index], spec.Members[1-index], receipt.Members[index]
		intent.CanonicalRoster.Rows = append(intent.CanonicalRoster.Rows, placement.CanonicalRosterRow{
			Region: deployment.Region, SeatID: seat.SeatID, FailureDomain: seat.FailureDomain,
			MemberID: seat.MemberID, Incarnation: seat.Incarnation,
			TLSLeafSHA256: pins.TLSLeafSHA256, ServerName: seat.ServerName})
		intent.RuntimeManifests = append(intent.RuntimeManifests, placement.RuntimeManifest{
			Region: deployment.Region, SeatID: seat.SeatID,
			ArtifactDigest: artifact.Digest, SourceDigest: artifact.SourceDigest,
			ManagedRuntimeRoot: deployment.ManagedRuntimeRoot, FileSystemUUID: member.FileSystemUUID,
			FileSystemType: ManagedFileSystemType, TrustedKeySHA256: receipt.TrustedKeySHA256,
			ServerCertificateSHA256: pins.Files["server.crt"], ServerPrivateKeySHA256: pins.Files["server.key"],
			ClientCARootsSHA256:                 pins.Files["client-ca.pem"],
			ClientManagedMaterialManifestSHA256: pins.Files["client-managed-manifest.json"],
			SQLSchemaBundleSHA256:               pins.Files[sqlSchemaBundleFileName],
			LiveS3ConfigSHA256:                  pins.Files["signed-v2-s3-config.json"],
			LiveS3TargetSHA256:                  targetDigest,
			LiveS3Credential:                    spec.LiveS3.Credential,
			ReplicationListenAddress:            net.JoinHostPort(seat.ReplicationIP, strconv.Itoa(int(seat.ReplicationPort))),
			ReplicationPeerMemberID:             peer.MemberID,
			ReplicationPeerAddress:              net.JoinHostPort(peer.ReplicationIP, strconv.Itoa(int(peer.ReplicationPort))),
			ReplicationServerCASHA256:           pins.Files["server-ca.pem"],
		})
	}
	if spec.Backup != nil {
		return placement.Intent{}, errors.New("backup-enabled initial material needs a separately reviewed placement")
	}
	if err := VerifyIntentAgainstReceipt(intent, receipt); err != nil {
		return placement.Intent{}, fmt.Errorf("rendered placement differs from prepared material: %w", err)
	}
	return intent, nil
}

func lowerHexIdentity(value string) bool {
	if len(value) != 32 || strings.Trim(value, "0") == "" {
		return false
	}
	for index := range len(value) {
		if !lowerAlphaNumeric(value[index]) || value[index] > 'f' {
			return false
		}
	}
	return true
}

func validFileSystemUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil() && parsed.String() == value
}
