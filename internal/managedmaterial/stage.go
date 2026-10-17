package managedmaterial

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// The signed record fits the broker's default 1 MiB publish limit after the
// control log base64-encodes its payload and adds its fixed entry metadata.
const MaxSignedMaterialStageBytes = 512 << 10

type MaterialStageAction string

const (
	MaterialStagePreparation          MaterialStageAction = "preparation"
	MaterialStageCredentials          MaterialStageAction = "credentials"
	MaterialStageBackupPrepare        MaterialStageAction = "backup_prepare"
	MaterialStageBackupAbort          MaterialStageAction = "backup_abort"
	MaterialStageBackupBarrier        MaterialStageAction = "backup_barrier"
	MaterialStageBackupCompletion     MaterialStageAction = "backup_completion"
	MaterialStageBackupOwnerReceipt   MaterialStageAction = "backup_owner_receipt"
	MaterialStageBackupReleaseRenewal MaterialStageAction = "backup_release_renewal"
	MaterialStageBackupBarrierAck     MaterialStageAction = "backup_barrier_ack"
	MaterialStageBackupCandidate      MaterialStageAction = "backup_candidate"
	MaterialStageBackupCompleteAck    MaterialStageAction = "backup_complete_ack"
)

type MaterialStageSourceName string

const (
	MaterialStageAcceptedIdentity      MaterialStageSourceName = "accepted_identity"
	MaterialStageControllerConfig      MaterialStageSourceName = "controller_config"
	MaterialStageControllerGeneration  MaterialStageSourceName = "controller_generation"
	MaterialStageMaterialKeyReference  MaterialStageSourceName = "material_key_reference"
	MaterialStageRootHead              MaterialStageSourceName = "root_head"
	MaterialStageServiceSpec           MaterialStageSourceName = "service_spec"
	MaterialStageOperatorPolicy        MaterialStageSourceName = "operator_policy"
	MaterialStageLease                 MaterialStageSourceName = "lease"
	MaterialStageOwnhost               MaterialStageSourceName = "ownhost"
	MaterialStageNativeManager         MaterialStageSourceName = "native_manager"
	MaterialStageNativeCluster         MaterialStageSourceName = "native_cluster"
	MaterialStageMaterialDomain        MaterialStageSourceName = "material_domain"
	MaterialStageInitialReceipt        MaterialStageSourceName = "initial_receipt"
	MaterialStageMaterialObject        MaterialStageSourceName = "material_object"
	MaterialStageCredentialPredecessor MaterialStageSourceName = "credential_predecessor"
	MaterialStagePlacement             MaterialStageSourceName = "placement"
	MaterialStageRoster                MaterialStageSourceName = "roster"
	MaterialStageBackupPredecessor     MaterialStageSourceName = "backup_predecessor"
	MaterialStageBackupInput           MaterialStageSourceName = "backup_input"
)

// MaterialStageSource retains exact public evidence, never a secret value or
// confidential bundle. A saved source is compared with independently reopened bytes.
type MaterialStageSource struct {
	Name      MaterialStageSourceName `json:"name"`
	Revision  uint64                  `json:"revision"`
	Payload   []byte                  `json:"payload"`
	ExpiresAt time.Time               `json:"expires_at,omitzero"`
}

type MaterialStageNative struct {
	NodeID            string `json:"node_id"`
	InstanceID        string `json:"instance_id"`
	OCIRegion         string `json:"oci_region"`
	SwarmClusterID    string `json:"swarm_cluster_id"`
	ClusterCASHA256   string `json:"cluster_ca_sha256"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

type MaterialStageBackupEvidence struct {
	Placement   authority.LogEntry               `json:"placement"`
	Predecessor *authority.BackupOperationRecord `json:"predecessor,omitempty"`
	Sequence    uint64                           `json:"sequence"`
	MemberID    string                           `json:"member_id,omitempty"`
	Input       []byte                           `json:"input,omitempty"`
}

type MaterialStageEvidence struct {
	Operator *protocol.Envelope           `json:"operator,omitempty"`
	Backup   *MaterialStageBackupEvidence `json:"backup,omitempty"`
}

// MaterialStage is one immutable original admission and proposed public CAS.
// Its native seal does not replace independent current domain-source admission.
type MaterialStage struct {
	Version                    uint64                           `json:"version"`
	Action                     MaterialStageAction              `json:"action"`
	Cell                       string                           `json:"cell"`
	DatabaseID                 string                           `json:"database_id"`
	PartitionID                string                           `json:"partition_id"`
	OperationID                string                           `json:"operation_id"`
	RuntimeID                  string                           `json:"runtime_id"`
	Epoch                      uint64                           `json:"epoch"`
	ExpectedSequence           uint64                           `json:"expected_sequence"`
	PredecessorPayload         []byte                           `json:"predecessor_payload,omitempty"`
	AdmittedAt                 time.Time                        `json:"admitted_at"`
	OperationExpiresAt         time.Time                        `json:"operation_expires_at"`
	GrantExpiresAt             time.Time                        `json:"grant_expires_at"`
	CredentialExpiresAt        time.Time                        `json:"credential_expires_at"`
	LeaseExpiresAt             time.Time                        `json:"lease_expires_at"`
	SemanticSourceExpiresAt    time.Time                        `json:"semantic_source_expires_at"`
	NativeCertificateExpiresAt time.Time                        `json:"native_certificate_expires_at"`
	OriginalContextExpiresAt   time.Time                        `json:"original_context_expires_at"`
	OriginalCallerExpiresAt    time.Time                        `json:"original_caller_expires_at"`
	ExpiresAt                  time.Time                        `json:"expires_at"`
	CallerAuthoritySHA256      string                           `json:"caller_authority_sha256"`
	Native                     MaterialStageNative              `json:"native"`
	Evidence                   MaterialStageEvidence            `json:"evidence"`
	Sources                    []MaterialStageSource            `json:"sources"`
	Preparation                *PreparationReceipt              `json:"preparation,omitempty"`
	Credentials                *CredentialCandidate             `json:"credentials,omitempty"`
	Backup                     *authority.BackupOperationRecord `json:"backup,omitempty"`
}

type SignedMaterialStage struct {
	Stage            MaterialStage `json:"stage"`
	CertificateChain [][]byte      `json:"certificate_chain"`
	Signature        []byte        `json:"signature"`
}

// MaterialStageSigningBytes has one fixed domain and accepts only the complete
// finite stage schema. It authenticates structure, not the caller or its sources.
func MaterialStageSigningBytes(stage MaterialStage) ([]byte, error) {
	if err := validateMaterialStage(stage); err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(stage)
	if err != nil || len(wire) > 384<<10 {
		return nil, ErrMaterialConflict
	}
	return append([]byte("TS-MANAGED-MATERIAL-STAGE-V1\x00"), wire...), nil
}

func validateMaterialStage(stage MaterialStage) error {
	if stage.Version != 1 || !repositoryToken.MatchString(stage.Cell) || len(stage.Cell) > 64 ||
		!entityid.Valid(stage.DatabaseID) || !entityid.Valid(stage.PartitionID) ||
		!entityid.Valid(stage.OperationID) || !entityid.Valid(stage.RuntimeID) || stage.Epoch == 0 ||
		(stage.ExpectedSequence == 0) != (len(stage.PredecessorPayload) == 0) ||
		!lowerHexDigest(stage.CallerAuthoritySHA256) || !materialStageUTC(stage.AdmittedAt) ||
		stage.Native.NodeID == "" || len(stage.Native.NodeID) > 256 || stage.Native.InstanceID == "" || len(stage.Native.InstanceID) > 256 ||
		stage.Native.OCIRegion == "" || len(stage.Native.OCIRegion) > 64 || stage.Native.SwarmClusterID == "" || len(stage.Native.SwarmClusterID) > 256 ||
		!lowerHexDigest(stage.Native.ClusterCASHA256) ||
		!lowerHexDigest(stage.Native.CertificateSHA256) {
		return ErrMaterialConflict
	}
	ceilings := []time.Time{stage.OperationExpiresAt, stage.GrantExpiresAt,
		stage.SemanticSourceExpiresAt, stage.NativeCertificateExpiresAt}
	minimum := ceilings[0]
	for _, expiry := range ceilings {
		if !materialStageUTC(expiry) || !stage.AdmittedAt.Before(expiry) {
			return ErrMaterialConflict
		}
		if expiry.Before(minimum) {
			minimum = expiry
		}
	}
	// Attempt credentials bound each use separately. Their original expiry
	// records provenance without manufacturing operation-wide authority.
	for _, expiry := range []time.Time{stage.CredentialExpiresAt, stage.LeaseExpiresAt,
		stage.OriginalContextExpiresAt, stage.OriginalCallerExpiresAt} {
		if !materialStageUTC(expiry) || !stage.AdmittedAt.Before(expiry) {
			return ErrMaterialConflict
		}
	}
	if !materialStageUTC(stage.ExpiresAt) || !stage.ExpiresAt.Equal(minimum) || len(stage.Sources) < 12 || len(stage.Sources) > 32 {
		return ErrMaterialConflict
	}
	required := []MaterialStageSourceName{MaterialStageAcceptedIdentity, MaterialStageControllerConfig,
		MaterialStageControllerGeneration, MaterialStageMaterialKeyReference, MaterialStageRootHead,
		MaterialStageServiceSpec, MaterialStageOperatorPolicy, MaterialStageLease, MaterialStageOwnhost,
		MaterialStageNativeManager, MaterialStageNativeCluster, MaterialStageMaterialDomain}
	var candidate any
	switch stage.Action {
	case MaterialStagePreparation:
		if stage.Preparation == nil || stage.Credentials != nil || stage.Backup != nil || stage.Evidence.Operator == nil ||
			stage.Evidence.Backup != nil || stage.ExpectedSequence != 0 ||
			stage.Preparation.Cell != stage.Cell || stage.Preparation.PartitionID != stage.PartitionID ||
			stage.Preparation.Spec.PlacementDatabaseID != stage.DatabaseID {
			return ErrMaterialConflict
		}
		candidate = stage.Preparation
		var spec InitialSpec
		if protocol.DecodeStrict(stage.Evidence.Operator.Payload, &spec, 16<<10) != nil {
			return ErrMaterialConflict
		}
		original, err := protocol.EncodeJSON(spec)
		proposed, candidateErr := protocol.EncodeJSON(stage.Preparation.Spec)
		if err != nil || candidateErr != nil || !bytes.Equal(original, stage.Evidence.Operator.Payload) ||
			!bytes.Equal(original, proposed) || stage.OperationID != entityid.Derive("material-g1", string(original)) {
			return ErrMaterialConflict
		}
	case MaterialStageCredentials:
		if stage.Credentials == nil || stage.Preparation != nil || stage.Backup != nil || stage.Evidence.Operator == nil ||
			stage.Evidence.Backup != nil || stage.Credentials.CommittedSequence != 0 ||
			stage.Credentials.ExpectedSequence != stage.ExpectedSequence ||
			stage.Credentials.Reply.Receipt.DatabaseID != stage.DatabaseID || stage.Credentials.Reply.Receipt.PartitionID != stage.PartitionID {
			return ErrMaterialConflict
		}
		required = append(required, MaterialStageInitialReceipt, MaterialStageMaterialObject, MaterialStageCredentialPredecessor)
		candidate = stage.Credentials
		var request CredentialRequest
		if protocol.DecodeStrict(stage.Evidence.Operator.Payload, &request, 16<<10) != nil ||
			request.OperationID != stage.OperationID || request.DatabaseID != stage.DatabaseID || request.PartitionID != stage.PartitionID ||
			request.ExpectedGeneration == ^uint64(0) || request.ExpectedGeneration+1 != stage.Credentials.Reply.Receipt.State.Generation {
			return ErrMaterialConflict
		}
		original, err := protocol.EncodeJSON(request)
		digest := sha256.Sum256(original)
		if err != nil || !bytes.Equal(original, stage.Evidence.Operator.Payload) ||
			stage.Credentials.Reply.Receipt.RequestSHA256 != hex.EncodeToString(digest[:]) {
			return ErrMaterialConflict
		}
	case MaterialStageBackupPrepare, MaterialStageBackupAbort, MaterialStageBackupBarrier, MaterialStageBackupCompletion,
		MaterialStageBackupOwnerReceipt, MaterialStageBackupReleaseRenewal, MaterialStageBackupBarrierAck,
		MaterialStageBackupCandidate, MaterialStageBackupCompleteAck:
		if stage.Backup == nil || stage.Preparation != nil || stage.Credentials != nil || stage.Evidence.Backup == nil ||
			stage.Evidence.Operator != nil || stage.Backup.DatabaseID != stage.DatabaseID || stage.Backup.PartitionID != stage.PartitionID ||
			stage.Evidence.Backup.Sequence != stage.ExpectedSequence ||
			(stage.ExpectedSequence == 0) != (stage.Evidence.Backup.Predecessor == nil) ||
			stage.Evidence.Backup.Placement.Kind != authority.MutationPlacementIntent || stage.Evidence.Backup.Placement.Sequence == 0 ||
			stage.Evidence.Backup.Placement.SubjectKey != stage.DatabaseID+"."+stage.PartitionID {
			return ErrMaterialConflict
		}
		required = append(required, MaterialStageInitialReceipt, MaterialStageMaterialObject, MaterialStagePlacement,
			MaterialStageRoster, MaterialStageBackupPredecessor)
		if len(stage.Evidence.Backup.Input) != 0 {
			required = append(required, MaterialStageBackupInput)
		}
		candidate = stage.Backup
		if predecessor := stage.Evidence.Backup.Predecessor; predecessor != nil {
			wire, err := protocol.EncodeJSON(predecessor)
			if err != nil || !bytes.Equal(wire, stage.PredecessorPayload) {
				return ErrMaterialConflict
			}
		}
	default:
		return ErrMaterialConflict
	}
	if operator := stage.Evidence.Operator; operator != nil {
		encoded, err := protocol.EncodeJSON(operator)
		if operator.OperationID != stage.OperationID || operator.Epoch != stage.Epoch || operator.Region != stage.Cell ||
			!operator.ExpiresAt.Equal(stage.OperationExpiresAt) || len(operator.Payload) == 0 || err != nil || len(encoded) > 64<<10 {
			return ErrMaterialConflict
		}
	}
	if len(stage.Sources) != len(required) {
		return ErrMaterialConflict
	}
	for i, source := range stage.Sources {
		if !slices.Contains(required, source.Name) || len(source.Payload) == 0 || len(source.Payload) > 128<<10 ||
			i > 0 && source.Name <= stage.Sources[i-1].Name ||
			!source.ExpiresAt.IsZero() && (!materialStageUTC(source.ExpiresAt) || !stage.AdmittedAt.Before(source.ExpiresAt)) {
			return ErrMaterialConflict
		}
	}
	wire, err := protocol.EncodeJSON(candidate)
	if err != nil || len(wire) > 256<<10 || len(stage.PredecessorPayload) > 256<<10 {
		return ErrMaterialConflict
	}
	return nil
}

func materialStageUTC(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0
}

// VerifySignedMaterialStage pins the seal to the actual accepted manager and
// cluster. Callers must additionally reopen original semantic evidence/sources.
func VerifySignedMaterialStage(signed SignedMaterialStage, managerCertificate, clusterCA []byte,
	clusterID string, now time.Time,
) error {
	encoded, err := protocol.EncodeJSON(signed)
	if err != nil || len(encoded) > MaxSignedMaterialStageBytes {
		return ErrMaterialConflict
	}
	wire, err := MaterialStageSigningBytes(signed.Stage)
	if err != nil || now.Before(signed.Stage.AdmittedAt) || !now.Before(signed.Stage.ExpiresAt) ||
		clusterID == "" || signed.Stage.Native.SwarmClusterID != clusterID ||
		len(signed.CertificateChain) == 0 || len(signed.CertificateChain) > 8 || len(signed.Signature) == 0 || len(signed.Signature) > 256 {
		return ErrMaterialConflict
	}
	block, rest := pem.Decode(managerCertificate)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, signed.CertificateChain[0]) {
		return ErrMaterialConflict
	}
	leaf, err := x509.ParseCertificate(signed.CertificateChain[0])
	if err != nil {
		return err
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || leaf.Subject.CommonName != signed.Stage.Native.NodeID || len(leaf.Subject.Organization) != 1 ||
		leaf.Subject.Organization[0] != clusterID || len(leaf.Subject.OrganizationalUnit) != 1 ||
		leaf.Subject.OrganizationalUnit[0] != "swarm-manager" || !leaf.NotAfter.Equal(signed.Stage.NativeCertificateExpiresAt) {
		return ErrMaterialConflict
	}
	certificateDigest, clusterDigest := sha256.Sum256(block.Bytes), sha256.Sum256(clusterCA)
	if signed.Stage.Native.CertificateSHA256 != hex.EncodeToString(certificateDigest[:]) ||
		signed.Stage.Native.ClusterCASHA256 != hex.EncodeToString(clusterDigest[:]) {
		return ErrMaterialConflict
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(clusterCA) {
		return ErrMaterialConflict
	}
	var total int
	for i, raw := range signed.CertificateChain {
		total += len(raw)
		if total > 64<<10 {
			return ErrMaterialConflict
		}
		if i > 0 {
			certificate, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			intermediates.AddCert(certificate)
		}
	}
	for _, at := range []time.Time{signed.Stage.AdmittedAt, now, signed.Stage.ExpiresAt} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
			CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return err
		}
	}
	digest := sha256.Sum256(wire)
	if !ecdsa.VerifyASN1(public, digest[:], signed.Signature) {
		return errors.New("managed material native stage signature is invalid")
	}
	return nil
}
