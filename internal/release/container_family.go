package release

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const MaxWorkerFamilyEvidenceBytes = 8 << 10

// WorkerFamilyDigest binds the common source and OCI root independently of
// which regions or architectures happen to qualify in this submission.
func (claim ContainerClaim) WorkerFamilyDigest() (string, error) {
	family := struct {
		Schema              string `json:"schema"`
		Role                string `json:"role"`
		Environment         string `json:"environment"`
		SourceRepository    string `json:"source_repository"`
		SourceRevision      string `json:"source_revision"`
		SourceTreeSHA256    string `json:"source_tree_sha256"`
		QualificationSHA256 string `json:"qualification_sha256"`
	}{"terrascale.release.worker-family.v1", claim.Role, claim.Environment, claim.SourceRepository, claim.SourceRevision, claim.SourceTreeSHA256, claim.QualificationSHA256}
	wire, err := trust.EncodePayload(family)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}

// WorkerFamilyEvidence returns the authenticated allocation record suitable for
// an immutable same-sequence family pin before a per-architecture floor moves.
func (c VerifiedContainer) WorkerFamilyEvidence() ([]byte, error) {
	if c.fingerprint == "" || len(c.familyEvidence) == 0 {
		return nil, errors.New("worker family requires a verified container")
	}
	return slices.Clone(c.familyEvidence), nil
}

// VerifyWorkerFamilyEvidence authenticates historical allocation evidence and
// compares its family with an already verified incoming worker. It grants no
// runtime authority and never treats another architecture's sequence as a floor.
func VerifyWorkerFamilyEvidence(wire []byte, roots trust.Keyring, incoming VerifiedContainer) error {
	if incoming.fingerprint == "" || len(incoming.familyEvidence) == 0 {
		return errors.New("worker family requires a verified incoming container")
	}
	return verifyWorkerFamilyEvidence(wire, roots, incoming.claim, incoming.genesis)
}

func verifyWorkerFamilyEvidence(wire []byte, roots trust.Keyring, claim ContainerClaim, genesis ...VerifiedWorkloadGenesis) error {
	if len(wire) == 0 || len(wire) > MaxWorkerFamilyEvidenceBytes {
		return errors.New("worker family evidence exceeds bound or is missing")
	}
	head, err := verifySequenceHead(wire, roots, claim.Role, claim.Environment, genesis...)
	if err != nil {
		return err
	}
	migration := head.WorkloadGenesisSHA256
	if migration == "" {
		migration, err = trust.Fingerprint(head.Migration)
		if err != nil {
			return err
		}
	}
	family, err := claim.WorkerFamilyDigest()
	if err != nil {
		return err
	}
	expected := SequenceIdentity{Role: claim.Role, Environment: claim.Environment, SourceRevision: claim.SourceRevision, ManifestSHA256: family}
	if head.Sequence != claim.ReleaseSequence || head.Identity != expected || migration != claim.OrderingSHA256() || (head.WorkloadGenesisSHA256 != "") != (claim.WorkloadGenesisSHA256 != "") {
		return errors.New("worker differs from authenticated sequence family")
	}
	return nil
}

// readWorkerFamily reads the immutable global winner, never the advancing head.
func (location SequenceLocation) readWorkerFamily(ctx context.Context, roots trust.Keyring, verified VerifiedContainer) ([]byte, error) {
	migration := verified.migration
	namespace, bucket := migration.Namespace, migration.Bucket
	if verified.genesis.IsVerified() {
		namespace, bucket = verified.genesis.origin.Namespace, verified.genesis.origin.Bucket
	}
	if location.Client == nil || location.Namespace != namespace || location.Bucket != bucket {
		return nil, errors.New("worker family reader differs from root-authorized sequence location")
	}
	claim := verified.claim
	name := SequenceReservationObject(claim.Role, claim.Environment, claim.OrderingSHA256(), claim.ReleaseSequence)
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name})
	if err != nil {
		return nil, err
	}
	if response.Content == nil {
		return nil, errors.New("worker family allocation has no body")
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, MaxWorkerFamilyEvidenceBytes+1))
	if err != nil {
		return nil, err
	}
	if err := verifyWorkerFamilyEvidence(wire, roots, claim, verified.genesis); err != nil {
		return nil, err
	}
	return wire, nil
}
