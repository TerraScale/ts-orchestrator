// Package databaseadmission durably accepts immutable database creation intent.
// A pending placement receipt never proves a database ready to serve.
package databaseadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/byokauthority"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

var ErrInvalid = errors.New("database admission: invalid request or plan")
var ErrConflict = errors.New("database admission: immutable create conflict")
var ErrForbidden = errors.New("database admission: organization admission denied")

type Request struct {
	ParentDatabaseID string `json:"parent_database_id,omitempty"`
	// These fields are authenticated restore provenance. They are required for
	// branch admissions and are persisted with the immutable request so a retry
	// cannot select a newer source point.
	RecoveryPointID string         `json:"recovery_point_id,omitempty"`
	JournalCut      string         `json:"journal_cut,omitempty"`
	RestoreEpoch    uint64         `json:"restore_epoch,omitempty"`
	RestoreProvider string         `json:"restore_provider,omitempty"`
	Environment     string         `json:"environment"`
	TenantID        string         `json:"tenant_id"`
	ProjectID       string         `json:"project_id"`
	Name            string         `json:"name"`
	OperationID     string         `json:"operation_id"`
	Regions         []string       `json:"regions"`
	Residency       string         `json:"residency"`
	BYOK            *BYOKReference `json:"byok,omitempty"`
}

// BYOKReference carries customer-owned provider references only. These
// references are safe to persist in the authenticated NATS admission journal
// so a restarted orchestrator can reconstruct provider clients. Provider
// credentials and plaintext key material are deliberately outside this
// contract. Wrapped DEKs are persisted separately on keylease.Entry, where
// their database binding and ciphertext-only invariant are enforced.
type BYOKReference struct {
	BackupEndpoint         string `json:"backup_endpoint"`
	BackupBucket           string `json:"backup_bucket"`
	BackupRegion           string `json:"backup_region"`
	BackupRoleARN          string `json:"backup_role_arn"`
	BackupExternalID       string `json:"backup_external_id,omitempty"`
	KeyProvider            string `json:"key_provider"`
	KeyID                  string `json:"key_id"`
	KeyRegion              string `json:"key_region"`
	KeyEndpoint            string `json:"key_endpoint,omitempty"`
	ConfigurationUpdatedAt string `json:"configuration_updated_at,omitempty"`
}

type BYOKConfig = BYOKReference
type RestoreSelection struct {
	Kind       string `json:"kind"`
	PointID    string `json:"point_id,omitempty"`
	UnixMillis int64  `json:"unix_millis,omitempty"`
}
type RestoreRequest struct {
	Environment      string           `json:"environment"`
	TenantID         string           `json:"tenant_id"`
	ProjectID        string           `json:"project_id"`
	SourceDatabaseID string           `json:"source_database_id"`
	Name             string           `json:"name"`
	Selection        RestoreSelection `json:"selection"`
	OperationID      string           `json:"operation_id"`
}
type RestoreAdmissionFacts struct {
	SourceDigest     string `json:"source_digest"`
	CapturedAtMillis uint64 `json:"captured_at_millis"`
	Checksum         string `json:"checksum"`
	RowCount         uint64 `json:"row_count"`
	PointID          string `json:"point_id"`
	Provider         string `json:"provider"`
	JournalCut       string `json:"journal_cut"`
	Epoch            uint64 `json:"epoch"`
}

// RestoreAcknowledgement is the native restore authority's durable proof. It
// is bound to the admitted target, source, and exact resolved facts.
type RestoreAcknowledgement struct {
	Version          uint32                `json:"version"`
	TargetDatabaseID string                `json:"target_database_id"`
	SourceDatabaseID string                `json:"source_database_id"`
	Facts            RestoreAdmissionFacts `json:"facts"`
}
type Target struct {
	ServerIdentity string
	MemberID       string
	Region         string
	Provision      keylease.ProvisionTarget
	Proposal       []byte
	Installed      bool
	BYOK           *BYOKReference `json:"byok,omitempty"`
}
type PlacementTarget struct {
	ServerIdentity, MemberID, Region string
	Proposal                         []byte
	// Receipt is the exact fenced producer acknowledgement for Proposal. It is
	// populated only after the remote stage has been acknowledged.
	Receipt             []byte
	Revision            uint64
	AcceptedReceipt     []byte
	AcceptedProof       []byte
	AcceptedRevision    uint64
	AcceptedEpoch       uint64
	AcceptedGeneration  uint64
	AcceptedProofDigest string
	Proposed            bool
}
type Plan struct {
	Members    []Target
	Placements []PlacementTarget
}
type Record struct {
	BYOK             *BYOKReference         `json:"byok,omitempty"`
	RestoreReceipt   []byte                 `json:"restore_receipt,omitempty"`
	RestoreFacts     *RestoreAdmissionFacts `json:"restore_facts,omitempty"`
	Restore          *RestoreRequest        `json:"restore,omitempty"`
	PlacementTargets []PlacementTarget
	BranchSource     *BranchSource
	BranchEvidence   []SignedReadiness
	BranchNonce      string
	Revision         uint64
	CreatedAt        time.Time
	Request          Request
	DatabaseID       string
	KeyVersion       string
	State            string
	Targets          []Target
	Wrapped          []keylease.Entry
	ReadyEvidence    []SignedReadiness
	ReadinessNonce   string
}
type Journal interface {
	Load(context.Context, string) (Record, bool, error)
	Save(context.Context, string, uint64, Record) (uint64, error)
	List(context.Context) ([]Record, error)
}

var canonicalID = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var databaseName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
var environmentName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

func ScopeKey(r Request) string {
	value, _ := json.Marshal([]string{r.Environment, r.TenantID, r.ProjectID, r.Name})
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// PlacementOperationID namespaces customer retry keys by their full scope.
// Different organizations commonly choose the same human-readable retry key.
func PlacementOperationID(r Request) string {
	value, _ := json.Marshal([]string{r.Environment, r.TenantID, r.ProjectID, r.Name, r.OperationID})
	sum := sha256.Sum256(value)
	return "database-create-" + hex.EncodeToString(sum[:])
}
func ValidateRequest(r Request) error {
	if r.BYOK != nil && ValidateBYOKReference(r.BYOK) != nil {
		return ErrInvalid
	}
	if r.ParentDatabaseID != "" && !canonicalID.MatchString(r.ParentDatabaseID) {
		return ErrInvalid
	}
	if !validBranchProvenance(r) {
		return ErrInvalid
	}
	if !environmentName.MatchString(r.Environment) || !canonicalID.MatchString(r.TenantID) || !canonicalID.MatchString(r.ProjectID) || !databaseName.MatchString(r.Name) || len(r.OperationID) < 1 || len(r.OperationID) > 128 || len(r.Regions) < 1 || len(r.Regions) > 3 {
		return ErrInvalid
	}
	for _, c := range r.OperationID {
		if c < 33 || c > 126 {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, region := range r.Regions {
		if !slices.Contains([]string{"GRU", "SFO", "FRA"}, region) || seen[region] {
			return ErrInvalid
		}
		seen[region] = true
	}
	allowed := []string{"GRU", "SFO", "FRA"}
	switch r.Residency {
	case "", "none":
	case "eu-only":
		allowed = []string{"FRA"}
	case "br-only":
		allowed = []string{"GRU"}
	default:
		allowed = strings.Split(r.Residency, ",")
		if len(allowed) > 3 {
			return ErrInvalid
		}
		constraints := map[string]bool{}
		for _, region := range allowed {
			if !slices.Contains([]string{"GRU", "SFO", "FRA"}, region) || constraints[region] {
				return ErrInvalid
			}
			constraints[region] = true
		}
	}
	for _, region := range r.Regions {
		if !slices.Contains(allowed, region) {
			return ErrInvalid
		}
	}
	return nil
}

func ValidateBYOKReference(b *BYOKReference) error {
	if b == nil {
		return ErrInvalid
	}
	validHTTPS := func(value string, limit int) bool {
		u, err := url.Parse(value)
		return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
	}
	validReference := func(value string, limit int) bool {
		return value != "" && len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
	}
	if b.KeyProvider != "aws-kms" {
		return ErrInvalid
	}
	if !validHTTPS(b.BackupEndpoint, 2048) || !environmentName.MatchString(b.BackupBucket) || len(b.BackupBucket) > 63 || !environmentName.MatchString(b.BackupRegion) || len(b.BackupRegion) > 64 || !strings.HasPrefix(b.BackupRoleARN, "arn:") || !validReference(b.BackupRoleARN, 512) || b.BackupExternalID != "" && !validReference(b.BackupExternalID, 256) || !slices.Contains([]string{"oci-vault", "aws-kms", "azure-key-vault", "customer-kms"}, b.KeyProvider) || !byokauthority.ValidKMSKeyARN(b.KeyID, b.KeyRegion) || b.KeyEndpoint != "" && !validHTTPS(b.KeyEndpoint, 2048) {
		return ErrInvalid
	}
	return nil
}
func ValidateRestoreRequest(r RestoreRequest) error {
	if !environmentName.MatchString(r.Environment) || !canonicalID.MatchString(r.TenantID) || !canonicalID.MatchString(r.ProjectID) || !canonicalID.MatchString(r.SourceDatabaseID) || !databaseName.MatchString(r.Name) || len(r.OperationID) == 0 || len(r.OperationID) > 128 {
		return ErrInvalid
	}
	for _, c := range r.OperationID {
		if c < 33 || c > 126 {
			return ErrInvalid
		}
	}
	if r.Selection.Kind == "latest" {
		if r.Selection.PointID != "" || r.Selection.UnixMillis != 0 {
			return ErrInvalid
		}
	} else if r.Selection.Kind == "point_id" {
		if !validDigest(r.Selection.PointID) || r.Selection.UnixMillis != 0 {
			return ErrInvalid
		}
	} else if r.Selection.Kind == "unix_millis" {
		if r.Selection.UnixMillis < 0 || r.Selection.PointID != "" {
			return ErrInvalid
		}
	} else {
		return ErrInvalid
	}
	return nil
}
func ValidateRecord(r Record) error {
	if err := validateRestoreRecord(r); err != nil {
		return err
	}
	if r.Request.ParentDatabaseID == r.DatabaseID {
		return ErrInvalid
	}
	if ValidateRequest(r.Request) != nil || !reflect.DeepEqual(r.BYOK, r.Request.BYOK) || !canonicalID.MatchString(r.DatabaseID) || !canonicalID.MatchString(r.KeyVersion) || !slices.Contains([]string{"accepted", "keys_provisioned", "members_admitted", "placement_pending", "ready"}, r.State) || len(r.Targets) != len(r.Request.Regions)*2 {
		return ErrInvalid
	}
	hosts := map[string]bool{}
	members := map[string]bool{}
	regions := map[string]int{}
	provisions := map[string]keylease.ProvisionTarget{}
	for _, t := range r.Targets {
		if t.ServerIdentity == "" || hosts[t.ServerIdentity] || !canonicalID.MatchString(t.MemberID) || members[t.MemberID] || !slices.Contains(r.Request.Regions, t.Region) || len(t.Proposal) == 0 {
			return ErrInvalid
		}
		if !reflect.DeepEqual(t.BYOK, r.BYOK) {
			return ErrInvalid
		}
		b := t.Provision.Binding
		if b.Environment != r.Request.Environment || b.TenantID != r.Request.TenantID || b.ProjectID != r.Request.ProjectID || b.DatabaseID != r.DatabaseID || b.KeyVersion != r.KeyVersion || b.Region != t.Region || b.Purpose != "data" {
			return ErrInvalid
		}
		if prior, exists := provisions[t.Region]; exists && !reflect.DeepEqual(prior, t.Provision) {
			return ErrInvalid
		}
		if t.Provision.NotAfter.IsZero() || t.Provision.LeaseSeconds == 0 || t.Provision.LeaseSeconds > 1800 {
			return ErrInvalid
		}
		provisions[t.Region] = t.Provision
		stage := new(pb.PlacementStageRequest)
		if proto.Unmarshal(t.Proposal, stage) != nil || stage.Proposal == nil || stage.Proposal.Environment != r.Request.Environment || !canonicalID.MatchString(stage.Proposal.Cluster) || stage.Proposal.Generation == 0 || stage.Proposal.Epoch == 0 {
			return ErrInvalid
		}
		if t.ServerIdentity != "spiffe://terrascale.tech/"+r.Request.Environment+"/terrabase-member/"+stage.Proposal.Cluster+"/"+t.MemberID {
			return ErrInvalid
		}
		local := false
		for _, assignment := range stage.Proposal.Assignments {
			if assignment.Database != r.DatabaseID {
				continue
			}
			if assignment.Tenant != r.Request.TenantID || assignment.Project != r.Request.ProjectID || !slices.Contains(r.Request.Regions, assignment.Region) {
				return ErrInvalid
			}
			if assignment.Region == t.Region && (assignment.WriterMember == t.MemberID || assignment.FollowerMember == t.MemberID) {
				local = true
			}
		}
		if !local {
			return ErrInvalid
		}
		hosts[t.ServerIdentity] = true
		members[t.MemberID] = true
		regions[t.Region]++
	}
	for _, region := range r.Request.Regions {
		if regions[region] != 2 {
			return ErrInvalid
		}
	}
	return validatePlacementTargets(r)
}

// ValidateNewRecord also checks time-bounded key policy before accepting intent;
// historical operations remain readable after key leases expire.
func ValidateNewRecord(r Record) error {
	if ValidateRecord(r) != nil {
		return ErrInvalid
	}
	for _, t := range r.Targets {
		if !t.Provision.NotAfter.After(time.Now()) {
			return ErrInvalid
		}
	}
	return nil
}

// ImmutableEqual permits progress updates, never a changed identity or plan.
func ImmutableEqual(a, b Record) bool {
	a.CreatedAt = a.CreatedAt.UTC()
	b.CreatedAt = b.CreatedAt.UTC()
	a.Revision = 0
	b.Revision = 0
	a.State = ""
	b.State = ""
	a.Wrapped = nil
	b.Wrapped = nil
	a.RestoreReceipt = nil
	b.RestoreReceipt = nil
	a.BranchSource = nil
	b.BranchSource = nil
	a.BranchEvidence = nil
	b.BranchEvidence = nil
	a.BranchNonce = ""
	b.BranchNonce = ""
	a.ReadyEvidence = nil
	b.ReadyEvidence = nil
	a.ReadinessNonce = ""
	b.ReadinessNonce = ""
	a.Targets = slices.Clone(a.Targets)
	b.Targets = slices.Clone(b.Targets)
	for i := range a.Targets {
		a.Targets[i].Installed = false
		a.Targets[i].Provision.NotAfter = a.Targets[i].Provision.NotAfter.UTC()
	}
	for i := range b.Targets {
		b.Targets[i].Installed = false
		b.Targets[i].Provision.NotAfter = b.Targets[i].Provision.NotAfter.UTC()
	}
	a.PlacementTargets = slices.Clone(a.PlacementTargets)
	b.PlacementTargets = slices.Clone(b.PlacementTargets)
	for i := range a.PlacementTargets {
		a.PlacementTargets[i].Proposed = false
		a.PlacementTargets[i].Receipt = nil
		a.PlacementTargets[i].Revision = 0
		a.PlacementTargets[i].AcceptedReceipt = nil
		a.PlacementTargets[i].AcceptedProof = nil
		a.PlacementTargets[i].AcceptedRevision = 0
		a.PlacementTargets[i].AcceptedEpoch = 0
		a.PlacementTargets[i].AcceptedGeneration = 0
		a.PlacementTargets[i].AcceptedProofDigest = ""
	}
	for i := range b.PlacementTargets {
		b.PlacementTargets[i].Proposed = false
		b.PlacementTargets[i].Receipt = nil
		b.PlacementTargets[i].Revision = 0
		b.PlacementTargets[i].AcceptedReceipt = nil
		b.PlacementTargets[i].AcceptedProof = nil
		b.PlacementTargets[i].AcceptedRevision = 0
		b.PlacementTargets[i].AcceptedEpoch = 0
		b.PlacementTargets[i].AcceptedGeneration = 0
		b.PlacementTargets[i].AcceptedProofDigest = ""
	}
	return reflect.DeepEqual(a, b)
}

func validatePlacementTargets(r Record) error {
	if len(r.PlacementTargets) < len(r.Targets) || len(r.PlacementTargets) > 6 {
		return ErrInvalid
	}
	seen := map[string]PlacementTarget{}
	var shared *pb.PlacementProposal
	for _, target := range r.PlacementTargets {
		if len(target.AcceptedReceipt) != 0 && (target.AcceptedRevision == 0 || target.AcceptedEpoch == 0 || target.AcceptedGeneration == 0 || len(target.AcceptedProofDigest) != 64) {
			return ErrInvalid
		}
		stage := new(pb.PlacementStageRequest)
		if proto.Unmarshal(target.Proposal, stage) != nil || stage.Proposal == nil {
			return ErrInvalid
		}
		proposal := stage.Proposal
		if shared == nil {
			shared = proposal
		} else if !proto.Equal(shared, proposal) {
			return ErrInvalid
		}
		if proposal.Environment != r.Request.Environment || target.ServerIdentity != "spiffe://terrascale.tech/"+r.Request.Environment+"/terrabase-member/"+proposal.Cluster+"/"+target.MemberID {
			return ErrInvalid
		}
		if _, ok := seen[target.ServerIdentity]; ok {
			return ErrInvalid
		}
		seen[target.ServerIdentity] = target
		local := false
		for _, seats := range proposal.Regions {
			if seats.Region == target.Region && slices.Contains(seats.Members, target.MemberID) {
				local = true
			}
		}
		if !local {
			return ErrInvalid
		}
		for _, assignment := range proposal.Assignments {
			if assignment.Database == r.DatabaseID && (assignment.Tenant != r.Request.TenantID || assignment.Project != r.Request.ProjectID || !slices.Contains(r.Request.Regions, assignment.Region)) {
				return ErrInvalid
			}
		}
	}
	if shared == nil {
		return ErrInvalid
	}
	count := 0
	for _, seats := range shared.Regions {
		for _, member := range seats.Members {
			count++
			id := "spiffe://terrascale.tech/" + r.Request.Environment + "/terrabase-member/" + shared.Cluster + "/" + member
			if target, ok := seen[id]; !ok || target.Region != seats.Region {
				return ErrInvalid
			}
		}
	}
	if count != len(seen) {
		return ErrInvalid
	}
	for _, target := range r.Targets {
		placement, ok := seen[target.ServerIdentity]
		if !ok || placement.MemberID != target.MemberID || placement.Region != target.Region || !slices.Equal(placement.Proposal, target.Proposal) {
			return ErrInvalid
		}
	}
	return nil
}
