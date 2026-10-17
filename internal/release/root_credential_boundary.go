package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

const RootCredentialBoundarySchema = "terrascale.release.root-credential-boundary.v1"

// RootCredentialBoundaryEvidence is retained native evidence for the final disk.
// Refusals describe a functioning boundary, never an absent service or transport.
type RootCredentialBoundaryEvidence struct {
	Schema      string                       `json:"schema"`
	Candidate   ProductionExpectation        `json:"candidate"`
	CompletedAt time.Time                    `json:"completed_at"`
	Hosts       []RootCredentialBoundaryHost `json:"hosts"`
}

// RootCredentialBoundaryHost binds redacted observations to an independently
// observed native host, its installed source and the fixed ordinary service UID.
type RootCredentialBoundaryHost struct {
	Role               string `json:"role"`
	InstanceID         string `json:"instance_id"`
	ImageOCID          string `json:"image_ocid"`
	SourceRevision     string `json:"source_revision"`
	NamespaceSHA256    string `json:"namespace_sha256"`
	RootUID            uint32 `json:"root_uid"`
	OrdinaryUID        uint32 `json:"ordinary_uid"`
	RootOCIRead        string `json:"root_oci_read"`
	OrdinaryUIDIMDS    string `json:"ordinary_uid_imds"`
	OrdinaryUIDSigning string `json:"ordinary_uid_signing"`
	UnauthorizedIPC    string `json:"unauthorized_ipc"`
	TranscriptSHA256   string `json:"transcript_sha256"`
	Transcript         []byte `json:"transcript"`
}

func (evidence RootCredentialBoundaryEvidence) Validate(expected ProductionExpectation) error {
	if evidence.Schema != RootCredentialBoundarySchema || evidence.Candidate != expected ||
		expected.Role != FoundationWriterRole || evidence.CompletedAt.IsZero() || len(evidence.Hosts) != 4 {
		return fmt.Errorf("%w: root credential boundary candidate or native hosts", ErrProductionQualification)
	}
	seen := make(map[string]bool, len(evidence.Hosts))
	roles := make(map[string]int, 2)
	var imageID string
	for _, host := range evidence.Hosts {
		sum := sha256.Sum256(host.Transcript)
		if host.InstanceID == "" || seen[host.InstanceID] ||
			!ValidOCIImageIDForRegion(host.ImageOCID, expected.Cell) || imageID != "" && host.ImageOCID != imageID ||
			host.SourceRevision != expected.SourceRevision || !digestPattern.MatchString(host.NamespaceSHA256) ||
			host.RootUID != 0 || host.OrdinaryUID == 0 || host.RootOCIRead != "authenticated" ||
			host.OrdinaryUIDIMDS != "refused" || host.OrdinaryUIDSigning != "refused" || host.UnauthorizedIPC != "refused" ||
			len(host.Transcript) == 0 || hex.EncodeToString(sum[:]) != host.TranscriptSHA256 ||
			host.Role != "manager" && host.Role != "container" {
			return fmt.Errorf("%w: native root credential boundary observation", ErrProductionQualification)
		}
		imageID = host.ImageOCID
		seen[host.InstanceID] = true
		roles[host.Role]++
	}
	if roles["manager"] != 3 || roles["container"] != 1 {
		return fmt.Errorf("%w: native root credential boundary topology", ErrProductionQualification)
	}
	return nil
}
