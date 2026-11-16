package materialsource

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
)

var ErrMaterialSource = errors.New("regional bootstrap source unavailable or conflicts with authorized installation")

type ColdStartMaterial struct {
	grant                     region.VerifiedBootstrapMaterial
	actor                     *region.SourceFounder
	objects                   bootstrapstart.FounderSelectionObjectWriter
	directory, key, etag      string
	kind, binding, secretName string
	link                      *linkInputs
	state                     materialSourceState
	archive                   materialSourceArchive
	record                    bootstrapmaterial.Record
	publication               bootstrapmaterial.Publication
}

type EscrowClient interface {
	bootstrapmaterial.BundleClient
	GetSecretBundleByName(context.Context, ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error)
}

type VerifiedColdStartMaterial struct {
	source      *ColdStartMaterial
	etag        string
	record      bootstrapmaterial.Record
	publication bootstrapmaterial.Publication
}

type materialSourceArchive struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Kind           string            `json:"kind,omitempty"`
	BindingSHA256  string            `json:"bindingSha256,omitempty"`
	InstallationID string            `json:"installationId"`
	Cell           string            `json:"cell"`
	Generation     uint64            `json:"generation"`
	PlanSHA256     string            `json:"planSha256"`
	Files          map[string][]byte `json:"files"`
}

type materialSourceState struct {
	SchemaVersion                int                           `json:"schemaVersion"`
	Actor                        materialSourceActor           `json:"actor"`
	Kind                         string                        `json:"kind,omitempty"`
	BindingSHA256                string                        `json:"bindingSha256,omitempty"`
	InstallationID               string                        `json:"installationId"`
	Cell                         string                        `json:"cell"`
	Generation                   uint64                        `json:"generation"`
	PlanSHA256                   string                        `json:"planSha256"`
	Target                       bootstrapmaterial.VaultTarget `json:"target"`
	SecretName                   string                        `json:"secretName"`
	RetryToken                   string                        `json:"retryToken"`
	StartedAt                    time.Time                     `json:"startedAt"`
	Reference                    materialSourceReference       `json:"reference"`
	Inventory                    []byte                        `json:"inventory,omitempty"`
	AdmissionAuthorizationSHA256 string                        `json:"admissionAuthorizationSha256,omitempty"`
	OriginalAdmissionInventory   []byte                        `json:"originalAdmissionInventory,omitempty"`
	Delivery                     []byte                        `json:"delivery,omitempty"`
	Journal                      []byte                        `json:"journal,omitempty"`
	Startup                      map[string][]byte             `json:"startup,omitempty"`
	SeedCompletion               []byte                        `json:"seedCompletion,omitempty"`
}

type materialSourceActor struct {
	InstanceID     string `json:"instanceId"`
	GrantDigest    string `json:"grantDigest"`
	TemplateDigest string `json:"templateDigest"`
}

type materialSourceReference struct {
	SecretOCID string `json:"secretOcid"`
	SHA256     string `json:"sha256"`
	MaxBytes   int64  `json:"maxBytes"`
}
