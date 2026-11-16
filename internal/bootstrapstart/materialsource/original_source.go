package materialsource

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

type VerifiedOriginalSourceArchive struct {
	actor           region.VerifiedOriginalSourceActor
	inputs          originalSourceInputs
	state           originalSourceState
	etag, directory string
}

type originalSourceInputs struct {
	scope                   region.OriginalSourceActorScope
	intent                  region.OriginalSourceProducerIntent
	config                  bootstrapmaterial.Config
	admission               release.AdmissionAttestorAuthorization
	intentSHA, admissionSHA string
}

type originalSourceState struct {
	SchemaVersion                int                               `json:"schemaVersion"`
	Kind                         string                            `json:"kind"`
	Scope                        region.OriginalSourceActorScope   `json:"scope"`
	IntentSHA256                 string                            `json:"intentSha256"`
	AdmissionAuthorizationSHA256 string                            `json:"admissionAuthorizationSha256"`
	Target                       bootstrapmaterial.VaultTarget     `json:"target"`
	SecretName                   string                            `json:"secretName"`
	RetryToken                   string                            `json:"retryToken"`
	StartedAt                    time.Time                         `json:"startedAt"`
	Candidate                    originalSourceCandidate           `json:"candidate"`
	Reference                    materialSourceReference           `json:"reference"`
	OriginalAdmissionInventory   []byte                            `json:"originalAdmissionInventory,omitempty"`
	Publication                  *originalMaterialPublicationState `json:"publication,omitempty"`
	Startup                      map[string][]byte                 `json:"startup,omitempty"`
	SeedCompletion               []byte                            `json:"seedCompletion,omitempty"`
}

type originalSourceCandidate struct {
	SHA256       string `json:"sha256"`
	MaxBytes     int64  `json:"maxBytes"`
	CreateSHA256 string `json:"createSha256"`
}
