package region

import (
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

var ErrOriginalSourceActorHold = errors.New("original source actor current signed, protected and physical proof is unavailable; HOLD")

// OriginalSourceActorScope identifies original archive custody only. Its values
// confer neither accepted startup identity nor ordinary foundation authority.
type OriginalSourceActorScope struct {
	SHA256               string
	InstanceID           string
	Cell                 string
	InstallationID       string
	Generation           uint64
	GrantSHA256          string
	BundleSHA256         string
	BirthSHA256          string
	ActorRequestSHA256   string
	ActorReadbackSHA256  string
	SourceIAMSHA256      string
	AdmissionReadsSHA256 string
	PublicationSHA256    string
	PlanSHA256           string
	TemplateSHA256       string
	Deadline             time.Time
}

// VerifiedOriginalSourceActor can only be opened from this machine's fixed
// production observations. The zero value grants no source custody.
type VerifiedOriginalSourceActor struct{ proof *originalSourceActorProof }

type originalSourceActorProof struct {
	factory             *ociclient.Factory
	scope               OriginalSourceActorScope
	config              bootstrapmaterial.Config
	intent              OriginalSourceProducerIntent
	attestor            VerifiedAdmissionAttestor
	recordETag          string
	publicETags         [2]string
	materialPublication *OriginalFoundationMaterialIAM
}
