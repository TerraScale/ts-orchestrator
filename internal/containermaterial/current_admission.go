//go:build linux

package containermaterial

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
)

// CurrentTaskSources are root-owned concrete readers, never ordinary-process
// callbacks. The genesis and candidate lease come from independent admission.
type CurrentTaskSources struct {
	Client            api.ControlReader
	JS                jetstream.JetStream
	Delivery          *delivery.Service
	Mutations         *authority.Reader
	Genesis           trust.Keyring
	RootIdentity      trust.ChainIdentity
	RootHead          string
	ResponsePublic    ed25519.PublicKey
	Lease             *authority.LeaseAdmission
	Credentials       ControllerCredentials
	ContainerProfiles ContainerProfiles
}

// ContainerProfiles is the root-owned immutable archive, never a caller locator.
type ContainerProfiles interface {
	ReadContainerProfile(context.Context, string) ([]byte, error)
}

// ControllerCredentials is supplied only by the private root producer.
type ControllerCredentials interface {
	Context() context.Context
	Guard(context.Context) error
}

type CurrentTask struct {
	Task       *api.Task
	Profile    Profile
	Release    release.VerifiedContainer
	Controller *bootstrapstart.ControllerHostRecipient
}

// Admission grants only exact signed-request material delivery.
type Admission struct{ state *currentTaskAdmission }

// GenerationAdmission grants metadata observation, never material delivery.
type GenerationAdmission struct{ state *currentTaskAdmission }

// TaskMaterial is checked output metadata, never an admission input.
type TaskMaterial struct {
	Binding      host.ContainerMaterialBinding
	OperationID  string
	ConfigDigest string
	Generation   uint64
	User         string
	ExpiresAt    time.Time
}

type currentTaskAdmission struct {
	sources               CurrentTaskSources
	original              context.Context
	credentials           context.Context
	task                  *api.Task
	profile               Profile
	verified              release.VerifiedContainer
	controller            *bootstrapstart.ControllerHostRecipient
	materialSession       *host.ContainerMaterialSession
	generationSession     *host.ContainerGenerationSession
	binding               host.ContainerMaterialBinding
	specRevision          uint64
	deadline              time.Time
	sealed                bool
	enrollmentSHA256      string
	originalProfileRecord string
}
