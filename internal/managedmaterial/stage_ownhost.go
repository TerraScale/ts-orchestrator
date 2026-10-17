package managedmaterial

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
)

// MaterialStageOwnhostSource preserves each actual source version separately.
// Only the opaque live ManagerRuntimeSession and ownhost binding authenticate it.
type MaterialStageOwnhostSource struct {
	Registration           host.Registration `json:"registration"`
	RegistrationRevision   uint64            `json:"registration_revision"`
	SourceRevision         uint64            `json:"source_revision"`
	SessionID              string            `json:"session_id"`
	SessionEpoch           uint64            `json:"session_epoch"`
	SessionSourceExpiresAt time.Time         `json:"session_source_expires_at"`
}
