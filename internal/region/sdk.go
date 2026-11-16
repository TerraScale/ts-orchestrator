package region

import (
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// SDKFoundations reconciles through the authenticated regional SDK factory.
// Authority and checkpoints come from the durable regional attempt.
type SDKFoundations struct{ Factory *ociclient.Factory }
