package rootcapacity

import (
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// Controller retains only concrete root SDK discovery. NATS is opened lazily
// after operation admission, so the root listener can precede broker startup.
type Controller struct {
	factory       *ociclient.Factory
	resolver      region.FoundationResolver
	store         *region.ObjectFoundationStore
	homeAuthority *region.HomeIAMAuthority
}
