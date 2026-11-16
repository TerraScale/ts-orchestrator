package hostenroll

import (
	"errors"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
)

// ErrNotManagedHost reports an instance launched without a host descriptor,
// such as a controller sharing the qualified image. An operator-launched C#
// TerraBase host carries a static descriptor (hostboot.Static) instead.
var ErrNotManagedHost = errors.New("instance has no managed host descriptor")

// ErrNodeNotNamed reports a node pool instance the regional leader has not
// renamed to its node name yet; host-setup retries until it has.
var ErrNodeNotNamed = errors.New("pool node is not named yet")

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func NewIMDSClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// InstanceMetadata is the untrusted instance identity hint returned by OCI
// IMDSv2. The controller must independently observe the instance and peer IP.
type InstanceMetadata struct {
	InstanceID string
	Descriptor hostboot.Descriptor
	Wire       []byte
}
