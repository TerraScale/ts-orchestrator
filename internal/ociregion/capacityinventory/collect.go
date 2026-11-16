package capacityinventory

import (
	"errors"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// Reader reads actual regional resources through the shared authenticated SDK
// factory. Public tariffs require no cloud credentials or Usage API history.
type Reader struct {
	factory                  *ociclient.Factory
	endpoint, pricesEndpoint string
	http                     *http.Client
}

func New(factory *ociclient.Factory) (*Reader, error) {
	if factory == nil {
		return nil, errors.New("infrastructure inventory requires authenticated OCI factory")
	}
	return &Reader{factory: factory, pricesEndpoint: priceCatalog, http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OCI price catalog redirect refused") }}}, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
