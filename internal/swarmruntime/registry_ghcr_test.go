package swarmruntime

import (
	"net/http"
)

type registryRoundTrip func(*http.Request) (*http.Response, error)

func (f registryRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
