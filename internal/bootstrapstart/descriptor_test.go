package bootstrapstart

import (
	"net/http"
)

type imdsRoundTrip func(*http.Request) (*http.Response, error)

func (fn imdsRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
