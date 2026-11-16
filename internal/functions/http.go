package functions

import (
	"net/http"
)

// Authorizer authenticates the caller and returns its trusted tenant identity.
// Implementations must verify credentials rather than copy a tenant header.
type Authorizer func(*http.Request) (string, error)
