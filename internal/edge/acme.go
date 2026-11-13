package edge

import (
	"net/http"
	"strings"
)

const challengePath = "/.well-known/acme-challenge/"

func (e *Edge) serveChallenge(w http.ResponseWriter, r *http.Request) {
	e.challenges.ServeHTTP(w, r)
}

func isChallenge(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, challengePath) }
