package netbird

import (
	"errors"
	"strings"
)

// peerName supplies display text; signed OCI identity and regional Vault access authorize enrollment.
func (e enroller) peerName() (string, error) {
	hostname, err := e.hostname()
	if err != nil || hostname == "" || len(hostname) > 253 || strings.ContainsAny(hostname, "\x00\r\n\t ") {
		return "", errors.New("cannot determine a valid server hostname for NetBird")
	}
	return hostname, nil
}
