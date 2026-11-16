package netbird

import (
	"bytes"
)

// Admin PAT bounds. NetBird issues "nbp_" + a 30-character secret + a
// 6-character base62 checksum (40 bytes); longer future tokens are accepted
// up to maxAdminPATBytes.
const (
	minAdminPATBytes = 40
	maxAdminPATBytes = 256
)

// validAdminPAT is the single NetBird personal access token shape check: the
// "nbp_" prefix followed by a bounded base62 body.
func validAdminPAT(token []byte) bool {
	if len(token) < minAdminPATBytes || len(token) > maxAdminPATBytes || !bytes.HasPrefix(token, []byte("nbp_")) {
		return false
	}
	for _, c := range token[4:] {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// ValidAdminPAT reports whether token has NetBird's PAT shape. The manager
// client and the OCI Vault reader share this predicate.
func ValidAdminPAT(token []byte) bool { return validAdminPAT(token) }
