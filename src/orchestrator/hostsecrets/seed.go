// Package hostsecrets installs pinned OCI Vault credentials on their intended host.
package hostsecrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

const OrchestratorUser = "terrascale-orchestrator"

const SeedPath = "/etc/terrascale/host-secrets.json"
const MaxSeedBytes = 32 << 10
const MaxSecretBytes = 64 << 10

var (
	ErrSeed        = errors.New("hostsecrets: invalid public seed")
	ErrIdentity    = errors.New("hostsecrets: instance identity unavailable")
	ErrFetch       = errors.New("hostsecrets: secret retrieval failed")
	ErrDigest      = errors.New("hostsecrets: secret identity mismatch")
	ErrOwnership   = errors.New("hostsecrets: unsafe filesystem ownership")
	ErrJournal     = errors.New("hostsecrets: publication journal conflict")
	ErrPublish     = errors.New("hostsecrets: credential publication failed")
	ErrUnsupported = errors.New("hostsecrets: root Linux host required")
)

type Seed struct {
	Region      string  `json:"region"`
	OperationID string  `json:"operationId"`
	Entries     []Entry `json:"entries"`
}

type Entry struct {
	SecretID      string `json:"secretId"`
	VersionNumber int64  `json:"versionNumber"`
	SHA256        string `json:"sha256"`
	Destination   string `json:"destination"`
}

var regionPattern = regexp.MustCompile(`^[a-z]{2,3}-[a-z0-9]+-[1-9][0-9]*$`)
var secretPattern = regexp.MustCompile(`^ocid1\.vaultsecret\.oc1\.[a-z0-9-]+\.[a-zA-Z0-9]+$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var operationPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func allowedDestination(path string) bool {
	switch path {
	case "/etc/terrascale/ts-node-bootstrap/client.key", "/etc/terrascale/ts-node-bootstrap/user.seed", "/etc/terrascale/orchestrator/membership.key", "/etc/terrascale/orchestrator/command.key":
		return true
	}
	for _, scope := range []string{"global", "regional"} {
		for _, leaf := range []string{"server.key", "client.key", "user.seed"} {
			if path == "/etc/terrascale/orchestrator/"+scope+"/"+leaf {
				return true
			}
		}
	}
	return false
}

// ValidateSeed validates public identities only. It does not read credentials
// or contact OCI. The caller's immutable admission manifest must bind the seed.
func ValidateSeed(seed Seed) error {
	if !regionPattern.MatchString(seed.Region) || !operationPattern.MatchString(seed.OperationID) || len(seed.Entries) == 0 || len(seed.Entries) > 10 {
		return ErrSeed
	}
	seen := map[string]bool{}
	for _, entry := range seed.Entries {
		if len(entry.SecretID) > 256 || !secretPattern.MatchString(entry.SecretID) || entry.VersionNumber <= 0 || !digestPattern.MatchString(entry.SHA256) || !allowedDestination(entry.Destination) || seen[entry.Destination] {
			return ErrSeed
		}
		seen[entry.Destination] = true
	}
	return nil
}

func ParseSeed(body []byte) (Seed, error) {
	var seed Seed
	if len(body) == 0 || len(body) > MaxSeedBytes {
		return seed, ErrSeed
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&seed) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Seed{}, ErrSeed
	}
	if err := ValidateSeed(seed); err != nil {
		return Seed{}, err
	}
	return seed, nil
}
func digest(body []byte) string    { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func seedDigest(seed Seed) string  { body, _ := json.Marshal(seed); return digest(body) }
func erase(body []byte)            { clear(body) }
func entryName(entry Entry) string { return strings.TrimPrefix(entry.Destination, "/etc/terrascale/") }
