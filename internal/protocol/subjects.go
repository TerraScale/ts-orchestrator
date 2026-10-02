package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nkeys"
)

const (
	SubjectRoot = "ts.orch.v1"
	GlobalScope = "global"
)

var ErrInvalidSubjectToken = errors.New("protocol subject token is invalid")

// CanonicalRegion validates and uppercases a region identifier. Its subject token
// is the lowercase form returned by RegionToken.
func CanonicalRegion(region string) (string, error) {
	if region == "" || len(region) > 63 {
		return "", fmt.Errorf("%w: region length is out of bounds", ErrInvalidSubjectToken)
	}
	region = strings.ToUpper(region)
	if region == "GLOBAL" {
		return region, nil
	}
	previousHyphen := true
	for _, character := range region {
		if character == '-' {
			if previousHyphen {
				return "", ErrInvalidSubjectToken
			}
			previousHyphen = true
			continue
		}
		if character < 'A' || character > 'Z' {
			if character < '0' || character > '9' {
				return "", ErrInvalidSubjectToken
			}
		}
		previousHyphen = false
	}
	if previousHyphen {
		return "", ErrInvalidSubjectToken
	}
	return region, nil
}

func RegionToken(region string) (string, error) {
	canonical, err := CanonicalRegion(region)
	if err != nil {
		return "", err
	}
	return strings.ToLower(canonical), nil
}

func RegionalRoot(region string) (string, error) {
	token, err := RegionToken(region)
	if err != nil || token == GlobalScope {
		return "", ErrInvalidSubjectToken
	}
	return SubjectRoot + "." + token, nil
}

func QuerySubject(region, query string) (string, error) {
	return regionalSubject(region, "query", query)
}

func CommandSubject(region, command string) (string, error) {
	return regionalSubject(region, "command", command)
}

func ObservationSubject(region, observation string) (string, error) {
	return regionalSubject(region, "observation", observation)
}

// ObservabilitySubject is a read-only member telemetry route inside one
// regional cell, for example ts.orch.v1.gru.obs.snapshot. Every controller
// answers it; it carries no signed state and never drives a mutation.
func ObservabilitySubject(region, leaf string) (string, error) {
	return regionalSubject(region, "obs", leaf)
}

// ObservabilityWildcard is the subscribe grant covering every
// ObservabilitySubject leaf of one region.
func ObservabilityWildcard(region string) (string, error) {
	if _, err := RegionalRoot(region); err != nil {
		return "", err
	}
	return ObservabilityGrant(region), nil
}

func AgentCommandSubject(region, nodeID, command string) (string, error) {
	return agentSubject(region, nodeID, "command", command)
}

// AgentObservationSubject binds the host RPC route to the authenticated NATS
// user key. A scoped account signer grants publish on this exact key's route.
func AgentObservationSubject(region, userPublicKey, observation string) (string, error) {
	if !nkeys.IsValidPublicUserKey(userPublicKey) {
		return "", ErrInvalidSubjectToken
	}
	root, err := RegionalRoot(region)
	if err != nil {
		return "", err
	}
	if err := ValidateSubjectToken(observation); err != nil {
		return "", err
	}
	return root + ".agent." + userPublicKey + ".observation." + observation, nil
}

func AgentAckSubject(region, nodeID, acknowledgement string) (string, error) {
	return agentSubject(region, nodeID, "ack", acknowledgement)
}

func AgentReplySubject(region, nodeID, operationID string) (string, error) {
	if !validIdentity(operationID, 128) {
		return "", fmt.Errorf("%w: invalid operation ID", ErrInvalidSubjectToken)
	}
	return agentSubject(region, nodeID, "reply", HashToken(operationID)[:32])
}

func GlobalControlSubject(action string) (string, error) {
	if err := ValidateSubjectToken(action); err != nil {
		return "", err
	}
	return SubjectRoot + "." + GlobalScope + ".control." + action, nil
}

// HashToken hashes caller-controlled identities before they enter a subject.
func HashToken(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

func ValidateSubjectToken(token string) error {
	if !validToken(token) {
		return ErrInvalidSubjectToken
	}
	return nil
}

func regionalSubject(region, family, leaf string) (string, error) {
	if err := ValidateSubjectToken(leaf); err != nil {
		return "", err
	}
	root, err := RegionalRoot(region)
	if err != nil {
		return "", err
	}
	return root + "." + family + "." + leaf, nil
}

func agentSubject(region, nodeID, family, leaf string) (string, error) {
	if !validIdentity(nodeID, 512) {
		return "", fmt.Errorf("%w: invalid node identity", ErrInvalidSubjectToken)
	}
	root, err := RegionalRoot(region)
	if err != nil {
		return "", err
	}
	if err := ValidateSubjectToken(leaf); err != nil {
		return "", err
	}
	return root + ".agent." + HashToken(nodeID) + "." + family + "." + leaf, nil
}

func validToken(token string) bool {
	if token == "" || len(token) > 63 || token[0] == '-' || token[len(token)-1] == '-' {
		return false
	}
	for _, character := range token {
		if character == '-' || character == '_' {
			continue
		}
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}
