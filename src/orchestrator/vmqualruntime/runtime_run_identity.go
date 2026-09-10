package vmqualruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"regexp"

	"terrascale.tech/orchestrator/src/orchestrator/qualificationstate"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type qualificationRunIdentity struct {
	Version             int    `json:"version"`
	ConfigurationSHA256 string `json:"configurationSha256"`
	NetworkRunID        string `json:"networkRunId"`
	StackRunID          string `json:"stackRunId"`
}

var qualificationStackRunIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Retain both ownership namespaces before creating any transport identity or
// host resources. Reopening a state root cannot select a fresh implicit run.
func retainQualificationRunIdentity(stateRoot string, config vmnet.Config) (qualificationRunIdentity, error) {
	var result qualificationRunIdentity
	bad := errors.New("vmqual: durable run identity differs from requested network")
	if !vmqual.CanonicalAbsolute(stateRoot) || stateRoot == string(filepath.Separator) {
		return result, bad
	}
	requested := config.RunID
	config.RunID = ""
	canonical, err := json.Marshal(config, json.Deterministic(true))
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(canonical)
	want := hex.EncodeToString(digest[:])
	parse := func(raw []byte) error {
		if json.Unmarshal(raw, &result, json.RejectUnknownMembers(true)) != nil || result.Version != 1 || result.ConfigurationSHA256 != want || len(result.NetworkRunID) != 32 || !qualificationStackRunIDPattern.MatchString(result.StackRunID) || requested != "" && requested != result.NetworkRunID {
			return bad
		}
		rawID, err := hex.DecodeString(result.NetworkRunID)
		if err != nil || hex.EncodeToString(rawID) != result.NetworkRunID {
			return bad
		}
		return nil
	}
	store, err := qualificationstate.Open(filepath.Join(stateRoot, "qualification-run"))
	if err != nil {
		return result, err
	}
	defer store.Close()
	raw, err := store.LoadOrCreate("identity.json", 4096, func() ([]byte, error) {
		stackID, err := vmqual.NewRunID()
		if err != nil {
			return nil, err
		}
		config.RunID = requested
		plan, err := vmnet.Plan(config)
		if err != nil {
			return nil, err
		}
		return json.Marshal(qualificationRunIdentity{Version: 1, ConfigurationSHA256: want, NetworkRunID: plan.RunID, StackRunID: stackID}, json.Deterministic(true))
	}, parse)
	if err != nil {
		return result, err
	}
	if err := parse(raw); err != nil {
		return qualificationRunIdentity{}, err
	}
	return result, nil
}

func (factory *firecrackerFactory) QualificationRunID() string { return factory.qualificationRunID }

// RetainQualificationRunIdentity exposes the production identity fence to
// material preparation; both processes must use the same pre-planning config.
func RetainQualificationRunIdentity(stateRoot string, config vmnet.Config) (string, error) {
	identity, err := retainQualificationRunIdentity(stateRoot, config)
	if err != nil {
		return "", err
	}
	return identity.NetworkRunID, nil
}
