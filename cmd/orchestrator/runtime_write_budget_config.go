package main

import (
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

// productionWriteBudgetFile contains operator supplied references for the
// billing authority. The policy is produced by the billing service and is
// admitted as an immutable initial snapshot; it is never synthesized from a
// plan or an allowance embedded in the orchestrator.
type productionWriteBudgetFile struct {
	PolicyTLS            placementpublisher.TLSFiles `json:"policy_tls"`
	PolicyFile           string                      `json:"policy_file"`
	StateKey             string                      `json:"state_key"`
	PolicyServiceKeyFile string                      `json:"policy_service_key_file"`
	PolicyListenAddress  string                      `json:"policy_listen_address"`
	Placement            string                      `json:"placement"`
}

type productionWriteBudgetPolicyFile struct {
	SchemaVersion    int            `json:"schemaVersion"`
	OrganizationID   string         `json:"organizationId"`
	CycleID          string         `json:"cycleId"`
	AccountRevision  string         `json:"accountRevision"`
	PolicyGeneration int            `json:"policyGeneration"`
	Policy           map[string]any `json:"policy"`
	Checksum         string         `json:"checksum"`
}

type writeBudgetPolicyDocument struct {
	PolicyEpoch  uint64            `json:"policyEpoch"`
	ConsentEpoch uint64            `json:"consentEpoch"`
	WriterEpoch  uint64            `json:"writerEpoch"`
	WriterEpochs map[string]uint64 `json:"writerEpochs"`
}

func (f productionWriteBudgetFile) validate() error {
	if f.PolicyFile == "" || f.StateKey == "" || f.Placement == "" {
		return errors.New("write budget: policy, state key, and placement are required")
	}
	if !absoluteCleanPath(f.PolicyFile) {
		return errors.New("write budget: policy file must be an absolute clean path")
	}
	if f.PolicyListenAddress == "" && f.PolicyServiceKeyFile != "" || f.PolicyListenAddress != "" && f.PolicyServiceKeyFile == "" {
		return errors.New("write budget: policy listener and service key must be configured together")
	}
	if f.PolicyListenAddress != "" && (!absoluteCleanPath(f.PolicyTLS.CertificateFile) || !absoluteCleanPath(f.PolicyTLS.PrivateKeyFile) || !absoluteCleanPath(f.PolicyTLS.TrustBundleFile)) {
		return errors.New("write budget: policy TLS identity files are required")
	}
	if f.PolicyServiceKeyFile != "" && !absoluteCleanPath(f.PolicyServiceKeyFile) {
		return errors.New("write budget: policy service key file must be an absolute clean path")
	}
	return nil
}

func absoluteCleanPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func loadProductionWriteBudgetPolicy(path string) (writebudget.Policy, writebudget.PolicyEnvelope, error) {
	raw, err := bootstrapcredentials.ReadFile(path, false, 256<<10)
	if err != nil {
		return writebudget.Policy{}, writebudget.PolicyEnvelope{}, err
	}
	var envelope productionWriteBudgetPolicyFile
	if err := json.Unmarshal(raw, &envelope, json.RejectUnknownMembers(true)); err != nil {
		return writebudget.Policy{}, writebudget.PolicyEnvelope{}, errors.New("write budget: policy file must be strict JSON")
	}
	encodedPolicy, err := json.Marshal(envelope.Policy)
	if err != nil {
		return writebudget.Policy{}, writebudget.PolicyEnvelope{}, errors.New("write budget: policy document is invalid")
	}
	var p writeBudgetPolicyDocument
	if err := json.Unmarshal(encodedPolicy, &p); err != nil {
		return writebudget.Policy{}, writebudget.PolicyEnvelope{}, errors.New("write budget: policy document is invalid")
	}
	if envelope.SchemaVersion != 1 || envelope.OrganizationID == "" || envelope.CycleID == "" || envelope.AccountRevision == "" || envelope.PolicyGeneration <= 0 || envelope.Checksum == "" {
		return writebudget.Policy{}, writebudget.PolicyEnvelope{}, errors.New("write budget: policy envelope is incomplete")
	}
	if p.PolicyEpoch == 0 || p.ConsentEpoch == 0 || p.WriterEpoch == 0 || len(p.WriterEpochs) == 0 {
		return writebudget.Policy{}, writebudget.PolicyEnvelope{}, errors.New("write budget: policy authority fields are incomplete")
	}
	for holder, epoch := range p.WriterEpochs {
		if holder == "" || epoch == 0 {
			return writebudget.Policy{}, writebudget.PolicyEnvelope{}, errors.New("write budget: invalid writer authority")
		}
	}
	policy, err := decodeWriteBudgetPolicy(writebudget.Policy{OrganizationID: envelope.OrganizationID, CycleID: envelope.CycleID, PolicyEpoch: p.PolicyEpoch, ConsentEpoch: p.ConsentEpoch, WriterEpoch: p.WriterEpoch, WriterEpochs: p.WriterEpochs}, writebudget.PolicyEnvelope{SchemaVersion: envelope.SchemaVersion, OrganizationID: envelope.OrganizationID, CycleID: envelope.CycleID, AccountRevision: envelope.AccountRevision, PolicyGeneration: envelope.PolicyGeneration, Policy: envelope.Policy, Checksum: envelope.Checksum})
	if err != nil {
		return writebudget.Policy{}, writebudget.PolicyEnvelope{}, err
	}
	return policy, writebudget.PolicyEnvelope{SchemaVersion: envelope.SchemaVersion, OrganizationID: envelope.OrganizationID, CycleID: envelope.CycleID, AccountRevision: envelope.AccountRevision, PolicyGeneration: envelope.PolicyGeneration, Policy: envelope.Policy, Checksum: envelope.Checksum}, nil
}

// constructProductionWriteBudgetConfig binds the admitted billing snapshot to
// the current GRU authorities. Signer, placement and delivery are supplied by
// their owning production adapters; this function does not create substitutes.
func constructProductionWriteBudgetConfig(file productionWriteBudgetFile, signer *security.CommandSignatureSigner, delivery writeBudgetDelivery) (runtimeWriteBudgetConfig, func() error, error) {
	var config runtimeWriteBudgetConfig
	if err := file.validate(); err != nil {
		return config, nil, err
	}
	if signer == nil || delivery == nil {
		return config, nil, errors.New("write budget: authenticated signer and regional delivery are required")
	}
	policy, initial, err := loadProductionWriteBudgetPolicy(file.PolicyFile)
	if err != nil {
		return config, nil, fmt.Errorf("write budget policy: %w", err)
	}
	config = runtimeWriteBudgetConfig{InitialPolicy: initial, Policy: policy, StateKey: file.StateKey, Signer: signer, Placement: file.Placement, Delivery: delivery}
	if file.PolicyListenAddress == "" {
		return config, func() error { return nil }, nil
	}
	key, err := bootstrapcredentials.ReadFile(file.PolicyServiceKeyFile, true, 16<<10)
	if err != nil {
		return runtimeWriteBudgetConfig{}, nil, err
	}
	rawServiceKey := string(key)
	serviceKey := strings.TrimSpace(rawServiceKey)
	clearBytes(key)
	if len(serviceKey) < 32 || serviceKey != rawServiceKey {
		return runtimeWriteBudgetConfig{}, nil, errors.New("write budget: policy service key is invalid")
	}
	tlsConfig, err := file.PolicyTLS.LoadTLS()
	if err != nil {
		return runtimeWriteBudgetConfig{}, nil, err
	}
	listener, err := tls.Listen("tcp", file.PolicyListenAddress, tlsConfig)
	if err != nil {
		return runtimeWriteBudgetConfig{}, nil, err
	}
	config.PolicyServiceKey = serviceKey
	config.PolicyListener = listener
	return config, func() error { return listener.Close() }, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
