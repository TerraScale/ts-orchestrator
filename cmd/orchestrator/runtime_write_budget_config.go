package main

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

// productionWriteBudgetFile contains operator supplied references for the
// billing authority. The policy is produced by the billing service and is
// admitted as an immutable initial snapshot; it is never synthesized from a
// plan or an allowance embedded in the orchestrator.
type productionWriteBudgetFile struct {
	PolicyFile           string `json:"policy_file"`
	StateKey             string `json:"state_key"`
	PolicyServiceKeyFile string `json:"policy_service_key_file"`
	PolicyListenAddress  string `json:"policy_listen_address"`
	Placement            string `json:"placement"`
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
	OrganizationID              string            `json:"organizationId"`
	CycleID                     string            `json:"cycleId"`
	PolicyEpoch                 uint64            `json:"policyEpoch"`
	ConsentEpoch                uint64            `json:"consentEpoch"`
	WriterEpoch                 uint64            `json:"writerEpoch"`
	WriterEpochs                map[string]uint64 `json:"writerEpochs"`
	IncludedWriteUnits          string            `json:"includedWriteUnits"`
	IncludedAllowanceUnits      int64             `json:"includedAllowanceUnits"`
	PaidExcessEnabled           bool              `json:"paidExcessEnabled"`
	RateNanoDollar              int64             `json:"rateNanoDollar"`
	OrganizationSpendNano       *int64            `json:"organizationSpendNano"`
	DatabaseSpendCapsCents      map[string]int64  `json:"databaseSpendCapsCents"`
	AccruedNonWriteNano         string            `json:"accruedNonWriteNano"`
	DatabaseAccruedNonWriteNano map[string]string `json:"databaseAccruedNonWriteNano"`
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
	if f.PolicyServiceKeyFile != "" && !absoluteCleanPath(f.PolicyServiceKeyFile) {
		return errors.New("write budget: policy service key file must be an absolute clean path")
	}
	return nil
}

func absoluteCleanPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func loadProductionWriteBudgetPolicy(path string) (writebudget.Policy, error) {
	raw, err := bootstrapcredentials.ReadFile(path, false, 256<<10)
	if err != nil {
		return writebudget.Policy{}, err
	}
	var envelope productionWriteBudgetPolicyFile
	if err := json.Unmarshal(raw, &envelope, json.RejectUnknownMembers(true)); err != nil {
		return writebudget.Policy{}, errors.New("write budget: policy file must be strict JSON")
	}
	encodedPolicy, err := json.Marshal(envelope.Policy)
	if err != nil {
		return writebudget.Policy{}, errors.New("write budget: policy document is invalid")
	}
	var p writeBudgetPolicyDocument
	if err := json.Unmarshal(encodedPolicy, &p); err != nil {
		return writebudget.Policy{}, errors.New("write budget: policy document is invalid")
	}
	if envelope.SchemaVersion != 1 || envelope.OrganizationID == "" || envelope.CycleID == "" || envelope.AccountRevision == "" || envelope.PolicyGeneration <= 0 || envelope.Checksum == "" || p.OrganizationID != envelope.OrganizationID || p.CycleID != envelope.CycleID {
		return writebudget.Policy{}, errors.New("write budget: policy envelope is incomplete")
	}
	if p.IncludedWriteUnits == "" || p.IncludedAllowanceUnits < 0 || p.PolicyEpoch == 0 || p.ConsentEpoch == 0 || p.WriterEpoch == 0 || len(p.WriterEpochs) == 0 || p.RateNanoDollar < 0 {
		return writebudget.Policy{}, errors.New("write budget: policy authority fields are incomplete")
	}
	policy := writebudget.Policy{
		OrganizationID: p.OrganizationID, CycleID: p.CycleID, PolicyEpoch: p.PolicyEpoch,
		ConsentEpoch: p.ConsentEpoch, WriterEpoch: p.WriterEpoch, WriterEpochs: p.WriterEpochs,
		IncludedAllowanceUnits: p.IncludedAllowanceUnits, PaidExcessEnabled: p.PaidExcessEnabled,
		RateNanoDollar: p.RateNanoDollar, OrganizationSpendCap: p.OrganizationSpendNano,
		DatabaseSpendCaps: make(map[string]*int64, len(p.DatabaseSpendCapsCents)),
	}
	for database, cents := range p.DatabaseSpendCapsCents {
		if database == "" || cents < 0 || cents > (1<<63-1)/10_000_000 {
			return writebudget.Policy{}, errors.New("write budget: database spending cap is invalid")
		}
		nano := cents * 10_000_000
		policy.DatabaseSpendCaps[database] = &nano
	}
	return policy, nil
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
	policy, err := loadProductionWriteBudgetPolicy(file.PolicyFile)
	if err != nil {
		return config, nil, fmt.Errorf("write budget policy: %w", err)
	}
	config = runtimeWriteBudgetConfig{Policy: policy, StateKey: file.StateKey, Signer: signer, Placement: file.Placement, Delivery: delivery}
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
	listener, err := net.Listen("tcp", file.PolicyListenAddress)
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
