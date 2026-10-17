package region

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// RuntimeLineageRecord is prepared with a new protected foundation, before any
// runtime exists. Missing historical records can never be upgraded to genesis.
type RuntimeLineageRecord struct {
	Version               int                    `json:"version"`
	FoundationOperationID string                 `json:"foundationOperationId"`
	Generation            uint64                 `json:"generation"`
	GrantSHA256           string                 `json:"grantSha256"`
	IntentSHA256          string                 `json:"intentSha256"`
	PreparedAt            time.Time              `json:"preparedAt"`
	Creation              *RuntimeCreation       `json:"creation,omitempty"`
	Broker                *RuntimeBrokerCreation `json:"broker,omitempty"`
	TrustFloor            *RuntimeTrustFloor     `json:"trustFloor,omitempty"`
}

// Original excludes the finite operations which progress under this origin.
func (lineage RuntimeLineageRecord) Original() RuntimeLineageRecord {
	lineage.Creation, lineage.Broker, lineage.TrustFloor = nil, nil, nil
	return lineage
}

// RuntimeCreation reserves the original accepted root source before node
// creation. A started reservation is retained across every ambiguous outcome.
type RuntimeCreation struct {
	OperationID      string               `json:"operationId"`
	DeploymentID     string               `json:"deploymentId"`
	SignedClusterID  string               `json:"signedClusterId"`
	Environment      string               `json:"environment"`
	HostID           string               `json:"hostId"`
	InstanceID       string               `json:"instanceId"`
	AcceptanceSHA256 string               `json:"acceptanceSha256"`
	AnchorSHA256     string               `json:"anchorSha256"`
	StartedAt        time.Time            `json:"startedAt"`
	ExpiresAt        time.Time            `json:"expiresAt"`
	Genesis          *RuntimeSwarmGenesis `json:"genesis,omitempty"`
}

// RuntimeSwarmGenesis retains only public actual storage identity.
type RuntimeSwarmGenesis struct {
	ClusterID    string    `json:"clusterId"`
	NodeID       string    `json:"nodeId"`
	RootCASHA256 string    `json:"rootCaSha256"`
	StartedAt    time.Time `json:"startedAt"`
	Version      uint64    `json:"version"`
	Term         uint64    `json:"term"`
	Leader       uint64    `json:"leader"`
}

func (r FoundationRecord) validateRuntimeLineage() error {
	lineage := r.RuntimeLineage
	if lineage == nil {
		return nil
	}
	if lineage.Version != 1 || lineage.Generation == 0 || lineage.Generation > r.Generation ||
		lineage.FoundationOperationID != entityid.Derive("regional-foundation", r.TenancyID, r.Cell, fmt.Sprint(lineage.Generation)) ||
		!validFoundationDigest(lineage.GrantSHA256) || !validFoundationDigest(lineage.IntentSHA256) ||
		lineage.PreparedAt.IsZero() || lineage.PreparedAt.After(r.UpdatedAt) {
		return errors.New("runtime lineage differs from original foundation creation")
	}
	if lineage.Generation == r.Generation && (lineage.FoundationOperationID != r.OperationID || lineage.GrantSHA256 != r.GrantSHA256 || lineage.IntentSHA256 != r.IntentDigest || !lineage.PreparedAt.Equal(r.StartedAt)) {
		return errors.New("runtime lineage differs from its current foundation generation")
	}
	if err := r.validateBrokerLineage(); err != nil {
		return err
	}
	creation := lineage.Creation
	if creation == nil {
		return nil
	}
	if creation.OperationID != entityid.Derive("runtime-genesis", lineage.FoundationOperationID) ||
		!entityid.Valid(creation.DeploymentID) || !entityid.Valid(creation.SignedClusterID) ||
		!release.ValidEnvironment(creation.Environment) || !slices.Contains([]string{"controller-a", "controller-b", "controller-c"}, creation.HostID) ||
		len(creation.InstanceID) > 512 || !strings.HasPrefix(creation.InstanceID, "ocid1.instance.") ||
		!validFoundationDigest(creation.AcceptanceSHA256) || !validFoundationDigest(creation.AnchorSHA256) ||
		creation.StartedAt.Before(lineage.PreparedAt) || creation.StartedAt.After(r.UpdatedAt) ||
		!creation.ExpiresAt.After(creation.StartedAt) || creation.ExpiresAt.After(creation.StartedAt.Add(30*time.Second)) {
		return errors.New("runtime creation reservation has invalid original authority")
	}
	if genesis := creation.Genesis; genesis != nil {
		if genesis.ClusterID == "" || len(genesis.ClusterID) > 128 || genesis.NodeID == "" || len(genesis.NodeID) > 128 ||
			!validFoundationDigest(genesis.RootCASHA256) || genesis.StartedAt.Before(creation.StartedAt) || genesis.StartedAt.After(r.UpdatedAt) ||
			genesis.Version == 0 || genesis.Term == 0 || genesis.Leader == 0 {
			return errors.New("runtime genesis has invalid actual storage identity")
		}
	}
	return nil
}

func retainRuntimeLineage(previous, current *RuntimeLineageRecord) error {
	if previous == nil {
		if current != nil {
			return errors.New("existing uncertified foundation cannot acquire runtime genesis")
		}
		return nil
	}
	if current == nil {
		return errors.New("protected runtime lineage cannot be removed")
	}
	if previous.Original() != current.Original() {
		return errors.New("protected runtime foundation origin cannot change")
	}
	if err := retainBrokerLineage(previous, current); err != nil {
		return err
	}
	if previous.Creation == nil {
		return nil
	}
	if current.Creation == nil {
		return errors.New("runtime creation reservation cannot be reset")
	}
	first, second := *previous.Creation, *current.Creation
	first.Genesis, second.Genesis = nil, nil
	if first != second || previous.Creation.Genesis != nil && (current.Creation.Genesis == nil || *previous.Creation.Genesis != *current.Creation.Genesis) {
		return errors.New("original runtime creation or genesis cannot change")
	}
	return nil
}
