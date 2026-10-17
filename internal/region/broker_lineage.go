package region

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nkeys"
)

// RuntimeBrokerCreation protects only the original foundation writer's local
// broker. Other regional stores require their own independently proven origin.
type RuntimeBrokerCreation struct {
	OperationID      string                       `json:"operationId"`
	DeploymentID     string                       `json:"deploymentId"`
	SignedClusterID  string                       `json:"signedClusterId"`
	Environment      string                       `json:"environment"`
	HostID           string                       `json:"hostId"`
	InstanceID       string                       `json:"instanceId"`
	AcceptanceSHA256 string                       `json:"acceptanceSha256"`
	AnchorSHA256     string                       `json:"anchorSha256"`
	Broker           identityrekey.BrokerIdentity `json:"broker"`
	Store            identityrekey.StoreIdentity  `json:"store"`
	StartedAt        time.Time                    `json:"startedAt"`
	ExpiresAt        time.Time                    `json:"expiresAt"`
	Genesis          *RuntimeBrokerGenesis        `json:"genesis,omitempty"`
}

type RuntimeBrokerGenesis struct {
	ServerID        string    `json:"serverId"`
	StartedAt       time.Time `json:"startedAt"`
	Device          uint64    `json:"device"`
	Inode           uint64    `json:"inode"`
	UID             uint32    `json:"uid"`
	OperatorSHA256  string    `json:"operatorSha256"`
	SystemJWTSHA256 string    `json:"systemJwtSha256"`
	CellJWTSHA256   string    `json:"cellJwtSha256"`
	MarkerSHA256    string    `json:"markerSha256"`
	MarkerInode     uint64    `json:"markerInode"`
}

// RuntimeTrustFloor stores fingerprints of already verified public signed
// source, keeping the complete protected foundation within its existing cap.
type RuntimeTrustFloor struct {
	OperationID       string    `json:"operationId"`
	RootSequence      uint64    `json:"rootSequence"`
	RootHead          string    `json:"rootHead"`
	RootChainSHA256   string    `json:"rootChainSha256"`
	RootStreamCreated time.Time `json:"rootStreamCreated,omitzero"`
	RootRevision      uint64    `json:"rootRevision"`
	SpecGeneration    uint64    `json:"specGeneration"`
	SpecSHA256        string    `json:"specSha256,omitempty"`
	SpecStreamCreated time.Time `json:"specStreamCreated,omitzero"`
	SpecRevision      uint64    `json:"specRevision"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

func (record FoundationRecord) validateBrokerLineage() error {
	lineage := record.RuntimeLineage
	creation := lineage.Broker
	if creation == nil {
		if lineage.TrustFloor != nil {
			return errors.New("root and spec floor has no original broker source")
		}
		return nil
	}
	if creation.OperationID != entityid.Derive("broker-genesis", lineage.FoundationOperationID) ||
		!entityid.Valid(creation.DeploymentID) || !entityid.Valid(creation.SignedClusterID) || !release.ValidEnvironment(creation.Environment) ||
		creation.HostID != "controller-a" && creation.HostID != "controller-b" && creation.HostID != "controller-c" ||
		!strings.HasPrefix(creation.InstanceID, "ocid1.instance.") || len(creation.InstanceID) > 512 ||
		!validFoundationDigest(creation.AcceptanceSHA256) || !validFoundationDigest(creation.AnchorSHA256) ||
		creation.StartedAt.Before(lineage.PreparedAt) || creation.StartedAt.After(record.UpdatedAt) ||
		!creation.ExpiresAt.After(creation.StartedAt) || creation.ExpiresAt.After(creation.StartedAt.Add(30*time.Second)) ||
		!filepath.IsAbs(creation.Store.Directory) || filepath.Clean(creation.Store.Directory) != creation.Store.Directory || len(creation.Store.Directory) > 512 || creation.Store.Directory == "/" ||
		creation.Store.ServerName == "" || len(creation.Store.ServerName) > 128 || creation.Store.RaftNodeID == "" || len(creation.Store.RaftNodeID) > 128 ||
		!validFoundationDigest(creation.Store.ServerNameSHA256) || !validFoundationDigest(creation.Store.NodeIdentitySHA256) || !nkeys.IsValidPublicOperatorKey(creation.Broker.Operator) {
		return errors.New("broker creation has invalid original accepted source")
	}
	accounts := []string{creation.Broker.SystemAccount, creation.Broker.CellAccount, creation.Broker.HostSigner, creation.Broker.RoleSigner}
	for _, account := range []string{creation.Broker.AccountSigner, creation.Broker.InterRegionAccount} {
		if account != "" {
			accounts = append(accounts, account)
		}
	}
	seen := map[string]bool{}
	for _, account := range accounts {
		if !nkeys.IsValidPublicAccountKey(account) || seen[account] {
			return errors.New("broker creation has invalid signed account identity")
		}
		seen[account] = true
	}
	if genesis := creation.Genesis; genesis != nil {
		if genesis.ServerID == "" || len(genesis.ServerID) > 128 || genesis.StartedAt.Before(creation.StartedAt) || genesis.StartedAt.After(record.UpdatedAt) ||
			genesis.Inode == 0 || genesis.MarkerInode == 0 || !validFoundationDigest(genesis.MarkerSHA256) ||
			!validFoundationDigest(genesis.OperatorSHA256) || !validFoundationDigest(genesis.SystemJWTSHA256) || !validFoundationDigest(genesis.CellJWTSHA256) {
			return errors.New("broker genesis has invalid actual storage identity")
		}
	}
	floor := lineage.TrustFloor
	if floor == nil || floor.OperationID != creation.OperationID || floor.RootSequence > trust.MaxRotations || !validFoundationDigest(floor.RootHead) || !validFoundationDigest(floor.RootChainSHA256) ||
		floor.SpecGeneration == 0 && floor.SpecSHA256 != "" || floor.SpecGeneration != 0 && !validFoundationDigest(floor.SpecSHA256) || floor.UpdatedAt.Before(creation.StartedAt) || floor.UpdatedAt.After(record.UpdatedAt) {
		return errors.New("broker source has no valid original root and spec floor")
	}
	if floor.RootRevision != 0 && floor.RootStreamCreated.IsZero() || floor.SpecRevision != 0 && floor.SpecStreamCreated.IsZero() ||
		!floor.RootStreamCreated.IsZero() && (floor.RootStreamCreated.Before(creation.StartedAt) || floor.RootStreamCreated.After(record.UpdatedAt)) ||
		!floor.SpecStreamCreated.IsZero() && (floor.SpecStreamCreated.Before(creation.StartedAt) || floor.SpecStreamCreated.After(record.UpdatedAt)) {
		return errors.New("root or spec floor has invalid actual stream identity")
	}
	if floor.SpecRevision == 0 && floor.SpecGeneration != 0 || floor.SpecRevision != 0 && (floor.SpecGeneration == 0 || floor.RootRevision == 0) ||
		creation.Genesis == nil && (floor.RootRevision != 0 || !floor.RootStreamCreated.IsZero() || floor.SpecRevision != 0 || !floor.SpecStreamCreated.IsZero()) {
		return errors.New("published control floor lacks its original committed broker or exact revision")
	}
	return nil
}

func retainBrokerLineage(previous, current *RuntimeLineageRecord) error {
	if previous.Broker != nil {
		if current.Broker == nil {
			return errors.New("original broker creation cannot be removed")
		}
		before, after := *previous.Broker, *current.Broker
		before.Genesis, after.Genesis = nil, nil
		if before != after || previous.Broker.Genesis != nil && (current.Broker.Genesis == nil || *previous.Broker.Genesis != *current.Broker.Genesis) {
			return errors.New("original broker creation or storage cannot change")
		}
	}
	before, after := previous.TrustFloor, current.TrustFloor
	if before == nil {
		if previous.Broker != nil && after != nil {
			return errors.New("existing uncertified broker cannot acquire an original trust floor")
		}
		return nil
	}
	if after == nil || before.OperationID != after.OperationID || after.RootSequence < before.RootSequence ||
		after.RootSequence == before.RootSequence && (after.RootHead != before.RootHead || after.RootChainSHA256 != before.RootChainSHA256) ||
		after.SpecGeneration < before.SpecGeneration || after.SpecGeneration == before.SpecGeneration && after.SpecSHA256 != before.SpecSHA256 || after.UpdatedAt.Before(before.UpdatedAt) {
		return errors.New("protected root or spec floor rolls back or changes adopted source")
	}
	if previous.Broker != nil && previous.Broker.Genesis == nil && *before != *after {
		return errors.New("uncommitted broker cannot change its original public source floor")
	}
	if after.RootSequence > before.RootSequence && after.RootRevision <= before.RootRevision ||
		after.SpecGeneration > before.SpecGeneration && after.SpecRevision <= before.SpecRevision {
		return errors.New("advanced control generation has no newer actual source revision")
	}
	if !before.RootStreamCreated.IsZero() && !before.RootStreamCreated.Equal(after.RootStreamCreated) ||
		!before.SpecStreamCreated.IsZero() && !before.SpecStreamCreated.Equal(after.SpecStreamCreated) ||
		after.RootRevision < before.RootRevision || after.SpecRevision < before.SpecRevision ||
		before.RootRevision != 0 && before.RootRevision == after.RootRevision && before.RootChainSHA256 != after.RootChainSHA256 ||
		before.SpecRevision != 0 && before.SpecRevision == after.SpecRevision && before.SpecSHA256 != after.SpecSHA256 {
		return errors.New("protected root or spec stream was recreated or its revision changed source")
	}
	return nil
}
