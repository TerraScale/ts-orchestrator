// Package vmcontrolseed renders explicitly owner-admitted initial GRU launches.
// Credentials travel through the private guest sideband, never cloud-init.
package vmcontrolseed

import (
	"encoding/json"
	"fmt"
	"regexp"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

const Directory = "/etc/terrascale/orchestrator"
const NKeyPath = Directory + "/regional/user.seed"
const GlobalNKeyPath = Directory + "/global/user.seed"
const RegionalProvisionerNKeyPath = Directory + "/regional/provisioner.seed"
const GlobalProvisionerNKeyPath = Directory + "/global/provisioner.seed"
const RegionalSnapshotNKeyPath = Directory + "/regional/snapshot-reader.seed"
const GlobalSnapshotNKeyPath = Directory + "/global/snapshot-reader.seed"
const SnapshotCertificatePath = Directory + "/snapshot/client.pem"
const SnapshotPrivateKeyPath = Directory + "/snapshot/client.key"
const CAPath = Directory + "/regional/ca.pem"
const CertificatePath = Directory + "/regional/client.pem"
const PrivateKeyPath = Directory + "/regional/client.key"
const ProvisionerCertificatePath = Directory + "/provisioner/client.pem"
const ProvisionerPrivateKeyPath = Directory + "/provisioner/client.key"
const ServerCertificatePath = Directory + "/regional/server.pem"
const ServerPrivateKeyPath = Directory + "/regional/server.key"
const MembershipKeyPath = Directory + "/identity.pem"
const MembershipPinsPath = Directory + "/membership-pins.json"
const StorePath = "/var/lib/terrascale/orchestrator/nats"
const ServiceUser = "terrascale-orchestrator"
const Arguments = "initial-gru-r1 --config @config"
const GlobalAccount = "GRU_GLOBAL"
const RegionalAccount = "GRU_REGIONAL"

func IsFilePath(path string) bool {
	switch path {
	case RegionalSnapshotNKeyPath, GlobalSnapshotNKeyPath, SnapshotCertificatePath, SnapshotPrivateKeyPath, NKeyPath, GlobalNKeyPath, RegionalProvisionerNKeyPath, GlobalProvisionerNKeyPath, CAPath, CertificatePath, PrivateKeyPath, ProvisionerCertificatePath, ProvisionerPrivateKeyPath, ServerCertificatePath, ServerPrivateKeyPath:
		return true
	}
	return false
}

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Guest struct{ ID, Address, MembershipPublicKey string }
type Material struct {
	HostID, Address, Settings string
	Selected                  bool
	Files                     map[string][]byte
}

func (m Material) Clone() Material {
	out := m
	out.Files = map[string][]byte{}
	for path, data := range m.Files {
		out.Files[path] = append([]byte(nil), data...)
	}
	return out
}
func (m Material) Clear() {
	for _, data := range m.Files {
		clear(data)
	}
}

// DataDriveBytes reserves the admitted broker capacity and filesystem overhead.
// The returned capacity does not assert how much sparse storage is allocated.
func (m Material) DataDriveBytes() (int64, error) {
	if err := m.Validate(); err != nil {
		return 0, err
	}
	if !m.Selected {
		return 64 << 20, nil
	}
	var config initialgrant.Config
	if err := json.Unmarshal([]byte(m.Settings), &config); err != nil {
		return 0, err
	}
	const filesystemAllowance = int64(256 << 20)
	if config.Broker.StorageBudgetBytes <= 0 || config.Broker.StorageBudgetBytes > 1<<40 {
		return 0, fmt.Errorf("vmcontrolseed: invalid admitted disk capacity")
	}
	return config.Broker.StorageBudgetBytes + filesystemAllowance, nil
}

const AuthorityDirectory = "/etc/terrascale/ts-node-authority"
const AuthorityNKeyPath = AuthorityDirectory + "/user.seed"
const AuthorityCAPath = AuthorityDirectory + "/ca.pem"
const AuthorityCertificatePath = AuthorityDirectory + "/client.pem"
const AuthorityPrivateKeyPath = AuthorityDirectory + "/client.key"

func IsAuthorityFilePath(path string) bool {
	return path == AuthorityNKeyPath || path == AuthorityCAPath || path == AuthorityCertificatePath || path == AuthorityPrivateKeyPath
}
func (m Material) AuthorityReader() (nodeauthority.ReaderConfig, error) {
	c, e := initialgrant.ParseConfig([]byte(m.Settings))
	return c.AuthorityReader, e
}
