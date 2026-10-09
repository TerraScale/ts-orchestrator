package natscell

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const nodeIdentityFile = "node-identity.json"

// nodeIdentity binds a disk to its cell/controller slot and immutable Raft ID,
// independently of the server's display name.
type nodeIdentity struct {
	Cell     string `json:"cell"`
	Instance string `json:"instance"`
	NodeID   string `json:"node_id"`
}

// pinNodeIdentity records the actual broker identity before NATS starts. The
// existing server-name guard still proves ownership during preparation.
func pinNodeIdentity(dir, cell, instance, nodeID string) error {
	return pinNodeIdentityWithSync(dir, cell, instance, nodeID, syncIdentityDirectory)
}

func pinNodeIdentityWithSync(dir, cell, instance, nodeID string, syncDirectory func(string) error) error {
	if cell == "" || instance == "" || !validNodeID(nodeID) {
		return fmt.Errorf("%w: invalid Raft store identity", ErrStoreIdentity)
	}
	want := nodeIdentity{Cell: cell, Instance: instance, NodeID: nodeID}
	path := filepath.Join(dir, nodeIdentityFile)
	check := func() error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 1024 {
			return fmt.Errorf("%w: invalid node identity file", ErrStoreIdentity)
		}
		wire, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var recorded nodeIdentity
		if err := protocol.DecodeStrict(wire, &recorded, 1024); err != nil || recorded != want {
			return fmt.Errorf("%w: node identity differs from this cell/controller and Raft ID", ErrStoreIdentity)
		}
		return nil
	}
	if err := check(); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return err
		}
		return syncDirectory(dir)
	}
	wire, err := json.Marshal(want)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, "node-identity.*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err := temp.Write(wire); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	// Link publishes a complete record without replacing another starter's pin.
	if err := os.Link(temp.Name(), path); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	return check()
}

func syncIdentityDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validNodeID(id string) bool {
	if len(id) != 8 {
		return false
	}
	for _, ch := range id {
		if !(ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z') {
			return false
		}
	}
	return true
}
