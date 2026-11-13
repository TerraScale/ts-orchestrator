package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

func (j *journey) keys() ([][]byte, error) {
	var keys [][]byte
	for _, node := range []string{"c18a", "c18b"} {
		key, err := os.ReadFile(filepath.Join(j.root, node, "swarm", "certificates", "swarm-node.key"))
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (j *journey) quickContinuity(owner *workload, before [][]byte) error {
	after, err := j.keys()
	if err != nil {
		return err
	}
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			return errors.New("agent restart changed node key")
		}
	}
	path := filepath.Join(j.root, "c18a", "data", "c18", "boots")
	boots, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Count(boots, []byte("\n")) != 1 {
		return errors.New("agent restart restarted data owner")
	}
	if err := owner.process.Kill(namespaces.WithNamespace(j.ctx, "terrascale"), syscall.SIGKILL, containerd.WithKillAll); err != nil {
		return err
	}
	if err := until(j.ctx, func() error {
		running, err := j.running(owner.task.ServiceID, owner.host, 0, owner.runtime)
		if err != nil {
			return err
		}
		if len(running) != 1 || running[0].task.ID == owner.task.ID {
			return errors.New("waiting for killed data owner to restart")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(data, boots) || bytes.Count(data, []byte("\n")) != 2 {
			return errors.New("task restart did not retain data")
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Println("quick main lane: same service processes across agent restart; both node keys unchanged; data retained across agent and task restart")
	return nil
}
