//go:build sandboxvm

package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

type FileReadinessProbe struct {
	Root     string
	Manifest vmimage.GuestImageManifest
}

func (p FileReadinessProbe) Probe(c context.Context, id string) (sandboxvm.Readiness, error) {
	if e := c.Err(); e != nil {
		return sandboxvm.Readiness{}, e
	}
	b, e := os.ReadFile(filepath.Join(p.Root, id+".json"))
	if e != nil {
		return sandboxvm.Readiness{}, e
	}
	var m vmimage.ReadinessMetadata
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&m); e != nil {
		return sandboxvm.Readiness{}, e
	}
	if e = m.Validate(p.Manifest, m.SeedDigest); e != nil {
		return sandboxvm.Readiness{}, e
	}
	if !m.IsReady() {
		return sandboxvm.Readiness{}, errors.New("guest readiness gates incomplete")
	}
	return sandboxvm.Readiness{Systemd: m.SystemdPID1, DataDiskMounted: m.DataDiskReady, Network: m.NetworkReady, TSNodeHealthy: m.TSNodeReady, ServiceHealthy: true}, nil
}
func newSandboxVMProvider(c Config) (*sandboxvm.Provider, error) {
	b, e := os.ReadFile(c.ImageManifestPath)
	if e != nil {
		return nil, e
	}
	m, e := vmimage.DecodeManifest(b)
	if e != nil {
		return nil, e
	}
	return sandboxvm.New(sandboxvm.Options{MachineFactory: sandboxvm.NewSDKMachineFactory(), OpenAPIFactory: func(x sandboxvm.Config) (sandboxvm.OpenAPI, error) {
		return sandboxvm.NewUnixSocketOpenAPI(x.SocketPath)
	}, Probe: FileReadinessProbe{c.ReadinessRoot, m}})
}

var _ = fmt.Sprintf
