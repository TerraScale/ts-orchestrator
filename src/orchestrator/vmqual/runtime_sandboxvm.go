//go:build sandboxvm

package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

type FileReadinessProbe struct {
	Root     string
	Manifest vmimage.GuestImageManifest
}

var readinessID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func (p FileReadinessProbe) Probe(c context.Context, id string) (sandboxvm.Readiness, error) {
	if c == nil {
		return sandboxvm.Readiness{}, errors.New("readiness context is nil")
	}
	if e := c.Err(); e != nil {
		return sandboxvm.Readiness{}, e
	}
	if p.Root == "" || !filepath.IsAbs(p.Root) {
		return sandboxvm.Readiness{}, errors.New("readiness root must be absolute")
	}
	if !readinessID.MatchString(id) || id == "." || id == ".." {
		return sandboxvm.Readiness{}, errors.New("readiness VM id is invalid")
	}
	if err := p.Manifest.Validate(); err != nil {
		return sandboxvm.Readiness{}, err
	}
	path := filepath.Join(p.Root, id+".json")
	if !pathWithin(p.Root, path) {
		return sandboxvm.Readiness{}, errors.New("readiness path escapes root")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return sandboxvm.Readiness{}, e
	}
	var m vmimage.ReadinessMetadata
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&m); e != nil {
		return sandboxvm.Readiness{}, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return sandboxvm.Readiness{}, errors.New("readiness metadata has trailing JSON")
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
	if err := c.Validate(); err != nil {
		return nil, err
	}
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
	}, Probe: FileReadinessProbe{Root: c.ReadinessRoot, Manifest: m}})
}
