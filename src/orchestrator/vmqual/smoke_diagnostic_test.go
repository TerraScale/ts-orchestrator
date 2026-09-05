package vmqual

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type smokeDiagnosticFactory struct {
	*smokeFakeFactory
	resources VMResourceIdentity
	cancel    context.CancelFunc
}

func (f *smokeDiagnosticFactory) PlanResources(context.Context, Guest) (VMResourceIdentity, error) {
	return f.resources, nil
}
func (f *smokeDiagnosticFactory) Create(ctx context.Context, guest Guest) (VM, error) {
	vm, err := f.smokeFakeFactory.Create(ctx, guest)
	if err != nil {
		return nil, err
	}
	return &smokeDiagnosticVM{smokeFakeVM: vm.(*smokeFakeVM), root: f.resources.StateDir, cancel: f.cancel}, nil
}

type smokeDiagnosticVM struct {
	*smokeFakeVM
	root   string
	cancel context.CancelFunc
}

func (v *smokeDiagnosticVM) StartReady(ctx context.Context) error {
	if v.cancel != nil {
		v.cancel()
	}
	return v.smokeFakeVM.StartReady(ctx)
}
func (v *smokeDiagnosticVM) Stop(ctx context.Context) error {
	// Remove logs on Stop as well: retained evidence must precede all teardown.
	return errors.Join(os.RemoveAll(v.root), v.smokeFakeVM.Stop(ctx))
}

func TestSmokeStartupFailurePreservesDiagnosticsBeforeCleanup(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		name := "valid"
		if unsafe {
			name = "unsafe-source"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "exact-vm-state")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			console := filepath.Join(root, "firecracker.log")
			metrics := filepath.Join(root, "metrics.json")
			if err := os.WriteFile(console, []byte("real failed startup console\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(metrics, []byte("{\"boot\":false}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if unsafe {
				if err := os.Chmod(console, 0644); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			startErr := errors.New("start failed deliberately")
			factory := &smokeDiagnosticFactory{
				smokeFakeFactory: &smokeFakeFactory{configure: func(vm *smokeFakeVM) { vm.startErr = startErr }},
				resources:        VMResourceIdentity{StateDir: root, LogPath: console, MetricsPath: metrics}, cancel: cancel,
			}
			network := &smokeFakeNetwork{}
			report, err := RunSmoke(ctx, factory, network, time.Second)
			if !errors.Is(err, startErr) {
				t.Fatalf("lost startup failure: %v", err)
			}
			if len(report.FailureDiagnostics) != 1 {
				t.Fatalf("missing diagnostic: %+v", report)
			}
			diagnostic := report.FailureDiagnostics[0]
			if diagnostic.VMID != "gru-member-1" || diagnostic.Console.Path != console || diagnostic.Metrics.Tail != "{\"boot\":false}\n" {
				t.Fatalf("wrong evidence: %+v", diagnostic)
			}
			if unsafe {
				if diagnostic.Console.Present || diagnostic.Console.Tail != "" || !strings.Contains(diagnostic.Console.Observation, "unsafe") {
					t.Fatalf("unsafe evidence accepted: %+v", diagnostic.Console)
				}
			} else if diagnostic.Console.Tail != "real failed startup console\n" {
				t.Fatalf("startup evidence lost: %+v", diagnostic.Console)
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("cleanup left state: %v", err)
			}
			if !network.cleaned || !factory.created[0].deleted || factory.created[0].stopCalls == 0 {
				t.Fatal("diagnostic failure prevented cleanup")
			}
			var output bytes.Buffer
			if err := WriteSmokeFailureDiagnostics(&output, report); err != nil || !strings.Contains(output.String(), `"failureDiagnostics"`) || !strings.Contains(output.String(), `"vmId":"gru-member-1"`) {
				t.Fatalf("CLI evidence missing: %s, %v", output.String(), err)
			}
		})
	}
}
