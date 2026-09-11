package vmqualbootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

func grantManifest(t *testing.T) hostmanifest.HostManifest {
	t.Helper()
	var components []hostmanifest.ComponentSpec
	for _, name := range []string{"orchestrator", "terrabase"} {
		component, err := hostmanifest.NewComponentSpec(hostmanifest.ComponentSpec{Name: name, Version: "1.0.0", ArtifactURL: "https://releases.terrascale.tech/" + name, SignatureURL: "https://releases.terrascale.tech/" + name + ".sig", Sha256: strings.Repeat("a", 64), User: "terrascale-" + name, DataVolume: "/var/lib/terrascale/" + name, CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100})
		if err != nil {
			t.Fatal(err)
		}
		components = append(components, component)
	}
	return hostmanifest.HostManifest{Components: components}
}
func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })
	return issuer
}

type refuseRuntime struct{}

func (refuseRuntime) Authorize(context.Context, string, []byte) (nodeauthority.CommandAuthorization, error) {
	return nodeauthority.CommandAuthorization{}, errors.New("no regional lease")
}

func TestIssuerPinsStableHostManifestAndFiniteSteps(t *testing.T) {
	issuer := testIssuer(t)
	manifest := grantManifest(t)
	material, err := issuer.Grant("gru-1", manifest)
	if err != nil {
		t.Fatal(err)
	}
	saved := append([]byte(nil), material.SignedGrant...)
	material.SignedGrant[0] ^= 1
	material, err = issuer.Grant("gru-1", manifest)
	if err != nil || !bytes.Equal(material.SignedGrant, saved) {
		t.Fatal("grant changed or retained caller mutation")
	}
	grant, err := hostagent.VerifyBootstrapGrant("gru-1", material.PublicKeyPEM, material.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	if grant.ExpiresAt.Sub(grant.IssuedAt).Hours() > 24 {
		t.Fatal("unbounded initial grant")
	}
	if _, err := hostagent.VerifyBootstrapGrant("gru-2", material.PublicKeyPEM, material.SignedGrant); err == nil {
		t.Fatal("foreign host accepted")
	}
	changed := manifest
	changed.Components = append([]hostmanifest.ComponentSpec(nil), manifest.Components...)
	changed.Components[0].Version = "2.0.0"
	if _, err := issuer.Grant("gru-1", changed); err == nil {
		t.Fatal("seeded initial manifest changed")
	}
	commands, err := hostagent.BootstrapCommands(grant)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := hostagent.NewBootstrapAuthority(refuseRuntime{}, "gru-1", material.PublicKeyPEM, material.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range commands {
		wire, err := issuer.Sign("gru-1", step.Subject, step.Command)
		if err != nil {
			t.Fatal(err)
		}
		admitted, err := authority.Authorize(context.Background(), step.Subject, wire)
		if err != nil || admitted.Epoch != 0 || admitted.LeaseID != "" || admitted.BootstrapGrantSHA256 == "" || !bytes.Equal(admitted.Command, step.Command) {
			t.Fatalf("real grant verification failed: %v", err)
		}
	}
	if _, err := issuer.Sign("gru-2", commands[0].Subject, commands[0].Command); err == nil {
		t.Fatal("unsigned host entered grant path")
	}
	if _, err := issuer.Sign("gru-1", commands[0].Subject, json.RawMessage(`{"commandId":"ordinary","draining":true}`)); err == nil {
		t.Fatal("ordinary mutation entered grant path")
	}
	_ = issuer.Close()
	if _, err := issuer.Sign("gru-1", commands[0].Subject, commands[0].Command); err == nil {
		t.Fatal("closed issuer retained signing authority")
	}
}

func TestActivationAuthenticatesFiniteGrantAndResumesActualVersions(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "partial"}[partial], func(t *testing.T) {
			issuer := testIssuer(t)
			manifest := grantManifest(t)
			host := "gru-1"
			material, err := issuer.Grant(host, manifest)
			if err != nil {
				t.Fatal(err)
			}
			authority, err := hostagent.NewBootstrapAuthority(refuseRuntime{}, host, material.PublicKeyPEM, material.SignedGrant)
			if err != nil {
				t.Fatal(err)
			}
			digest, _ := hostmanifest.HostManifestSha256(manifest)
			report := hostagent.NodeStatusReport{NodeId: host, State: hostagent.NodeStateServing, Facts: hostagent.HostFacts{ManifestSha256: digest, ClockMeasured: true}}
			for _, spec := range manifest.Components {
				report.Facts.Components = append(report.Facts.Components, hostagent.ComponentFact{Name: spec.Name, Desired: spec.Version, Installed: true})
			}
			effects := map[string]int{}
			attempts := 0
			failOnce := partial
			status := func(context.Context, string, string) (hostagent.NodeStatusReport, error) { return report, nil }
			send := func(ctx context.Context, node, subject string, command json.RawMessage, reply any) error {
				wire, err := issuer.Sign(node, subject, command)
				if err != nil {
					return err
				}
				admitted, err := authority.Authorize(ctx, subject, wire)
				if err != nil {
					return err
				}
				if admitted.Epoch != 0 || admitted.LeaseID != "" {
					t.Fatal("bootstrap fabricated runtime authority")
				}
				attempts++
				switch target := reply.(type) {
				case *hostagent.DrainReceipt:
					var c hostagent.DrainCommand
					if err := json.Unmarshal(admitted.Command, &c); err != nil {
						return err
					}
					report.Quiesced = c.Drain
					report.State = hostagent.NodeStateServing
					if c.Drain {
						report.State = hostagent.NodeStateQuiesced
					}
					for index := range report.Facts.Components {
						report.Facts.Components[index].UnitActive = !c.Drain && report.Facts.Components[index].Version != ""
					}
					*target = hostagent.DrainReceipt{CommandId: c.CommandId, NodeId: host, Draining: c.Drain, Quiesced: c.Drain}
				case *hostagent.DeployReceipt:
					var c hostagent.DeployCommand
					if err := json.Unmarshal(admitted.Command, &c); err != nil {
						return err
					}
					if c.Component == "terrabase" && failOnce {
						failOnce = false
						return errors.New("interrupted before deployment")
					}
					effects[c.Component]++
					for index := range report.Facts.Components {
						if report.Facts.Components[index].Name == c.Component {
							report.Facts.Components[index].Version = c.Version
							report.Facts.Components[index].UnitActive = true
						}
					}
					report.Quiesced = false
					report.State = hostagent.NodeStateDraining
					*target = hostagent.DeployReceipt{CommandId: c.CommandId, NodeId: host, Accepted: true, Current: c.Version}
				default:
					t.Fatal("unexpected initial command")
				}
				return nil
			}
			if partial {
				if err := Activate(context.Background(), host, material, status, send); err == nil {
					t.Fatal("interruption ignored")
				}
			}
			if err := Activate(context.Background(), host, material, status, send); err != nil {
				t.Fatal(err)
			}
			if effects["orchestrator"] != 1 || effects["terrabase"] != 1 {
				t.Fatalf("initial effects repeated: %v", effects)
			}
			completedAttempts := attempts
			if err := Activate(context.Background(), host, material, status, send); err != nil || attempts != completedAttempts {
				t.Fatal("completed activation issued more bootstrap mutations")
			}
			for index, fact := range report.Facts.Components {
				report.Facts.Components[index].UnitActive = false
				if err := Activate(context.Background(), host, material, status, send); err == nil {
					t.Fatalf("inactive %s process qualified as serving", fact.Name)
				}
				report.Facts.Components[index].UnitActive = true
			}
		})
	}
}
