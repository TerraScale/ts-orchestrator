package publicapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"
)

type fakeOCI struct {
	calls [][]string
	call  func([]string) (map[string]any, error)
}

func (f *fakeOCI) Call(_ context.Context, args ...string) (map[string]any, error) {
	f.calls = append(f.calls, slices.Clone(args))
	return f.call(args)
}
func (f *fakeOCI) Head(context.Context, ...string) error { return errors.New("unexpected head") }
func data(v any) map[string]any                          { return map[string]any{"data": v} }

func TestProvisionCreatesTLSOnlyPublicIngress(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "resume"}[existing], func(t *testing.T) {
			plan := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(plan, []byte(`{"resource_ids":{"network_compartment":"network","vcn":"vcn"},"subnet_cidr":"10.251.0.0/26"}`), 0644); err != nil {
				t.Fatal(err)
			}
			nlbCreated := existing
			f := &fakeOCI{}
			f.call = func(args []string) (map[string]any, error) {
				kind, action := args[1], args[2]
				if args[0] == "network" && kind == "nsg" {
					if action != "rules" {
						t.Fatal(args)
					}
					if args[3] == "list" {
						return data([]any{}), nil
					}
					if args[3] != "add" {
						t.Fatal(args)
					}
					ruleJSON := args[len(args)-1]
					if !strings.Contains(ruleJSON, `"source":"10.251.0.128/26"`) || !strings.Contains(ruleJSON, `"protocol":"6"`) || !strings.Contains(ruleJSON, `"min":9465`) {
						t.Fatal(ruleJSON)
					}
					return map[string]any{}, nil
				}
				if args[0] == "network" {
					r := map[string]any{"id": kind, "display-name": Prefix, "lifecycle-state": "AVAILABLE"}
					if action == "list" {
						if existing {
							return data([]any{r}), nil
						}
						return data([]any{}), nil
					}
					if action != "create" {
						t.Fatal(args)
					}
					if kind == "security-list" {
						ingress := args[slices.Index(args, "--ingress-security-rules")+1]
						egress := args[slices.Index(args, "--egress-security-rules")+1]
						if !strings.Contains(ingress, `"min":443`) || !strings.Contains(ingress, `"max":443`) || !strings.Contains(egress, `"destination":"10.251.0.0/26"`) || !strings.Contains(egress, `"min":9465`) {
							t.Fatalf("ingress=%s egress=%s", ingress, egress)
						}
					}
					return data(r), nil
				}
				if args[0] != "nlb" {
					t.Fatal(args)
				}
				r := map[string]any{"id": "nlb", "display-name": Prefix, "lifecycle-state": "ACTIVE", "ip-addresses": []any{map[string]any{"is-public": true, "ip-address": "192.0.2.5"}}}
				switch action {
				case "list":
					if nlbCreated {
						return data(map[string]any{"items": []any{r}}), nil
					}
					return data(map[string]any{"items": []any{}}), nil
				case "get":
					return data(r), nil
				case "create":
					nlbCreated = true
					backends := args[slices.Index(args, "--backend-sets")+1]
					listeners := args[slices.Index(args, "--listeners")+1]
					if !strings.Contains(backends, `"ipAddress":"10.251.0.21"`) || !strings.Contains(backends, `"ipAddress":"10.251.0.22"`) || !strings.Contains(listeners, `"port":443`) || !strings.Contains(listeners, `"protocol":"TCP"`) {
						t.Fatalf("backends=%s listeners=%s", backends, listeners)
					}
					return data(r), nil
				default:
					t.Fatal(args)
					return nil, nil
				}
			}
			r, err := (Provisioner{Client: f}).Provision(t.Context(), Options{Plan: plan, Members: "10.251.0.21,10.251.0.22", ClientPort: 9465, WorkloadNSG: "workload", SubnetCIDR: "10.251.0.128/26"})
			if err != nil {
				t.Fatal(err)
			}
			if r["public_ip"] != "192.0.2.5" || r["port"] != 443 || r["subnet"] != "subnet" {
				t.Fatal(r)
			}
			want := []string{"network internet-gateway list"}
			if !existing {
				want = append(want, "network internet-gateway create")
			}
			for _, kind := range []string{"route-table", "security-list", "subnet"} {
				want = append(want, "network "+kind+" list")
				if !existing {
					want = append(want, "network "+kind+" create")
				}
			}
			want = append(want, "network nsg rules list", "network nsg rules add", "nlb network-load-balancer list")
			if !existing {
				want = append(want, "nlb network-load-balancer create", "nlb network-load-balancer list")
			}
			want = append(want, "nlb network-load-balancer get")
			got := []string{}
			for _, args := range f.calls {
				n := 3
				if args[1] == "nsg" {
					n = 4
				}
				got = append(got, strings.Join(args[:n], " "))
			}
			if !slices.Equal(want, got) {
				t.Fatalf("calls=%v want=%v", got, want)
			}
		})
	}
}

func TestNamedRejectsAmbiguityAndIgnoresDeleted(t *testing.T) {
	rows := []map[string]any{{"display-name": Prefix, "lifecycle-state": "DELETED"}, {"display-name": Prefix, "lifecycle-state": "AVAILABLE", "id": "one"}}
	r, err := Named(rows, Prefix)
	if err != nil || r["id"] != "one" {
		t.Fatalf("resource=%v error=%v", r, err)
	}
	rows = append(rows, map[string]any{"display-name": Prefix, "lifecycle-state": "CREATING"})
	if _, err := Named(rows, Prefix); err == nil {
		t.Fatal("accepted duplicate live resource")
	}
}

func TestInvalidInputAndCancellationStopProviderEffects(t *testing.T) {
	f := &fakeOCI{call: func([]string) (map[string]any, error) { t.Fatal("provider effect before admission"); return nil, nil }}
	if _, err := (Provisioner{Client: f}).Provision(t.Context(), Options{Plan: "unused", Members: "not-an-IP", WorkloadNSG: "nsg", SubnetCIDR: "10.0.0.0/24", ClientPort: 9465}); err == nil {
		t.Fatal("accepted malformed IP")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (Provisioner{Client: f}).Provision(ctx, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatal(f.calls)
	}
}

func TestWaitStateStopsOnTerminalFailureOrCancellation(t *testing.T) {
	for _, state := range []string{"FAILED", "CREATING"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f := &fakeOCI{call: func([]string) (map[string]any, error) { return data(map[string]any{"lifecycle-state": state}), nil }}
			_, err := (Provisioner{Client: f, Pause: func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }}).WaitState(ctx, []string{"nlb", "network-load-balancer", "get"}, "ACTIVE")
			if err == nil {
				t.Fatal("accepted unavailable NLB")
			}
			if state == "CREATING" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if len(f.calls) != 1 {
				t.Fatal(f.calls)
			}
		})
	}
}

var _ command.Client = (*fakeOCI)(nil)
