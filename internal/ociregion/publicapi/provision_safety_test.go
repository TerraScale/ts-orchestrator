package publicapi

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"
)

func TestLoadPlanMemberIdentityFollowsSlots(t *testing.T) {
	plan := strings.Replace(testPlan, `["gru-1-db-1"]`, `["gru-1-db-1","gru-1-db-2"]`, 1)
	want := testDesired(t, plan)
	var document map[string]any
	if err := json.Unmarshal([]byte(plan), &document); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(document["hosts"].([]any))
	got := testDesired(t, command.JSON(document))
	if !slices.Equal(got.TerraBase, want.TerraBase) || !slices.Equal(got.Auth, want.Auth) {
		t.Fatalf("reordered hosts changed identities: members=%v controllers=%v", got.TerraBase, got.Auth)
	}
	if got.TerraBase[0].Name != "gru-1-db-1" || got.TerraBase[0].Addr.String() != "10.251.0.21:9465" ||
		got.TerraBase[1].Name != "gru-1-db-2" || got.TerraBase[1].Addr.String() != "10.251.0.22:9465" {
		t.Fatal(got.TerraBase)
	}
	// A missing earlier slot must not renumber the remaining member.
	document["hosts"] = slices.DeleteFunc(document["hosts"].([]any), func(host any) bool {
		return host.(map[string]any)["slot"] == "member-a"
	})
	document["public_api"].(map[string]any)["terrabase_members"] = []string{"gru-1-db-2"}
	got = testDesired(t, command.JSON(document))
	if got.TerraBase[0].Name != "gru-1-db-2" || got.TerraBase[0].Addr.String() != "10.251.0.22:9465" {
		t.Fatal(got.TerraBase)
	}
}

func TestLoadPlanRejectsAmbiguousSlotsAndUnsupportedListeners(t *testing.T) {
	for name, edit := range map[string][2]string{
		"unsupported member":     {`"member-a"`, `"member-aa"`},
		"unsupported controller": {`"controller-a"`, `"controller-aa"`},
		"unknown host":           {`"member-a"`, `"other-a"`},
		"duplicate member":       {`"member-b"`, `"member-a"`},
		"duplicate controller":   {`"controller-b"`, `"controller-a"`},
		"duplicate address":      {`"10.251.0.22"`, `"10.251.0.21"`},
		"other listener":         {`"listener_port":443`, `"listener_port":80`},
		"missing listener":       {`"listener_port":443,`, ``},
		"null listener":          {`"listener_port":443`, `"listener_port":null`},
	} {
		t.Run(name, func(t *testing.T) {
			plan := strings.Replace(testPlan, edit[0], edit[1], 1)
			if plan == testPlan {
				t.Fatal("fixture edit did not apply")
			}
			if _, err := ParsePlan([]byte(plan)); err == nil {
				t.Fatal("accepted an ambiguous identity or unsupported listener")
			}
		})
	}
}

// reviewedEdge seeds the existing OCI fake with complete network readbacks,
// including the attachments and security rules that apply must verify.
func reviewedEdge(t *testing.T) (Desired, *fakeOCI, Provisioner, Cloudflare, string) {
	t.Helper()
	d := testDesired(t, testPlan)
	f := newFakeOCI(t)
	_, cloudflare := newFakeCloudflare(t)
	for kind, name := range map[string]string{"internet-gateway": d.Names.IGW, "route-table": d.Names.Routes,
		"security-list": d.Names.Security, "subnet": d.Names.Subnet, "nsg": d.Names.NSG} {
		f.network[kind] = map[string]any{"id": kind, "display-name": name, "lifecycle-state": "AVAILABLE",
			"compartment-id": d.Network, "vcn-id": d.VCN}
	}
	f.network["internet-gateway"]["is-enabled"] = true
	f.network["route-table"]["route-rules"] = []any{map[string]any{"destination": "0.0.0.0/0",
		"destination-type": "CIDR_BLOCK", "network-entity-id": "internet-gateway"}}
	f.network["security-list"]["ingress-security-rules"] = []any{}
	f.network["security-list"]["egress-security-rules"] = []any{reviewedEgress(9465), reviewedEgress(8080)}
	subnet := f.network["subnet"]
	subnet["cidr-block"], subnet["dns-label"] = "10.251.0.128/26", "public"
	subnet["prohibit-public-ip-on-vnic"], subnet["prohibit-internet-ingress"] = false, false
	subnet["route-table-id"], subnet["security-list-ids"] = "route-table", []any{"security-list"}
	members := testCA(t)
	args := []string{"lb", "load-balancer", "create", "--compartment-id", d.Network, "--display-name", d.Names.LB,
		"--shape-name", "flexible", "--subnet-ids", `["subnet"]`, "--is-private", "false", "--network-security-group-ids", `["nsg"]`}
	for flag, value := range d.loadBalancer("ORIGIN", "KEY", members, "") {
		args = append(args, "--"+flag, value)
	}
	if _, err := f.Call(t.Context(), args...); err != nil {
		t.Fatal(err)
	}
	p := Provisioner{Client: f, PollAttempts: 2, Pause: func(context.Context, time.Duration) error { return nil }}
	if _, err := p.Provision(t.Context(), d, cloudflare, members, ""); err != nil {
		t.Fatalf("reviewed fixture was rejected: %v", err)
	}
	f.calls = nil
	return d, f, p, cloudflare, members
}

func reviewedEgress(port int) map[string]any {
	return map[string]any{"protocol": "6", "destination": "10.251.0.0/25", "destination-type": "CIDR_BLOCK", "is-stateless": false,
		"tcp-options": map[string]any{"destination-port-range": map[string]any{"min": port, "max": port}}}
}

func TestProvisionRejectsNetworkSecurityDriftBeforeMutation(t *testing.T) {
	for name, edit := range map[string]func(*fakeOCI){
		"load balancer without NSG": func(f *fakeOCI) { f.balancer["network-security-group-ids"] = []any{} },
		"load balancer other NSG":   func(f *fakeOCI) { f.balancer["network-security-group-ids"] = []any{"0000000000V4MRM46HP1SNGDYW"} },
		"load balancer extra NSG": func(f *fakeOCI) {
			f.balancer["network-security-group-ids"] = []any{"nsg", "0000000000V4MRM46HP1SNGDYW"}
		},
		"load balancer other subnet":      func(f *fakeOCI) { f.balancer["subnet-ids"] = []any{"0000000000V4MRM46HP1SNGDYW"} },
		"load balancer extra subnet":      func(f *fakeOCI) { f.balancer["subnet-ids"] = []any{"subnet", "0000000000V4MRM46HP1SNGDYW"} },
		"load balancer other compartment": func(f *fakeOCI) { f.balancer["compartment-id"] = "0000000000V4MRM46HP1SNGDYW" },
		"subnet extra security list":      func(f *fakeOCI) { f.network["subnet"]["security-list-ids"] = []any{"security-list", "default"} },
		"subnet other security list":      func(f *fakeOCI) { f.network["subnet"]["security-list-ids"] = []any{"default"} },
		"subnet other route table":        func(f *fakeOCI) { f.network["subnet"]["route-table-id"] = "0000000000V4MRM46HP1SNGDYW" },
		"subnet other CIDR":               func(f *fakeOCI) { f.network["subnet"]["cidr-block"] = "10.251.0.0/25" },
		"subnet private":                  func(f *fakeOCI) { f.network["subnet"]["prohibit-public-ip-on-vnic"] = true },
		"subnet prohibits ingress":        func(f *fakeOCI) { f.network["subnet"]["prohibit-internet-ingress"] = true },
		"subnet other VCN":                func(f *fakeOCI) { f.network["subnet"]["vcn-id"] = "0000000000V4MRM46HP1SNGDYW" },
		"security list other VCN":         func(f *fakeOCI) { f.network["security-list"]["vcn-id"] = "0000000000V4MRM46HP1SNGDYW" },
		"security list public ingress": func(f *fakeOCI) {
			f.network["security-list"]["ingress-security-rules"] = []any{map[string]any{"source": "0.0.0.0/0", "protocol": "all"}}
		},
		"security list unknown ingress": func(f *fakeOCI) { delete(f.network["security-list"], "ingress-security-rules") },
		"security list extra egress": func(f *fakeOCI) {
			f.network["security-list"]["egress-security-rules"] = append(f.network["security-list"]["egress-security-rules"].([]any),
				map[string]any{"destination": "0.0.0.0/0", "protocol": "all"})
		},
		"security list missing egress": func(f *fakeOCI) { f.network["security-list"]["egress-security-rules"] = []any{reviewedEgress(9465)} },
		"security list duplicate egress": func(f *fakeOCI) {
			f.network["security-list"]["egress-security-rules"] = []any{reviewedEgress(9465), reviewedEgress(9465)}
		},
		"security list stateless": func(f *fakeOCI) {
			f.network["security-list"]["egress-security-rules"].([]any)[0].(map[string]any)["is-stateless"] = true
		},
		"security list public egress": func(f *fakeOCI) {
			f.network["security-list"]["egress-security-rules"].([]any)[0].(map[string]any)["destination"] = "0.0.0.0/0"
		},
		"security list broad port range": func(f *fakeOCI) {
			field(f.network["security-list"], "egress-security-rules").([]any)[0].(map[string]any)["tcp-options"].(map[string]any)["destination-port-range"] = map[string]any{"min": 1, "max": 65535}
		},
		"security list source port restriction": func(f *fakeOCI) {
			f.network["security-list"]["egress-security-rules"].([]any)[0].(map[string]any)["tcp-options"].(map[string]any)["source-port-range"] = map[string]any{"min": 443, "max": 443}
		},
		"disabled gateway": func(f *fakeOCI) { f.network["internet-gateway"]["is-enabled"] = false },
		"other gateway route": func(f *fakeOCI) {
			f.network["route-table"]["route-rules"].([]any)[0].(map[string]any)["network-entity-id"] = "0000000000V4MRM46HP1SNGDYW"
		},
	} {
		t.Run(name, func(t *testing.T) {
			d, f, p, cloudflare, members := reviewedEdge(t)
			edit(f)
			// Valid reconciliation work must also stay unapplied on unsafe networking.
			d.MaxMbps = 200
			f.rules["nsg"] = nil
			if _, err := p.Provision(t.Context(), d, cloudflare, members, ""); err == nil || !strings.Contains(err.Error(), "reviewed network configuration") {
				t.Fatalf("accepted network drift: %v", err)
			}
			if got := f.mutations(); len(got) != 0 {
				t.Fatalf("mutated resources before refusing network drift: %v", got)
			}
		})
	}
}

func TestProvisionAcceptsReviewedNetworkWithoutChanges(t *testing.T) {
	d, f, p, cloudflare, members := reviewedEdge(t)
	// Security-list ordering carries no meaning.
	slices.Reverse(f.network["security-list"]["egress-security-rules"].([]any))
	result, err := p.Provision(t.Context(), d, cloudflare, members, "")
	if err != nil || result["public_subnet"] != "subnet" || result["load_balancer_nsg"] != "nsg" || len(f.mutations()) != 0 {
		t.Fatalf("reviewed edge changed or failed: result=%v mutations=%v err=%v", result, f.mutations(), err)
	}
}

type attachmentDriftOCI struct {
	*fakeOCI
	reads, driftAt int
}

func (f *attachmentDriftOCI) Call(ctx context.Context, args ...string) (map[string]any, error) {
	result, err := f.fakeOCI.Call(ctx, args...)
	if len(args) >= 3 && slices.Equal(args[:3], []string{"lb", "load-balancer", "list"}) {
		f.reads++
		if f.reads == f.driftAt {
			f.balancer["network-security-group-ids"] = []any{"nsg", "unreviewed"}
		}
	}
	return result, err
}

func TestProvisionRechecksAttachmentsAfterActivationAndConvergence(t *testing.T) {
	for _, stage := range []string{"creation", "activation", "convergence"} {
		t.Run(stage, func(t *testing.T) {
			d, f, p, cloudflare, members := reviewedEdge(t)
			client := &attachmentDriftOCI{fakeOCI: f, driftAt: 2}
			var mutations []string
			if stage == "creation" {
				f.balancer = nil
				steps, err := p.certSteps(t.Context(), d, cloudflare)
				if err != nil {
					t.Fatal(err)
				}
				if err := run(t.Context(), steps, true, io.Discard); err != nil {
					t.Fatal(err)
				}
				f.calls = nil
				mutations = []string{"lb load-balancer create"}
			}
			if stage == "convergence" {
				d.MaxMbps, client.driftAt = 200, 4
				mutations = []string{"lb load-balancer update-shape"}
			}
			p.Client = client
			if _, err := p.Provision(t.Context(), d, cloudflare, members, ""); err == nil || !strings.Contains(err.Error(), "NSG attachments differ") {
				t.Fatalf("reported success after %s attachment drift: %v", stage, err)
			}
			if !slices.Equal(f.mutations(), mutations) {
				t.Fatalf("unexpected mutations after attachment drift: %v", f.mutations())
			}
		})
	}
}

func TestSyncRulesKeepsFirstDesiredIDAndRemovesDuplicates(t *testing.T) {
	for _, remove := range []bool{true, false} {
		t.Run(map[bool]string{true: "exact", false: "additive"}[remove], func(t *testing.T) {
			f := newFakeOCI(t)
			p := Provisioner{Client: f}
			row := func(id, source string) map[string]any {
				r := (Rule{source, 443}).json("source")
				r["direction"], r["id"] = "INGRESS", id
				return f.render(r)
			}
			f.rules["nsg"] = []map[string]any{row("first", "173.245.48.0/20"), row("duplicate-2", "173.245.48.0/20"),
				row("duplicate-3", "173.245.48.0/20"), row("stale", "0.0.0.0/0")}
			want := OriginRules([]string{"173.245.48.0/20"})
			steps, err := p.syncRules(t.Context(), "nsg", "Cloudflare", want, remove)
			if err != nil {
				t.Fatal(err)
			}
			before := command.JSON(f.rules["nsg"])
			var out bytes.Buffer
			if err := run(t.Context(), steps, false, &out); err != nil || len(f.mutations()) != 0 || command.JSON(f.rules["nsg"]) != before {
				t.Fatalf("dry run changed rules: %v", err)
			}
			if err := run(t.Context(), steps, true, io.Discard); err != nil {
				t.Fatal(err)
			}
			expected := []string{"network nsg rules add"}
			if remove {
				expected = append(expected, "network nsg rules remove", "network nsg rules remove", "network nsg rules remove")
				if err := CheckOriginRules(f.rules["nsg"], []string{"173.245.48.0/20"}); err != nil {
					t.Fatal(err)
				}
			}
			if !slices.Equal(f.mutations(), expected) || f.rules["nsg"][0]["id"] != "first" {
				t.Fatalf("mutations=%v rules=%v", f.mutations(), f.rules["nsg"])
			}
			if !remove && len(f.rules["nsg"]) != 5 {
				t.Fatalf("additive sync removed existing rules: %v", f.rules["nsg"])
			}
			if again, err := p.syncRules(t.Context(), "nsg", "Cloudflare", want, remove); err != nil || len(again) != 0 {
				t.Fatalf("rerun planned %d changes: %v", len(again), err)
			}
		})
	}
}
