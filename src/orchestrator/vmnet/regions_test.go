package vmnet

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fourthRegion(code RegionCode) RegionSpec {
	return RegionSpec{Code: code, Guests: []GuestSpec{{ID: strings.ToLower(string(code)) + "-member-1"}, {ID: strings.ToLower(string(code)) + "-member-2"}}}
}

func TestDeclaredFourthRegionUsesIndependentSlotAndCleanup(t *testing.T) {
	config := qualifiedConfig(t)
	config.Regions = append(config.Regions, fourthRegion("IAD"))
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := plan.Journal.Validate(); err != nil {
		t.Fatal(err)
	}
	fourth := plan.Regions[3]
	if fourth.Code != "IAD" || fourth.CIDR != "10.77.3.0/24" || fourth.Gateway != "10.77.3.1" || fourth.Guests[0].Address != "10.77.3.10" || fourth.Guests[0].MAC != "02:fc:77:04:01:01" {
		t.Fatalf("fourth Region allocation: %+v", fourth)
	}
	prefix, run, region, ok := ownedNamespace(fourth.Namespace)
	if !ok || prefix != plan.Prefix || run != plan.RunID || region != "IAD" {
		t.Fatal("fourth namespace is not recoverably owned")
	}
	if len(plan.Cleanup.Commands) != 4 || plan.Cleanup.Commands[0].Args[2] != fourth.Namespace {
		t.Fatal("fourth namespace absent from reverse cleanup")
	}
	config.Regions = append(config.Regions, fourthRegion("AMS"))
	expanded, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fourth, expanded.Regions[3]) || expanded.Regions[4].CIDR != "10.77.4.0/24" {
		t.Fatal("appending a Region moved an existing allocation")
	}
	addressAssignments := func(plan NetworkPlan) map[string]string {
		result := make(map[string]string)
		for _, command := range plan.Commands {
			args := command.Args
			if len(args) == 7 && args[0] == "-n" && args[2] == "addr" && args[3] == "add" && args[5] == "dev" {
				result[args[1]+"/"+args[6]] = args[4]
			}
		}
		return result
	}
	expandedAddresses := addressAssignments(expanded)
	for device, address := range addressAssignments(plan) {
		if expandedAddresses[device] != address {
			t.Fatalf("appending a Region renumbered %s: %s -> %s", device, address, expandedAddresses[device])
		}
	}
	runner, writer := &fakeRunner{failAt: -1}, &fakeJournalWriter{}
	if err := expanded.ApplyWithJournal(context.Background(), runner, writer); err != nil {
		t.Fatal(err)
	}
	if err := expanded.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestDeclaredRegionsRejectCollisionsAndBounds(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Config)
	}{
		{"duplicate code", func(c *Config) { c.Regions = append(c.Regions, fourthRegion(GRU)) }},
		{"lowercase", func(c *Config) { c.Regions = append(c.Regions, fourthRegion("iad")) }},
		{"unsafe code", func(c *Config) { c.Regions = append(c.Regions, fourthRegion("I/D")) }},
		{"additional single guest", func(c *Config) { r := fourthRegion("IAD"); r.Guests = r.Guests[:1]; c.Regions = append(c.Regions, r) }},
		{"reserved baseline subnet", func(c *Config) { r := fourthRegion("IAD"); r.CIDR = StableCIDR(FRA); c.Regions = []RegionSpec{r} }},
		{"transit subnet", func(c *Config) { r := fourthRegion("IAD"); r.CIDR = "10.78.254.0/24"; c.Regions = append(c.Regions, r) }},
		{"duplicate guest identity", func(c *Config) {
			r := fourthRegion("IAD")
			r.Guests[0].ID = c.Regions[0].Guests[0].ID
			c.Regions = append(c.Regions, r)
		}},
		{"too many Regions", func(c *Config) {
			for i := 0; i < 18; i++ {
				c.Regions = append(c.Regions, fourthRegion(RegionCode("A"+string(rune('A'+i))+"A")))
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := qualifiedConfig(t)
			test.edit(&config)
			if _, err := Plan(config); err == nil {
				t.Fatal("invalid declared topology accepted")
			}
		})
	}
}

func TestDeclaredFourthRegionRealNamespace(t *testing.T) {
	if os.Getenv("TS_VMNET_FOURTH_NAMESPACE_TEST") != "1" {
		t.Skip("set TS_VMNET_FOURTH_NAMESPACE_TEST=1 with qualification host privileges")
	}
	tools, err := DiscoverHostTools()
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	digest := sha256.Sum256([]byte(t.TempDir()))
	config.RunID = fmt.Sprintf("%x", digest[:16])
	config.Tools = tools
	config.Regions = append(config.Regions, fourthRegion("IAD"))
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewHostRunner(tools)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := plan.Cleanup.Run(cleanupCtx, runner); err != nil {
			t.Errorf("cleanup real fourth Region fixture: %v", err)
		}
	}()
	if err := plan.ApplyWithJournal(ctx, runner, &fakeJournalWriter{}); err != nil {
		t.Fatal(err)
	}
	for _, region := range plan.Regions {
		if _, err := os.Stat(region.NamespacePath); err != nil {
			t.Fatalf("declared namespace missing: %s: %v", region.Code, err)
		}
	}
	ping, err := exec.LookPath("ping")
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(ctx, tools.IP, "netns", "exec", plan.Regions[3].Namespace, ping, "-n", "-c", "1", "-W", "2", plan.Regions[0].Gateway).CombinedOutput()
	if err != nil {
		t.Fatalf("fourth-to-GRU namespace packet failed: %v %s", err, output)
	}
}
