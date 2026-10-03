package manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPodmanManagerSyncAndPrune runs a disposable NetBird 0.80 manager and
// real client peers in rootless Podman. It seeds the legacy production shape,
// syncs twice as a dedicated admin service user (the second sync must change
// nothing), checks renames kept IDs and memberships, one-way ping and cell DNS,
// and that prune deletes a replaced revision and renames the live peer.
//
// Opt in with TS_NETBIRD_PODMAN=1 (make netbird-podman-test). Nested Podman
// inside a CI job container also needs TS_NESTED_PODMAN=1.
func TestPodmanManagerSyncAndPrune(t *testing.T) {
	if os.Getenv("TS_NETBIRD_PODMAN") != "1" {
		t.Skip("set TS_NETBIRD_PODMAN=1 to run the NetBird manager Podman integration test")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not installed; the NetBird manager integration test needs it")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	stack := newPodmanStack(ctx, t)
	owner := stack.startServer()

	// The PAT belongs to a dedicated service user with the admin role, the
	// least-privileged built-in role able to do everything sync and prune do.
	admin := stack.serviceUserToken(owner, "ts-orchestrator", "admin")
	networkAdmin := stack.serviceUserToken(owner, "network-admin-probe", "network_admin")

	seeded := stack.seedLegacy(owner)
	d := GRU()
	// Slot addresses become this test network's fixed container IPs, inside
	// the test cell subnet as Validate requires.
	d.Network.Resource.Address = stack.cellSubnet()
	for i := range d.Slots {
		d.Slots[i].IP = stack.slotIP(d.Slots[i].IP)
	}
	api, err := NewAPI(stack.base, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()

	before := stack.inventoryJSON(api)
	plan, err := Sync(ctx, api, d, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) == 0 || stack.inventoryJSON(api) != before {
		t.Fatalf("dry run planned %d changes or mutated the manager", len(plan.Changes))
	}
	applied, err := Sync(ctx, api, d, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first sync applied %d changes", len(applied.Changes))
	if len(applied.Warnings) != 0 {
		t.Fatalf("sync warnings: %v", applied.Warnings)
	}
	second, err := Sync(ctx, api, d, true)
	if err != nil || len(second.Changes) != 0 {
		t.Fatalf("second sync was not a no-op: %v %v", second.Changes, err)
	}
	stack.verifySynced(owner, d, seeded)
	stack.verifyTraffic(owner, d, seeded)

	// A network admin may not rename peers: prune needs the admin role.
	if status := stack.status(networkAdmin, "PUT", "/peers/"+seeded.peers["ts-ops"],
		map[string]any{"name": "ts-ops", "ssh_enabled": false, "login_expiration_enabled": false,
			"inactivity_expiration_enabled": false}); status != http.StatusForbidden {
		t.Fatalf("network_admin peer update returned HTTP %d, want 403", status)
	}

	// Replace member-1: the old revision goes offline, a new identity at the
	// same slot IP registers under its OS hostname.
	slot := d.Slots[3]
	stack.removeContainer("gru-member-1")
	stale := seeded.peers["gru-member-1"]
	stack.wait("replaced revision to disconnect", 90*time.Second, func() bool {
		var peer apiPeer
		return stack.call(owner, "GET", "/peers/"+stale, nil, &peer) == nil && !peer.Connected
	})
	stack.client("ip-replacement", seeded.serverKey, slot.IP, false)
	live := stack.peerID(owner, "ip-replacement")

	pruned, err := Prune(ctx, api, d, PruneOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prune applied %v", pruned.Changes)
	var peers []apiPeer
	if err := stack.call(owner, "GET", "/peers", nil, &peers); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(peers, func(p apiPeer) bool { return p.ID == stale }) {
		t.Fatal("prune kept the replaced revision")
	}
	index := slices.IndexFunc(peers, func(p apiPeer) bool { return p.ID == live })
	if index < 0 || peers[index].Name != d.PeerName(slot) || !cleanLabel(peers[index], d.PeerName(slot)) {
		t.Fatalf("live peer was not renamed to its slot name: %+v", peers[index])
	}
	if !slices.ContainsFunc(peers, func(p apiPeer) bool { return p.ID == seeded.peers["operator-1"] }) ||
		!slices.ContainsFunc(peers, func(p apiPeer) bool { return p.ID == seeded.peers["gru-controller-a"] }) {
		t.Fatal("prune deleted a peer it must keep")
	}
	again, err := Prune(ctx, api, d, PruneOptions{}, true)
	if err != nil || len(again.Changes) != 0 {
		t.Fatalf("second prune was not a no-op: %v %v", again.Changes, err)
	}
}

const podmanServerImage = "docker.io/netbirdio/netbird-server:0.80.0"
const podmanClientImage = "docker.io/netbirdio/netbird:0.80.0"

const podmanServerConfig = `server:
  listenAddress: ":80"
  exposedAddress: "http://nbserver:80"
  stunPorts:
    - 3478
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"
  authSecret: "%s"
  dataDir: "/var/lib/netbird"
  auth:
    issuer: "http://nbserver:80/oauth2"
    signKeyRefreshEnabled: true
    sessionCookieEncryptionKey: "%s"
    dashboardRedirectURIs:
      - "http://127.0.0.1/nb-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"
  store:
    engine: "sqlite"
    encryptionKey: "%s"
`

type podmanStack struct {
	ctx        context.Context
	t          *testing.T
	tag        string
	network    string
	volume     string
	subnet     string // first three octets
	base       string
	containers []string
	http       *http.Client
}

func newPodmanStack(ctx context.Context, t *testing.T) *podmanStack {
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	octet, _ := rand.Int(rand.Reader, big.NewInt(200))
	s := &podmanStack{ctx: ctx, t: t, tag: "tsorch-nb-" + hex.EncodeToString(suffix),
		subnet: fmt.Sprintf("10.252.%d", 20+octet.Int64()), http: &http.Client{Timeout: 30 * time.Second}}
	s.network, s.volume = s.tag+"-net", s.tag+"-data"
	t.Cleanup(s.cleanup)
	return s
}

// cellSubnet is the test stand-in for the GRU cell subnet: the upper half
// of the test network, so it never covers the server at .2.
func (s *podmanStack) cellSubnet() string { return s.subnet + ".128/25" }

// slotIP maps a production slot address into cellSubnet, offsetting the last
// octet by 128.
func (s *podmanStack) slotIP(production string) string {
	octet, err := strconv.Atoi(production[strings.LastIndex(production, ".")+1:])
	if err != nil || octet <= 0 || octet >= 127 {
		s.t.Fatalf("slot address %s cannot be mapped into the test cell subnet", production)
	}
	return fmt.Sprintf("%s.%d", s.subnet, 128+octet)
}

func (s *podmanStack) podman(args ...string) string {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, "podman", args...)
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		s.t.Fatalf("podman %s: %v\n%s", strings.Join(args[:min(3, len(args))], " "), err, tail(stderr.String()))
	}
	return strings.TrimSpace(stdout.String())
}

func tail(text string) string {
	return text[max(0, len(text)-2000):]
}

func (s *podmanStack) run(args ...string) {
	s.t.Helper()
	run := []string{"run"}
	if os.Getenv("TS_NESTED_PODMAN") == "1" {
		run = append(run, "--cgroups=disabled")
	}
	s.podman(append(run, args...)...)
}

func (s *podmanStack) cleanup() {
	if os.Getenv("TS_NETBIRD_PODMAN_KEEP") == "1" {
		s.t.Logf("kept containers with prefix %s", s.tag)
		return
	}
	if s.t.Failed() {
		for _, name := range s.containers {
			logs, _ := exec.Command("podman", "logs", "--tail", "20", name).CombinedOutput()
			s.t.Logf("--- %s\n%s", name, tail(string(logs)))
		}
	}
	for _, name := range slices.Backward(s.containers) {
		_ = exec.Command("podman", "rm", "-f", "-t", "2", name).Run()
	}
	_ = exec.Command("podman", "volume", "rm", "-f", s.volume).Run()
	_ = exec.Command("podman", "network", "rm", "-f", s.network).Run()
}

func secret32() string {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

func freePort(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func (s *podmanStack) wait(what string, timeout time.Duration, probe func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if probe() {
			return
		}
		select {
		case <-s.ctx.Done():
			s.t.Fatalf("waiting for %s: %v", what, s.ctx.Err())
		case <-time.After(time.Second):
		}
	}
	s.t.Fatalf("timed out waiting for %s", what)
}

// call is a raw test-harness request; errors include the body for debugging.
func (s *podmanStack) call(token, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		wire, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(wire)
	}
	request, err := http.NewRequestWithContext(s.ctx, method, s.base+"/api"+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Token "+token)
	}
	response, err := s.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	wire, _ := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, response.StatusCode, tail(string(wire)))
	}
	if out != nil && len(bytes.TrimSpace(wire)) > 0 {
		return json.Unmarshal(wire, out)
	}
	return nil
}

func (s *podmanStack) must(token, method, path string, in, out any) {
	s.t.Helper()
	if err := s.call(token, method, path, in, out); err != nil {
		s.t.Fatal(err)
	}
}

func (s *podmanStack) status(token, method, path string, in any) int {
	err := s.call(token, method, path, in, nil)
	if err == nil {
		return http.StatusOK
	}
	var status int
	_, _ = fmt.Sscanf(err.Error()[strings.Index(err.Error(), "HTTP "):], "HTTP %d", &status)
	return status
}

func (s *podmanStack) startServer() string {
	config := filepath.Join(s.t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, []byte(fmt.Sprintf(podmanServerConfig, secret32(), secret32(), secret32())), 0o644); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Chmod(config, 0o644); err != nil {
		s.t.Fatal(err)
	}
	s.podman("network", "create", "--subnet", s.subnet+".0/24", s.network)
	s.podman("volume", "create", s.volume)
	port := freePort(s.t)
	s.base = fmt.Sprintf("http://127.0.0.1:%d", port)
	name := s.tag + "-server"
	s.containers = append(s.containers, name)
	s.run("-d", "--name", name, "--network", s.network, "--ip", s.subnet+".2", "--network-alias", "nbserver",
		"-p", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "NB_SETUP_PAT_ENABLED=true",
		"-v", s.volume+":/var/lib/netbird", "-v", config+":/etc/netbird/config.yaml:ro",
		podmanServerImage, "--config", "/etc/netbird/config.yaml")
	var instance struct {
		SetupRequired bool `json:"setup_required"`
	}
	s.wait("netbird-server API", 4*time.Minute, func() bool { return s.call("", "GET", "/instance", nil, &instance) == nil })
	if !instance.SetupRequired {
		s.t.Fatal("fresh manager does not require owner setup")
	}
	password := make([]byte, 18)
	_, _ = rand.Read(password)
	var setup struct {
		PAT string `json:"personal_access_token"`
	}
	s.must("", "POST", "/setup", map[string]any{"email": "owner@example.test", "password": base64.RawURLEncoding.EncodeToString(password),
		"name": "Test Owner", "create_pat": true, "pat_expire_in": 1}, &setup)
	if len(setup.PAT) < 20 {
		s.t.Fatal("owner setup returned no PAT")
	}
	return setup.PAT
}

func (s *podmanStack) serviceUserToken(owner, name, role string) string {
	var user struct {
		ID string `json:"id"`
	}
	s.must(owner, "POST", "/users", map[string]any{"name": name, "role": role, "is_service_user": true, "auto_groups": []string{}}, &user)
	var token struct {
		Plain string `json:"plain_token"`
	}
	s.must(owner, "POST", "/users/"+user.ID+"/tokens", map[string]any{"name": name, "expires_in": 1}, &token)
	return token.Plain
}

func (s *podmanStack) client(hostname, setupKey, ip string, dns bool) {
	name := s.tag + "-" + hostname
	s.containers = append(s.containers, name)
	args := []string{"-d", "--name", name, "--hostname", hostname, "--network", s.network,
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--device", "/dev/net/tun",
		"-e", "NB_MANAGEMENT_URL=http://nbserver:80", "-e", "NB_SETUP_KEY=" + setupKey,
		"-e", "NB_HOSTNAME=" + hostname, "-e", fmt.Sprintf("NB_DISABLE_DNS=%t", !dns), "-e", "NB_LOG_LEVEL=info"}
	if ip != "" {
		args = append(args, "--ip", ip)
	}
	s.run(append(args, podmanClientImage)...)
}

func (s *podmanStack) removeContainer(hostname string) {
	s.podman("rm", "-f", "-t", "5", s.tag+"-"+hostname)
}

func (s *podmanStack) peerID(owner, hostname string) string {
	var id string
	s.wait("peer "+hostname, 2*time.Minute, func() bool {
		var peers []apiPeer
		if s.call(owner, "GET", "/peers", nil, &peers) != nil {
			return false
		}
		for _, peer := range peers {
			if peer.Hostname == hostname && peer.Connected {
				id = peer.ID
				return true
			}
		}
		return false
	})
	return id
}

type podmanSeed struct {
	groups    map[string]string // legacy name -> ID
	peers     map[string]string // hostname -> ID
	network   string
	resource  string
	router    string
	policies  map[string]string // legacy name -> ID
	serverKey string
	keyID     string
}

func (s *podmanStack) seedLegacy(owner string) podmanSeed {
	seed := podmanSeed{groups: map[string]string{}, peers: map[string]string{}, policies: map[string]string{}}
	var policies []apiPolicy
	s.must(owner, "GET", "/policies", nil, &policies)
	for _, policy := range policies {
		s.must(owner, "DELETE", "/policies/"+policy.ID, nil, nil)
	}
	for _, name := range []string{"operators", "gateway", "ts-orch-servers"} {
		var group created
		s.must(owner, "POST", "/groups", map[string]any{"name": name, "peers": []string{}}, &group)
		seed.groups[name] = group.ID
	}
	key := func(name, kind, group string) (string, string) {
		var out struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		}
		expires, limit := 86400, 1
		if kind == "reusable" {
			expires, limit = 0, 0
		}
		s.must(owner, "POST", "/setup-keys", map[string]any{"name": name, "type": kind, "expires_in": expires,
			"auto_groups": []string{seed.groups[group]}, "usage_limit": limit, "ephemeral": false,
			"allow_extra_dns_labels": false}, &out)
		return out.ID, out.Key
	}
	_, gatewayKey := key("gateway", "one-off", "gateway")
	seed.keyID, seed.serverKey = key("gru-ts-orch-servers", "reusable", "ts-orch-servers")
	_, operatorKey := key("test-operator", "one-off", "operators")
	s.client("ts-ops", gatewayKey, "", false)
	s.client("operator-1", operatorKey, "", true)
	s.client("gru-controller-a", seed.serverKey, s.slotIP("10.251.0.11"), false)
	s.client("gru-member-1", seed.serverKey, s.slotIP("10.251.0.21"), false)
	for _, host := range []string{"ts-ops", "operator-1", "gru-controller-a", "gru-member-1"} {
		seed.peers[host] = s.peerID(owner, host)
	}
	var network, resource, router created
	s.must(owner, "POST", "/networks", map[string]any{"name": "gru-cell", "description": "TerraScale GRU private cell"}, &network)
	s.must(owner, "POST", "/networks/"+network.ID+"/resources", map[string]any{"name": "gru-cell",
		"description": "TerraScale GRU private subnet", "address": s.cellSubnet(), "enabled": true, "groups": []string{}}, &resource)
	s.must(owner, "POST", "/networks/"+network.ID+"/routers", map[string]any{"peer": seed.peers["ts-ops"],
		"metric": 100, "masquerade": true, "enabled": true}, &router)
	seed.network, seed.resource, seed.router = network.ID, resource.ID, router.ID
	operators, gateway, servers := seed.groups["operators"], seed.groups["gateway"], seed.groups["ts-orch-servers"]
	policy := func(name string, rule map[string]any) {
		rule["enabled"], rule["action"] = true, "accept"
		var out created
		s.must(owner, "POST", "/policies", map[string]any{"name": name, "description": "", "enabled": true,
			"source_posture_checks": []string{}, "rules": []any{rule}}, &out)
		seed.policies[name] = out.ID
	}
	policy("operators-to-gru-cell", map[string]any{"name": "operators-to-gru-cell", "bidirectional": false, "protocol": "tcp",
		"ports": []string{"22", "4222", "9465"}, "sources": []string{operators},
		"destinationResource": map[string]string{"id": resource.ID, "type": "subnet"}})
	policy("operators-ssh-to-ts-orch-servers", map[string]any{"name": "operators-ssh-to-ts-orch-servers",
		"bidirectional": false, "protocol": "netbird-ssh", "sources": []string{operators}, "destinations": []string{servers}})
	policy("operators-to-forgejo", map[string]any{"name": "forgejo-services", "bidirectional": false, "protocol": "tcp",
		"ports": []string{"22", "443", "2022"}, "sources": []string{operators}, "destinations": []string{gateway}})
	policy("operators-ping-to-forgejo", map[string]any{"name": "forgejo-ping", "bidirectional": true, "protocol": "icmp",
		"sources": []string{operators}, "destinations": []string{gateway}})
	return seed
}

func (s *podmanStack) inventoryJSON(api *API) string {
	s.t.Helper()
	inventory, err := ReadInventory(s.ctx, api)
	if err != nil {
		s.t.Fatal(err)
	}
	for i := range inventory.Peers {
		inventory.Peers[i].LastSeen = time.Time{}
		inventory.Peers[i].Connected = false
	}
	wire, err := json.Marshal(inventory)
	if err != nil {
		s.t.Fatal(err)
	}
	return string(wire)
}

func (s *podmanStack) verifySynced(owner string, d Desired, seed podmanSeed) {
	t := s.t
	var groups []apiGroup
	s.must(owner, "GET", "/groups", nil, &groups)
	byID := map[string]apiGroup{}
	for _, group := range groups {
		byID[group.ID] = group
	}
	for legacy, name := range map[string]string{"operators": "operators", "gateway": "ts-ops-gateway", "ts-orch-servers": "gru-servers"} {
		if byID[seed.groups[legacy]].Name != name {
			t.Fatalf("group %s did not keep its ID as %s", legacy, name)
		}
	}
	members := func(legacy string) []string {
		var ids []string
		for _, peer := range byID[seed.groups[legacy]].Peers {
			ids = append(ids, peer.ID)
		}
		slices.Sort(ids)
		return ids
	}
	wantServers := []string{seed.peers["gru-controller-a"], seed.peers["gru-member-1"]}
	slices.Sort(wantServers)
	if !slices.Equal(members("gateway"), []string{seed.peers["ts-ops"]}) || !slices.Equal(members("operators"), []string{seed.peers["operator-1"]}) ||
		!slices.Equal(members("ts-orch-servers"), wantServers) {
		t.Fatal("renamed groups lost members")
	}
	var resource apiResource
	s.must(owner, "GET", "/networks/"+seed.network+"/resources/"+seed.resource, nil, &resource)
	if resource.Name != d.Network.Resource.Name || resource.Address != d.Network.Resource.Address || !resource.Enabled {
		t.Fatalf("resource %+v", resource)
	}
	var router apiRouter
	s.must(owner, "GET", "/networks/"+seed.network+"/routers/"+seed.router, nil, &router)
	if router.Peer != seed.peers["ts-ops"] || !router.Masquerade || router.Metric != 100 || !router.Enabled {
		t.Fatalf("router %+v", router)
	}
	var policies []apiPolicy
	s.must(owner, "GET", "/policies", nil, &policies)
	if len(policies) != 4 {
		t.Fatalf("%d policies", len(policies))
	}
	for legacy, id := range seed.policies {
		index := slices.IndexFunc(policies, func(p apiPolicy) bool { return p.ID == id })
		if index < 0 {
			t.Fatalf("policy %s lost its ID", legacy)
		}
		p := policies[index]
		if len(p.Rules) != 1 || p.Rules[0].Name != p.Name || p.Rules[0].Bidirectional || p.Description == "" ||
			p.Rules[0].Description != p.Description || p.Name == legacy {
			t.Fatalf("policy %s: %+v", legacy, p)
		}
	}
	var accounts []apiAccount
	s.must(owner, "GET", "/accounts", nil, &accounts)
	if rawString(accounts[0].Settings, "dns_domain") != d.PeerDNSDomain || rawString(accounts[0].Settings, "network_range") != d.NetworkRange {
		t.Fatal("account settings were not applied")
	}
	var dns dnsSettings
	s.must(owner, "GET", "/dns/settings", nil, &dns)
	if !slices.Equal(dns.DisabledManagementGroups, []string{seed.groups["ts-orch-servers"]}) {
		t.Fatalf("dns settings %v", dns)
	}
	var zones []apiZone
	s.must(owner, "GET", "/dns/zones", nil, &zones)
	if len(zones) != 1 || zones[0].Domain != d.Zone.Domain || !zones[0].Enabled || zones[0].EnableSearchDomain ||
		!slices.Equal(zones[0].DistributionGroups, []string{seed.groups["operators"]}) {
		t.Fatalf("zones %+v", zones)
	}
	var records []apiRecord
	s.must(owner, "GET", "/dns/zones/"+zones[0].ID+"/records", nil, &records)
	var got, want []string
	for _, r := range records {
		got = append(got, fmt.Sprintf("%s %s %s %d", r.Name, r.Type, r.Content, r.TTL))
	}
	for _, r := range d.Records() {
		want = append(want, fmt.Sprintf("%s A %s 300", r.Name, r.Content))
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("records %v, want %v", got, want)
	}
	var key apiSetupKey
	s.must(owner, "GET", "/setup-keys/"+seed.keyID, nil, &key)
	if key.Name != d.SetupKeyName || !key.Valid || key.Revoked || !slices.Equal(key.AutoGroups, []string{seed.groups["ts-orch-servers"]}) {
		t.Fatalf("setup key changed: %+v", key)
	}
}

func (s *podmanStack) exec(container string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "podman", append([]string{"exec", s.tag + "-" + container}, args...)...).CombinedOutput()
	return string(output), err == nil
}

func (s *podmanStack) verifyTraffic(owner string, d Desired, seed podmanSeed) {
	var tsOps, operator apiPeer
	s.must(owner, "GET", "/peers/"+seed.peers["ts-ops"], nil, &tsOps)
	s.must(owner, "GET", "/peers/"+seed.peers["operator-1"], nil, &operator)
	s.wait("operator ping to ts-ops", 2*time.Minute, func() bool {
		_, ok := s.exec("operator-1", "ping", "-c", "1", "-W", "2", tsOps.IP)
		return ok
	})
	// The ping policy is one-way: ts-ops cannot start a ping to operators.
	for range 3 {
		if _, ok := s.exec("ts-ops", "ping", "-c", "1", "-W", "2", operator.IP); ok {
			s.t.Fatal("ts-ops pinged an operator: the ping policy is not one-way")
		}
	}
	slot := d.Slots[0]
	s.wait("operator to resolve "+slot.Name+"."+d.Zone.Domain, 2*time.Minute, func() bool {
		output, ok := s.exec("operator-1", "nslookup", slot.Name+"."+d.Zone.Domain)
		_, answer, _ := strings.Cut(output, "Name:")
		return ok && strings.Contains(answer, slot.IP)
	})
}
