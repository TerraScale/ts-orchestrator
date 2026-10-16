//go:build ignore

// natsdiag reads only regional JetStream metadata during a Firecracker lab run.
// It never prints credentials or raw control-log payloads.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

type diagnosticTopology struct {
	replicas      int
	endpoints     []string
	memberNames   []string
	endpointNames map[string]string
	localEndpoint string
	localMember   string
	managed       bool
}

type formationExpectation struct {
	cell                    string
	replicas                int
	members                 []string
	connectedMember         string
	respondingMembers       []string
	endpointNames           map[string]string
	endpointMappingComplete bool
	phase                   string
	missingMember           string
	managed                 bool
}

func topologyFromControllerConfig(config app.Config) (diagnosticTopology, error) {
	natsConfig := config.NATS
	embedded := natsConfig.Embedded
	if natsConfig.Cell == "" || natsConfig.Instance == "" || natsConfig.Replicas < 1 ||
		embedded == nil || len(embedded.BrokerIDs) != natsConfig.Replicas ||
		len(embedded.Routes) != natsConfig.Replicas-1 {
		return diagnosticTopology{}, errors.New("controller config lacks a complete embedded broker topology")
	}
	parsed, err := url.Parse(natsConfig.URL)
	if err != nil || parsed.Scheme != "tls" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return diagnosticTopology{}, errors.New("controller URL must be a direct TLS endpoint")
	}
	localHost, localPort, err := net.SplitHostPort(parsed.Host)
	if err != nil || localHost != embedded.Host || localPort != strconv.Itoa(embedded.Port) ||
		embedded.Port != 4222 || embedded.RoutePort != 6222 ||
		embedded.RouteHost != embedded.Host || !privateIPv4(localHost) {
		return diagnosticTopology{}, errors.New("controller endpoint differs from its embedded private broker address")
	}
	if !slices.Contains(embedded.BrokerIDs, natsConfig.Instance) {
		return diagnosticTopology{}, errors.New("controller instance is absent from broker slot order")
	}
	seen := make(map[string]struct{}, len(embedded.BrokerIDs))
	for _, name := range embedded.BrokerIDs {
		if name == "" {
			return diagnosticTopology{}, errors.New("broker slot name is empty")
		}
		if _, exists := seen[name]; exists {
			return diagnosticTopology{}, errors.New("broker slot order contains a duplicate")
		}
		seen[name] = struct{}{}
	}
	routeEndpoints := make([]string, 0, len(embedded.Routes))
	for _, route := range embedded.Routes {
		routeURL, err := url.Parse(route)
		if err != nil || routeURL.Scheme != "nats-route" || routeURL.User != nil || routeURL.Path != "" ||
			routeURL.RawQuery != "" || routeURL.Fragment != "" {
			return diagnosticTopology{}, errors.New("embedded route is not a direct NATS route URL")
		}
		host, port, err := net.SplitHostPort(routeURL.Host)
		if err != nil || port != "6222" || !privateIPv4(host) || host == localHost {
			return diagnosticTopology{}, errors.New("embedded route is not a peer private address on port 6222")
		}
		routeEndpoints = append(routeEndpoints, "tls://"+net.JoinHostPort(host, "4222"))
	}
	endpoints := make([]string, len(embedded.BrokerIDs))
	members := make([]string, len(embedded.BrokerIDs))
	endpointNames := make(map[string]string, len(embedded.BrokerIDs))
	routeIndex := 0
	for index, brokerID := range embedded.BrokerIDs {
		members[index] = natsConfig.Cell + "-" + brokerID
		if brokerID == natsConfig.Instance {
			endpoints[index] = natsConfig.URL
		} else {
			endpoints[index] = routeEndpoints[routeIndex]
			routeIndex++
		}
		endpointNames[endpoints[index]] = members[index]
	}
	seenEndpoints := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if _, exists := seenEndpoints[endpoint]; exists {
			return diagnosticTopology{}, errors.New("controller topology contains duplicate endpoints")
		}
		seenEndpoints[endpoint] = struct{}{}
	}
	managedFields := []string{config.Controller.OciRegionIntentFile, config.Controller.OciRegionConfig,
		config.Controller.PlacementConfig}
	managedCount := 0
	for _, field := range managedFields {
		if field != "" {
			managedCount++
		}
	}
	if managedCount != 0 && managedCount != len(managedFields) {
		return diagnosticTopology{}, errors.New("controller config has incomplete managed OCI paths")
	}
	return diagnosticTopology{replicas: natsConfig.Replicas, endpoints: endpoints,
		memberNames: members, endpointNames: endpointNames, localEndpoint: parsed.Host,
		localMember: natsConfig.Cell + "-" + natsConfig.Instance,
		managed:     managedCount == len(managedFields)}, nil
}

func privateIPv4(raw string) bool {
	address, err := netip.ParseAddr(raw)
	return err == nil && address.Is4() && address.IsPrivate() && address.String() == raw
}

func parseDiagnosticForwards(raw string) (map[string]string, error) {
	forwards := make(map[string]string)
	if strings.TrimSpace(raw) == "" {
		return forwards, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		original, destination, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found {
			return nil, errors.New("each forward must map PRIVATE_IP:4222=127.0.0.1:PORT")
		}
		originalHost, originalPort, originalErr := net.SplitHostPort(original)
		destinationHost, destinationPort, destinationErr := net.SplitHostPort(destination)
		port, portErr := strconv.Atoi(destinationPort)
		if originalErr != nil || !privateIPv4(originalHost) || originalPort != "4222" ||
			destinationErr != nil || destinationHost != "127.0.0.1" || portErr != nil || port < 1 || port > 65535 {
			return nil, errors.New("each forward must map a private IPv4 controller endpoint to a loopback TCP port")
		}
		if _, exists := forwards[original]; exists {
			return nil, errors.New("a controller endpoint has multiple forward destinations")
		}
		forwards[original] = destination
	}
	return forwards, nil
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	for index := range items {
		items[index] = strings.TrimSpace(items[index])
	}
	return items
}

func completeTLS(files natscell.TLSFiles) bool {
	return files.CAFile != "" && files.CertFile != "" && files.KeyFile != ""
}

func managedTopology(topology *diagnosticTopology) bool {
	return topology != nil && topology.managed
}

func main() {
	controllerConfigPath := flag.String("controller-config", "", "controller app.Config used to derive signed broker endpoints")
	operatorConfigPath := flag.String("operator-config", "", "operator app.Config used for credentials and TLS")
	seed := flag.String("seed", "", "private controller NKey seed file")
	operatorSeed := flag.String("operator-seed", "", "private operator NKey seed file")
	creds := flag.String("creds", "", "private controller JWT credentials file")
	operatorCreds := flag.String("operator-creds", "", "private operator JWT credentials file")
	sessionMode := flag.String("session-probe", "", "single pinned endpoint admission probe: once or hold")
	cell := flag.String("cell", "", "regional cell name")
	operationID := flag.String("operation-id", "", "delivery operation to inspect without payloads")
	urls := flag.String("urls", "", "comma-separated direct controller URLs")
	forwards := flag.String("nats-forward", "", "comma-separated private-IP:4222=127.0.0.1:PORT NATS forwards")
	phase := flag.String("phase", "steady", "formation expectation: steady, controller-outage, or recovered")
	replicas := flag.Int("replicas", 3, "required JetStream stream replica count")
	members := flag.String("members", "", "expected NATS server names in broker slot order")
	caFile := flag.String("ca", "", "trusted NATS CA PEM file")
	certFile := flag.String("cert", "", "NATS client certificate PEM file")
	keyFile := flag.String("key", "", "NATS client private key PEM file")
	operatorCertFile := flag.String("operator-cert", "", "operator NATS client certificate PEM file")
	operatorKeyFile := flag.String("operator-key", "", "operator NATS client private key PEM file")
	flag.Parse()
	if *phase != "steady" && *phase != "controller-outage" && *phase != "recovered" {
		fmt.Fprintln(os.Stderr, "--phase must be steady, controller-outage, or recovered")
		os.Exit(2)
	}
	if *replicas < 1 || *replicas > 5 {
		fmt.Fprintln(os.Stderr, "--replicas must be between 1 and 5")
		os.Exit(2)
	}
	var topology *diagnosticTopology
	var config app.Config
	if *controllerConfigPath != "" {
		loaded, err := app.LoadConfig(*controllerConfigPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load controller config:", err)
			os.Exit(1)
		}
		config = loaded
		built, err := topologyFromControllerConfig(config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "controller topology:", err)
			os.Exit(2)
		}
		topology = &built
		if *cell == "" {
			*cell = config.NATS.Cell
		}
		if *replicas == 3 && config.NATS.Replicas != 3 {
			*replicas = config.NATS.Replicas
		}
		if *members == "" {
			*members = strings.Join(topology.memberNames, ",")
		}
	}
	if *operatorConfigPath != "" {
		loaded, err := app.LoadConfig(*operatorConfigPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load operator config:", err)
			os.Exit(1)
		}
		config = loaded
		if *cell == "" {
			*cell = config.NATS.Cell
		}
	}
	if *cell == "" {
		fmt.Fprintln(os.Stderr, "--cell or --controller-config is required")
		os.Exit(2)
	}
	if *sessionMode != "" && (*sessionMode != "once" && *sessionMode != "hold" || strings.Contains(*urls, ",") || *controllerConfigPath != "" || *operatorConfigPath != "" || *forwards != "") {
		fmt.Fprintln(os.Stderr, "session probe requires once or hold and one pinned endpoint")
		os.Exit(2)
	}
	forwardMap, err := parseDiagnosticForwards(*forwards)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid --nats-forward:", err)
		os.Exit(2)
	}
	if *phase == "controller-outage" {
		if topology == nil || *operatorConfigPath == "" || len(forwardMap) != *replicas-1 {
			fmt.Fprintln(os.Stderr, "controller-outage requires controller/operator configs and one forward per surviving broker")
			os.Exit(2)
		}
		for endpoint := range forwardMap {
			if endpoint == topology.localEndpoint {
				fmt.Fprintln(os.Stderr, "controller-outage forwards must target surviving broker endpoints")
				os.Exit(2)
			}
		}
	}
	if *urls == "" {
		if topology == nil {
			fmt.Fprintln(os.Stderr, "--urls or --controller-config is required")
			os.Exit(2)
		}
		if *phase == "controller-outage" {
			selected := make([]string, 0, len(forwardMap))
			for _, endpoint := range topology.endpoints {
				if _, ok := forwardMap[strings.TrimPrefix(endpoint, "tls://")]; ok {
					selected = append(selected, endpoint)
				}
			}
			*urls = strings.Join(selected, ",")
		} else {
			*urls = strings.Join(topology.endpoints, ",")
		}
	}
	if *phase == "controller-outage" {
		selected := splitCSV(*urls)
		if len(selected) != len(forwardMap) {
			fmt.Fprintln(os.Stderr, "controller-outage URLs must exactly match the forwarded surviving brokers")
			os.Exit(2)
		}
		for _, endpoint := range selected {
			original, ok := strings.CutPrefix(endpoint, "tls://")
			if !ok {
				fmt.Fprintln(os.Stderr, "controller-outage endpoints must retain their original tls:// identity")
				os.Exit(2)
			}
			if _, ok := forwardMap[original]; !ok {
				fmt.Fprintln(os.Stderr, "controller-outage URLs must target forwarded surviving brokers only")
				os.Exit(2)
			}
		}
	}
	if len(forwardMap) > 0 && *phase != "controller-outage" {
		fmt.Fprintln(os.Stderr, "--nats-forward is only valid during controller-outage")
		os.Exit(2)
	}
	identitySeed, identityCreds := *seed, *creds
	identityTLS := config.NATS.TLS
	role := "controller"
	if *controllerConfigPath != "" && identitySeed == "" && identityCreds == "" {
		identitySeed, identityCreds = config.NATS.NKeySeedFile, config.NATS.CredentialsFile
	}
	if *operatorConfigPath != "" {
		identitySeed, identityCreds = config.NATS.NKeySeedFile, config.NATS.CredentialsFile
		identityTLS = config.NATS.TLS
		role = "operator"
	}
	if identitySeed != "" && identityCreds != "" || identitySeed == "" && identityCreds == "" {
		fmt.Fprintln(os.Stderr, "exactly one controller/operator identity seed or credentials file is required")
		os.Exit(2)
	}
	options, err := diagnosticOptions(identitySeed, identityCreds, *cell)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load NATS identity:", err)
		os.Exit(1)
	}
	if (*caFile != "" || *certFile != "" || *keyFile != "") && (*caFile == "" || *certFile == "" || *keyFile == "") {
		fmt.Fprintln(os.Stderr, "--ca, --cert, and --key must be supplied together")
		os.Exit(2)
	}
	if (*operatorCertFile != "" || *operatorKeyFile != "") &&
		(*operatorCertFile == "" || *operatorKeyFile == "" || *caFile == "" || *operatorSeed == "" && *operatorCreds == "") {
		fmt.Fprintln(os.Stderr, "--operator-cert and --operator-key require TLS and --operator-seed")
		os.Exit(2)
	}
	if *caFile == "" && completeTLS(identityTLS) {
		*caFile, *certFile, *keyFile = identityTLS.CAFile, identityTLS.CertFile, identityTLS.KeyFile
	}
	if *caFile != "" {
		tlsOption, err := diagnosticTLSWithForwards(*caFile, *certFile, *keyFile, forwardMap)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load diagnostic TLS:", err)
			os.Exit(1)
		}
		options = append(options, tlsOption)
	}
	if *sessionMode != "" {
		if err := sessionProbe(*urls, *sessionMode, options); err != nil {
			fmt.Fprintln(os.Stderr, "session probe:", err)
			os.Exit(1)
		}
		return
	}
	if topology != nil && topology.replicas != *replicas {
		fmt.Fprintln(os.Stderr, "--replicas differs from controller config")
		os.Exit(2)
	}
	if topology != nil && *phase == "controller-outage" {
		for endpoint := range forwardMap {
			if !slices.Contains(topology.endpoints, "tls://"+endpoint) {
				fmt.Fprintln(os.Stderr, "--nats-forward contains a non-controller endpoint")
				os.Exit(2)
			}
		}
	}
	expectedMembers := splitCSV(*members)
	if len(expectedMembers) > 0 && len(expectedMembers) != *replicas {
		fmt.Fprintln(os.Stderr, "--members count must equal --replicas")
		os.Exit(2)
	}
	if *phase == "controller-outage" && *replicas != 3 {
		fmt.Fprintln(os.Stderr, "controller-outage currently requires an R3 formation")
		os.Exit(2)
	}
	expectation := formationExpectation{cell: *cell, replicas: *replicas,
		members: expectedMembers, phase: *phase, managed: managedTopology(topology)}
	endpointNames, respondingMembers, mappingComplete, err := diagnosticEndpointMapping(
		splitCSV(*urls), topology, expectedMembers, *phase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "diagnostic endpoints:", err)
		os.Exit(2)
	}
	expectation.endpointNames = endpointNames
	expectation.respondingMembers = respondingMembers
	expectation.endpointMappingComplete = mappingComplete
	if *phase == "controller-outage" && topology != nil {
		expectation.missingMember = topology.localMember
	}
	var output sync.Mutex
	var workers sync.WaitGroup
	var records []map[string]any
	launch := func(url, role string, identity []nats.Option, operatorMode bool) {
		workers.Go(func() {
			record := probe(url, role, *cell, *operationID, identity, expectation, operatorMode)
			output.Lock()
			records = append(records, record)
			output.Unlock()
		})
	}
	for _, url := range splitCSV(*urls) {
		launch(url, role, options, *operatorConfigPath != "" || managedTopology(topology) && role == "operator")
	}
	if *operatorConfigPath == "" && (*operatorSeed != "" || *operatorCreds != "") {
		operatorOptions, err := diagnosticOptions(*operatorSeed, *operatorCreds, *cell)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load operator identity:", err)
			os.Exit(1)
		}
		if *caFile != "" {
			operatorCert, operatorKey := *certFile, *keyFile
			if *operatorCertFile != "" {
				operatorCert, operatorKey = *operatorCertFile, *operatorKeyFile
			}
			tlsOption, err := diagnosticTLS(*caFile, operatorCert, operatorKey)
			if err != nil {
				fmt.Fprintln(os.Stderr, "load diagnostic TLS:", err)
				os.Exit(1)
			}
			operatorOptions = append(operatorOptions, tlsOption)
		}
		launch(*urls, "operator", operatorOptions, managedTopology(topology))
	}
	workers.Wait()
	snapshotIDsUnique := snapshotServerIDsUnique(records, expectation.respondingMembers)
	for _, record := range records {
		record["snapshot_server_ids_unique"] = snapshotIDsUnique
		if snapshotIDsUnique != true {
			record["formation_ready"] = false
		}
	}
	sort.Slice(records, func(left, right int) bool {
		leftURL, _ := records[left]["requested_url"].(string)
		rightURL, _ := records[right]["requested_url"].(string)
		if leftURL != rightURL {
			return leftURL < rightURL
		}
		leftRole, _ := records[left]["role"].(string)
		rightRole, _ := records[right]["role"].(string)
		return leftRole < rightRole
	})
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			fmt.Fprintln(os.Stderr, "encode diagnostic:", err)
			continue
		}
		fmt.Println(string(encoded))
	}
}

func mapTopologyDiagnosticEndpoints(endpoints []string, topology *diagnosticTopology,
	members []string, phase string) (map[string]string, []string, error) {
	if topology == nil {
		return nil, nil, errors.New("controller topology is required")
	}
	if !slices.Equal(members, topology.memberNames) {
		return nil, nil, errors.New("--members must match controller broker slot order")
	}
	expectedEndpoints := make(map[string]string, len(topology.endpointNames))
	for endpoint, member := range topology.endpointNames {
		if phase == "controller-outage" && member == topology.localMember {
			continue
		}
		expectedEndpoints[endpoint] = member
	}
	if len(endpoints) != len(expectedEndpoints) {
		return nil, nil, errors.New("URLs must include every expected direct controller endpoint")
	}
	mapped := make(map[string]string, len(endpoints))
	respondingMembers := make([]string, 0, len(endpoints))
	seenMembers := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		member, ok := expectedEndpoints[endpoint]
		if !ok {
			return nil, nil, errors.New("URL is not an expected direct controller endpoint")
		}
		if _, exists := mapped[endpoint]; exists {
			return nil, nil, errors.New("URLs contain a duplicate controller endpoint")
		}
		if _, exists := seenMembers[member]; exists {
			return nil, nil, errors.New("controller endpoint mapping contains a duplicate member")
		}
		mapped[endpoint] = member
		seenMembers[member] = struct{}{}
		respondingMembers = append(respondingMembers, member)
	}
	return mapped, respondingMembers, nil
}

func diagnosticEndpointMapping(endpoints []string, topology *diagnosticTopology,
	members []string, phase string) (map[string]string, []string, bool, error) {
	if topology != nil {
		mapped, responding, err := mapTopologyDiagnosticEndpoints(endpoints, topology, members, phase)
		return mapped, responding, err == nil, err
	}
	if len(members) > 0 {
		mapped, responding, err := mapExplicitDiagnosticEndpoints(endpoints, members)
		return mapped, responding, err == nil, err
	}
	return nil, nil, false, nil
}

func mapExplicitDiagnosticEndpoints(endpoints, members []string) (map[string]string, []string, error) {
	if len(endpoints) != len(members) {
		return nil, nil, errors.New("--urls count must equal --members count")
	}
	mapped := make(map[string]string, len(endpoints))
	seenMembers := make(map[string]struct{}, len(members))
	for index, endpoint := range endpoints {
		member := members[index]
		if endpoint == "" || member == "" {
			return nil, nil, errors.New("--urls and --members entries must not be empty")
		}
		if _, exists := mapped[endpoint]; exists {
			return nil, nil, errors.New("--urls contains a duplicate endpoint")
		}
		if _, exists := seenMembers[member]; exists {
			return nil, nil, errors.New("--members contains a duplicate member")
		}
		mapped[endpoint] = member
		seenMembers[member] = struct{}{}
	}
	return mapped, slices.Clone(members), nil
}

func snapshotServerIDsUnique(records []map[string]any, expectedResponding ...[]string) bool {
	if len(records) == 0 {
		return false
	}
	seenIDs := make(map[string]string, len(records))
	seenNames := make(map[string]string, len(records))
	responding := make(map[string]string)
	for _, record := range records {
		requestedMember, _ := record["requested_member"].(string)
		server, ok := record["server"].(map[string]string)
		if requestedMember != "" && !ok {
			return false
		}
		if !ok {
			continue
		}
		if server["id"] == "" || server["name"] == "" ||
			requestedMember != "" && server["name"] != requestedMember {
			return false
		}
		if requestedMember != "" {
			if _, exists := responding[requestedMember]; exists {
				return false
			}
			responding[requestedMember] = server["id"]
		}
		if id, exists := seenNames[server["name"]]; exists && id != server["id"] {
			return false
		}
		if name, exists := seenIDs[server["id"]]; exists && name != server["name"] {
			return false
		}
		seenNames[server["name"]] = server["id"]
		seenIDs[server["id"]] = server["name"]
	}
	if len(expectedResponding) > 0 {
		want := make(map[string]struct{}, len(expectedResponding[0]))
		for _, member := range expectedResponding[0] {
			want[member] = struct{}{}
		}
		if len(want) != len(expectedResponding[0]) || len(want) != len(responding) {
			return false
		}
		for member := range want {
			if _, exists := responding[member]; !exists {
				return false
			}
		}
	}
	return true
}

type diagnosticTLSDialer struct {
	config   *tls.Config
	forwards map[string]string
}

func (d *diagnosticTLSDialer) Dial(network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	destination := address
	if forwarded, ok := d.forwards[address]; ok {
		destination = forwarded
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	plain, err := (&net.Dialer{}).DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	config := d.config.Clone()
	if config.ServerName == "" {
		config.ServerName = host
	}
	secure := tls.Client(plain, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		_ = plain.Close()
		return nil, err
	}
	return secure, nil
}

func (*diagnosticTLSDialer) SkipTLSHandshake() bool { return true }

func bridgeURL(raw string) string {
	parts := strings.Split(raw, ",")
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if address, ok := strings.CutPrefix(part, "tls://"); ok {
			parts[index] = "nats://" + address
		} else {
			parts[index] = part
		}
	}
	return strings.Join(parts, ",")
}

func diagnosticTLS(caFile, certFile, keyFile string) (nats.Option, error) {
	return diagnosticTLSWithForwards(caFile, certFile, keyFile, nil)
}

func diagnosticTLSWithForwards(caFile, certFile, keyFile string, forwards map[string]string) (nats.Option, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("NATS CA file has no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return nats.SetCustomDialer(&diagnosticTLSDialer{config: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{certificate},
	}, forwards: forwards}), nil
}

func diagnosticOptions(seedFile, credentialsFile, cell string) ([]nats.Option, error) {
	if credentialsFile == "" {
		return identityOptions(seedFile, cell)
	}
	contents, err := os.ReadFile(credentialsFile)
	if err != nil {
		return nil, err
	}
	pair, err := nkeys.ParseDecoratedUserNKey(contents)
	clear(contents)
	if err != nil {
		return nil, err
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil {
		return nil, err
	}
	return []nats.Option{nats.CustomInboxPrefix("ts.orch.v1." + cell + ".inbox." + public),
		nats.UserCredentials(credentialsFile)}, nil
}

func identityOptions(seedFile, cell string) ([]nats.Option, error) {
	seed, err := os.ReadFile(seedFile)
	if err != nil {
		return nil, err
	}
	pair, err := nkeys.ParseDecoratedUserNKey(seed)
	clear(seed)
	if err != nil {
		return nil, err
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil {
		return nil, err
	}
	identity, err := nats.NkeyOptionFromSeed(seedFile)
	if err != nil {
		return nil, err
	}
	return []nats.Option{nats.CustomInboxPrefix("ts.orch.v1." + cell + ".inbox." + public), identity}, nil
}

// sessionProbe keeps one authenticated, non-reconnecting connection pinned to
// one bridge. A successful INFO request is required after Flush and on each
// hold poll, so an open TCP socket without a working account cannot pass.
func sessionProbe(url, mode string, identity []nats.Option) error {
	return sessionProbeReady(url, mode, identity, nil)
}

func sessionProbeReady(url, mode string, identity []nats.Option, ready chan<- struct{}) error {
	started := time.Now()
	options := append([]nats.Option{nats.Timeout(2 * time.Second), nats.NoReconnect()}, identity...)
	conn, err := nats.Connect(bridgeURL(url), options...)
	if err != nil {
		return fmt.Errorf("authenticated admission: %w", err)
	}
	defer conn.Close()
	read := func() error {
		if err := conn.FlushTimeout(2 * time.Second); err != nil {
			return err
		}
		response, err := conn.Request("$JS.API.INFO", nil, 2*time.Second)
		if err != nil {
			return err
		}
		if len(response.Data) == 0 || strings.Contains(string(response.Data), `"error"`) {
			return errors.New("JetStream account read was empty or rejected")
		}
		return nil
	}
	if err := read(); err != nil {
		return fmt.Errorf("required first read: %w", err)
	}
	emit := func(state string) error {
		encoded, err := json.Marshal(map[string]any{
			"state": state, "elapsed_ms": time.Since(started).Milliseconds(), "time": time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		_, err = fmt.Println(string(encoded))
		return err
	}
	if err := emit("ready"); err != nil || mode == "once" {
		return err
	}
	if ready != nil {
		ready <- struct{}{}
	}
	for time.Since(started) < 5*time.Minute {
		time.Sleep(250 * time.Millisecond)
		if err := read(); err != nil {
			if conn.IsClosed() {
				return emit("closed")
			}
			return fmt.Errorf("required read failed while connection remained open: %w", err)
		}
	}
	return errors.New("pinned connection did not close before probe deadline")
}

func probe(url, role, cell, operationID string, identity []nats.Option,
	expectation formationExpectation, operatorMode bool) map[string]any {
	result := map[string]any{"requested_url": url, "role": role, "time": time.Now().UTC()}
	options := append([]nats.Option{nats.Timeout(2 * time.Second), nats.NoReconnect()}, identity...)
	conn, err := nats.Connect(bridgeURL(url), options...)
	if err != nil {
		result["connect_error"] = err.Error()
		result["formation_ready"] = false
		return result
	}
	defer conn.Close()
	result["connected_url"] = conn.ConnectedUrl()
	result["servers"] = conn.Servers()
	result["discovered_servers"] = conn.DiscoveredServers()
	server := map[string]string{"id": conn.ConnectedServerId(), "name": conn.ConnectedServerName(),
		"cluster": conn.ConnectedClusterName()}
	result["server"] = server
	expectation.connectedMember = server["name"]
	requestedMember := expectation.endpointNames[url]
	if requestedMember != "" {
		result["requested_member"] = requestedMember
	}
	js, err := jetstream.New(conn)
	if err != nil {
		result["jetstream_error"] = err.Error()
		result["formation_ready"] = false
		return result
	}
	read := func(name string, operation func(context.Context) (any, error)) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		value, err := operation(ctx)
		if err != nil {
			result[name+"_error"] = err.Error()
			result[name+"_status"] = resourceStatus(err)
			return
		}
		if _, err := json.Marshal(value); err != nil {
			result[name+"_error"] = fmt.Sprintf("encode diagnostic query: %v", err)
			result[name+"_status"] = "unknown"
			return
		}
		result[name] = value
		result[name+"_status"] = "ok"
	}
	read("account", func(ctx context.Context) (any, error) {
		info, err := js.AccountInfo(ctx)
		if err != nil {
			return nil, err
		}
		return accountDiagnostic(info), nil
	})
	streamNames := append([]string(nil), requiredStreams...)
	if !operatorMode && expectation.managed {
		streamNames = append(streamNames, "KV_TS_PLACEMENT_STATE", "KV_TS_OCI_OPERATIONS")
	} else if operatorMode && expectation.managed {
		result["stream_KV_TS_PLACEMENT_STATE"] = map[string]any{"status": "permission_denied", "access": "controller_only"}
		result["stream_KV_TS_OCI_OPERATIONS"] = map[string]any{"status": "permission_denied", "access": "controller_only"}
	}
	allStreamsReady := true
	for _, name := range streamNames {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		stream, streamErr := js.Stream(ctx, name)
		if streamErr == nil {
			var info *jetstream.StreamInfo
			info, streamErr = stream.Info(ctx)
			if streamErr == nil {
				diagnostic := streamDiagnostic(info)
				readiness := assessStream(info, expectation)
				diagnostic["readiness"] = readiness
				result["stream_"+name] = diagnostic
				if readiness["ready"] != true {
					allStreamsReady = false
				}
			}
		}
		cancel()
		if streamErr != nil {
			result["stream_"+name] = map[string]any{"status": resourceStatus(streamErr)}
			allStreamsReady = false
		}
	}
	if operatorMode && expectation.managed {
		allStreamsReady = false
	}
	result["formation_expectation"] = map[string]any{"cell": expectation.cell,
		"replicas": expectation.replicas, "members": expectation.members, "phase": expectation.phase,
		"endpoint_mapping_complete": expectation.endpointMappingComplete}
	if expectation.missingMember != "" {
		result["formation_expectation"].(map[string]any)["offline_member"] = expectation.missingMember
	}
	result["formation_ready"] = formationReady(result["account_status"] == "ok", allStreamsReady,
		server, requestedMember, expectation)
	if role == "controller" && !operatorMode {
		read("delivery_consumer", func(ctx context.Context) (any, error) {
			consumer, err := js.Consumer(ctx, delivery.IntentStream, delivery.IntentConsumer)
			if err != nil {
				return nil, err
			}
			info, err := consumer.Info(ctx)
			if err != nil {
				return nil, err
			}
			return consumerDiagnostic(info), nil
		})
	}
	if !operatorMode {
		read("authority", func(ctx context.Context) (any, error) {
			snapshot, err := authority.Observe(ctx, js, cell)
			if err != nil {
				return nil, err
			}
			return map[string]any{"candidate": snapshot.CandidateID, "epoch": snapshot.Epoch,
				"revision": snapshot.Revision, "expires_at": snapshot.ExpiresAt,
				"ready": snapshot.Ready, "reason": snapshot.Reason}, nil
		})
	}
	if operationID != "" && !operatorMode {
		read("delivery_operation", func(ctx context.Context) (any, error) {
			return operationDiagnostic(ctx, js, operationID)
		})
	}
	if role == "operator" && !operatorMode {
		result["operator_read_paths"] = operatorReadPaths(conn, js, cell, operationID)
	}
	return result
}

var requiredStreams = []string{authority.ControlStreamName, delivery.IntentStream, "OBJ_TS_ARTIFACTS",
	"KV_TS_DELIVERY_ADMISSIONS", "KV_TS_DELIVERY_OPERATIONS", "KV_TS_HOST_STATE"}

func resourceStatus(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, jetstream.ErrStreamNotFound), errors.Is(err, nats.ErrStreamNotFound):
		return "missing"
	case errors.Is(err, nats.ErrAuthorization), errors.Is(err, nats.ErrPermissionViolation):
		return "permission_denied"
	}
	if apiError, ok := errors.AsType[*jetstream.APIError](err); ok &&
		(apiError.Code == 401 || apiError.Code == 403) {
		return "permission_denied"
	}
	return "unknown"
}

func serverMatchesExpectation(server map[string]string, expected formationExpectation) bool {
	if server["id"] == "" || server["name"] == "" || server["cluster"] != expected.cell {
		return false
	}
	if expected.missingMember != "" && server["name"] == expected.missingMember {
		return false
	}
	return len(expected.members) == 0 || slices.Contains(expected.members, server["name"])
}

func formationReady(accountReady, streamsReady bool, server map[string]string,
	requestedMember string, expected formationExpectation) bool {
	return expected.endpointMappingComplete && accountReady && streamsReady &&
		serverMatchesExpectation(server, expected) &&
		(requestedMember == "" || server["name"] == requestedMember)
}

func assessStream(info *jetstream.StreamInfo, expected formationExpectation) map[string]any {
	status := "ready"
	reason := ""
	if info == nil {
		return map[string]any{"status": "degraded", "ready": false, "reason": "stream_info_missing"}
	}
	if info.Config.Replicas != expected.replicas {
		status, reason = "degraded", "replica_count_mismatch"
	}
	cluster := info.Cluster
	if cluster == nil {
		status, reason = "degraded", "cluster_metadata_missing"
	} else if cluster.Name != expected.cell || cluster.Leader == "" {
		status, reason = "degraded", "cluster_identity_missing"
	} else {
		members := make(map[string]struct{}, expected.replicas)
		if cluster.Leader != "" {
			members[cluster.Leader] = struct{}{}
		}
		availableMembers := map[string]struct{}{cluster.Leader: {}}
		fullyCurrent := true
		for _, peer := range cluster.Replicas {
			if peer == nil || peer.Name == "" {
				fullyCurrent = false
				continue
			}
			members[peer.Name] = struct{}{}
			if !peer.Offline && !peer.Pending && peer.Name != cluster.Leader {
				availableMembers[peer.Name] = struct{}{}
			}
			if !peer.Current || peer.Offline || peer.Pending || peer.Lag != 0 {
				fullyCurrent = false
			}
		}
		if len(members) != expected.replicas {
			status, reason = "degraded", "member_count_mismatch"
		}
		if expected.connectedMember == "" {
			status, reason = "degraded", "connected_member_missing"
		} else if _, exists := members[expected.connectedMember]; !exists {
			status, reason = "degraded", "connected_member_not_in_cluster"
		}
		if len(expected.members) > 0 {
			for _, member := range expected.members {
				if _, exists := members[member]; !exists {
					status, reason = "degraded", "expected_member_missing"
				}
			}
			if len(members) != len(expected.members) {
				status, reason = "degraded", "unexpected_member"
			}
		}
		if expected.phase == "controller-outage" {
			if cluster.Leader == expected.missingMember {
				status, reason = "degraded", "offline_member_is_leader"
			}
			if len(availableMembers) < expected.replicas/2+1 {
				status, reason = "degraded", "quorum_unavailable"
			}
		} else if !fullyCurrent {
			status, reason = "degraded", "replicas_not_current"
		}
	}
	return map[string]any{"status": status, "ready": status == "ready", "reason": reason}
}

type readTarget struct {
	label  string
	bucket string
	key    string
}

func readTargets(cell, operationID string) []readTarget {
	targets := make([]readTarget, 0, 3)
	if operationID != "" {
		sum := sha256.Sum256([]byte(operationID))
		targets = append(targets, readTarget{label: "delivery_operation",
			bucket: delivery.OperationBucket, key: "o_" + hex.EncodeToString(sum[:])})
	}
	targets = append(targets,
		readTarget{label: "host_session", bucket: "TS_HOST_STATE", key: "session." + cell + ".host-a"},
		readTarget{label: "host_report", bucket: "TS_HOST_STATE", key: "report." + cell + ".host-a.terrabase"})
	return targets
}

func (target readTarget) subject() string {
	return "$KV." + target.bucket + "." + target.key
}

// These two reads use the same operator connection but different JetStream
// routes. KeyValue.Get may use a replica's direct endpoint; GetLastMsg without
// DirectGet is sent to the stream leader. Each attempt owns a fresh deadline.
func operatorReadPaths(conn *nats.Conn, js jetstream.JetStream, cell, operationID string) map[string]any {
	results := make(map[string]any)
	for _, target := range readTargets(cell, operationID) {
		results[target.label] = map[string]any{
			"stream": "KV_" + target.bucket,
			"direct_kv": timedReadPath(func(ctx context.Context) (string, bool, uint64, error) {
				store, err := js.KeyValue(ctx, target.bucket)
				if err != nil {
					return "kv_open", false, 0, err
				}
				entry, err := store.Get(ctx, target.key)
				if err != nil {
					return "kv_get", false, 0, err
				}
				if entry == nil {
					return "kv_get", false, 0, errors.New("missing KV entry")
				}
				return "kv_get", true, entry.Revision(), nil
			}),
			"leader_api": timedReadPath(func(ctx context.Context) (string, bool, uint64, error) {
				legacy, err := conn.JetStream()
				if err != nil {
					return "jetstream_context", false, 0, err
				}
				message, err := legacy.GetLastMsg("KV_"+target.bucket, target.subject(), nats.Context(ctx))
				if err != nil {
					return "get_last_msg", false, 0, err
				}
				if message == nil {
					return "get_last_msg", false, 0, errors.New("missing stream message")
				}
				return "get_last_msg", true, message.Sequence, nil
			}),
		}
	}
	return results
}

func timedReadPath(call func(context.Context) (string, bool, uint64, error)) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	stage, found, revision, err := call(ctx)
	return map[string]any{"stage": stage,
		"elapsed_ms": float64(time.Since(started).Microseconds()) / 1000,
		"error":      readPathError(err), "found": found, "revision": revision}
}

func readPathError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return "deadline_exceeded"
	case errors.Is(err, jetstream.ErrKeyNotFound), errors.Is(err, nats.ErrMsgNotFound):
		return "not_found"
	case errors.Is(err, nats.ErrNoResponders):
		return "no_responders"
	case errors.Is(err, nats.ErrAuthorization):
		return "authorization"
	default:
		return "other"
	}
}

func operationDiagnostic(ctx context.Context, js jetstream.JetStream, operationID string) (any, error) {
	store, err := js.KeyValue(ctx, delivery.OperationBucket)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(operationID))
	entry, err := store.Get(ctx, "o_"+hex.EncodeToString(sum[:]))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return map[string]any{"state": "unclaimed"}, nil
	}
	if err != nil {
		return nil, err
	}
	var operation struct {
		Intent struct {
			OperationID    string `json:"operationId"`
			Generation     uint64 `json:"generation"`
			AuthorityEpoch uint64 `json:"authorityEpoch"`
		} `json:"intent"`
		Plan    []struct{} `json:"plan"`
		Receipt *struct {
			Status         string `json:"status"`
			Generation     uint64 `json:"generation"`
			AuthorityEpoch uint64 `json:"authorityEpoch"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(entry.Value(), &operation); err != nil {
		return nil, errors.New("operation metadata is malformed")
	}
	if operation.Intent.OperationID != operationID {
		return nil, errors.New("operation key and stored identity differ")
	}
	result := map[string]any{"state": "claimed", "revision": entry.Revision(),
		"generation": operation.Intent.Generation, "authority_epoch": operation.Intent.AuthorityEpoch,
		"plan_count": len(operation.Plan)}
	if operation.Receipt != nil {
		result["receipt"] = map[string]any{"status": operation.Receipt.Status,
			"generation":      operation.Receipt.Generation,
			"authority_epoch": operation.Receipt.AuthorityEpoch}
	}
	return result, nil
}

func accountDiagnostic(info *jetstream.AccountInfo) map[string]any {
	tiers := make(map[string]any, len(info.Tiers))
	for name, tier := range info.Tiers {
		tiers[name] = map[string]any{"memory": tier.Memory, "storage": tier.Store,
			"reserved_memory": tier.ReservedMemory, "reserved_storage": tier.ReservedStore,
			"streams": tier.Streams, "consumers": tier.Consumers}
	}
	return map[string]any{"api": map[string]any{"level": info.API.Level, "total": info.API.Total,
		"errors": info.API.Errors, "inflight": info.API.Inflight}, "tiers": tiers}
}

func streamDiagnostic(info *jetstream.StreamInfo) map[string]any {
	return map[string]any{"status": "ok", "config_replicas": info.Config.Replicas,
		"messages": info.State.Msgs, "first_seq": info.State.FirstSeq,
		"last_seq": info.State.LastSeq, "cluster": clusterDiagnostic(info.Cluster)}
}

func consumerDiagnostic(info *jetstream.ConsumerInfo) map[string]any {
	return map[string]any{"delivered": sequenceDiagnostic(info.Delivered),
		"ack_floor": sequenceDiagnostic(info.AckFloor), "ack_pending": info.NumAckPending,
		"redelivered": info.NumRedelivered, "waiting": info.NumWaiting,
		"pending": info.NumPending, "cluster": clusterDiagnostic(info.Cluster)}
}

func sequenceDiagnostic(info jetstream.SequenceInfo) map[string]any {
	return map[string]any{"consumer_seq": info.Consumer, "stream_seq": info.Stream,
		"last_active": info.Last}
}

func clusterDiagnostic(info *jetstream.ClusterInfo) any {
	if info == nil {
		return nil
	}
	replicas := make([]map[string]any, 0, len(info.Replicas))
	for _, peer := range info.Replicas {
		if peer == nil {
			continue
		}
		replicas = append(replicas, map[string]any{"name": peer.Name, "peer": peer.Peer,
			"current": peer.Current, "offline": peer.Offline, "pending": peer.Pending,
			"lag": peer.Lag, "active_ns": peer.Active.Nanoseconds()})
	}
	cluster := map[string]any{"name": info.Name, "raft_group": info.RaftGroup,
		"leader": info.Leader, "leader_since": info.LeaderSince, "replicas": replicas}
	if info.Desired != nil {
		desiredReplicas := make([]map[string]any, 0, len(info.Desired.Replicas))
		for _, peer := range info.Desired.Replicas {
			if peer == nil {
				continue
			}
			desiredReplicas = append(desiredReplicas, map[string]any{"name": peer.Name,
				"peer": peer.Peer, "offline": peer.Offline})
		}
		desired := map[string]any{"name": info.Desired.Name, "created": info.Desired.Created,
			"replicas": desiredReplicas}
		if info.Desired.Status != nil {
			desired["status"] = map[string]any{"type": string(info.Desired.Status.Type),
				"description": info.Desired.Status.Description}
		}
		cluster["desired"] = desired
	}
	return cluster
}
