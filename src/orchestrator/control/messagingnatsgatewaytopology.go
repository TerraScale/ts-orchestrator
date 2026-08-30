// Port of src/TerraScale.Orchestrator/Messaging/NatsGatewayTopology.cs.
package control

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// NatsGatewayPlane mirrors the C# enum: the NATS trust plane a cluster belongs
// to. The control and product planes never share an operator, account,
// process, port, cgroup, or store path.
type NatsGatewayPlane int

const (
	NatsGatewayPlaneControl NatsGatewayPlane = 0
	NatsGatewayPlaneProduct NatsGatewayPlane = 1
)

func (p NatsGatewayPlane) String() string {
	switch p {
	case NatsGatewayPlaneControl:
		return "Control"
	case NatsGatewayPlaneProduct:
		return "Product"
	default:
		return strconv.Itoa(int(p))
	}
}

// NatsGatewayEndpoint mirrors the C# record: one qualified transport endpoint
// — an explicit host and an explicit port.
type NatsGatewayEndpoint struct {
	Host string
	Port int
}

// NewNatsGatewayEndpoint mirrors the C# constructor.
func NewNatsGatewayEndpoint(host string, port int) (*NatsGatewayEndpoint, error) {
	if !NatsGatewayEndpointIsValidHost(host) {
		return nil, errors.New(
			"The endpoint host is not a bounded DNS-style host. (Parameter 'host')")
	}

	if port < 1 || port > 65535 {
		return nil, fmt.Errorf(
			"The endpoint port must be an explicit TCP port. (Parameter 'port')\nActual value was %d.", port)
	}

	return &NatsGatewayEndpoint{Host: host, Port: port}, nil
}

// Qualified mirrors the C# Qualified property: the single canonical rendering
// used by configuration and evidence.
func (e *NatsGatewayEndpoint) Qualified() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

// IsLoopback mirrors the C# IsLoopback: true for the whole loopback surface
// the production profile rejects.
func (e *NatsGatewayEndpoint) IsLoopback() bool {
	if strings.EqualFold(e.Host, "localhost") {
		return true
	}

	labels := strings.Split(e.Host, ".")
	if len(labels) == 0 || labels[0] != "127" {
		return false
	}

	for _, label := range labels {
		if len(label) == 0 {
			return false
		}

		for index := 0; index < len(label); index++ {
			if label[index] < '0' || label[index] > '9' {
				return false
			}
		}
	}

	return true
}

// NatsGatewayEndpointParse mirrors the static Parse: parses host:port;
// anything else (including a bare host) is unqualified.
func NatsGatewayEndpointParse(qualified string) (*NatsGatewayEndpoint, error) {
	endpoint, ok := NatsGatewayEndpointTryParse(qualified)
	if !ok || endpoint == nil {
		display := qualified
		if display == "" {
			display = "<null>"
		}

		return nil, fmt.Errorf(
			"The endpoint '%s' is not a qualified host:port endpoint. (Parameter 'qualified')",
			display)
	}

	return endpoint, nil
}

// NatsGatewayEndpointTryParse mirrors the static TryParse.
func NatsGatewayEndpointTryParse(qualified string) (*NatsGatewayEndpoint, bool) {
	if qualified == "" {
		return nil, false
	}

	separator := strings.LastIndex(qualified, ":")
	if separator <= 0 || separator == len(qualified)-1 {
		return nil, false
	}

	host := qualified[:separator]
	portText := qualified[separator+1:]
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, false
	}

	if !NatsGatewayEndpointIsValidHost(host) {
		return nil, false
	}

	endpoint, constructErr := NewNatsGatewayEndpoint(host, port)
	if constructErr != nil {
		return nil, false
	}

	return endpoint, true
}

// NatsGatewayEndpointIsValidHost mirrors the static IsValidHost.
func NatsGatewayEndpointIsValidHost(host string) bool {
	if len(host) < 1 || len(host) > 253 {
		return false
	}

	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		// bracket literals are not part of the accepted host grammar
		return false
	}

	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for index := 0; index < len(label); index++ {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' {
				continue
			}

			return false
		}
	}

	return true
}

// NatsGatewayTransport mirrors the C# enum: the transport a certificate
// profile protects.
type NatsGatewayTransport int

const (
	NatsGatewayTransportClient  NatsGatewayTransport = 0
	NatsGatewayTransportRoute   NatsGatewayTransport = 1
	NatsGatewayTransportGateway NatsGatewayTransport = 2
)

func (t NatsGatewayTransport) String() string {
	switch t {
	case NatsGatewayTransportClient:
		return "Client"
	case NatsGatewayTransportRoute:
		return "Route"
	case NatsGatewayTransportGateway:
		return "Gateway"
	default:
		return strconv.Itoa(int(t))
	}
}

// NatsGatewayCertificateProfile mirrors the C# record: one mTLS certificate
// profile — file references only, never key material.
type NatsGatewayCertificateProfile struct {
	Transport              NatsGatewayTransport
	CertificateFile        string
	KeyFile                string
	CaFile                 string
	ExpectedPeerIdentities []string
}

// NewNatsGatewayCertificateProfile mirrors the C# constructor.
func NewNatsGatewayCertificateProfile(
	transport NatsGatewayTransport,
	certificateFile string,
	keyFile string,
	caFile string,
	expectedPeerIdentities []string,
) (*NatsGatewayCertificateProfile, error) {
	if !path.IsAbs(certificateFile) || !strings.HasSuffix(certificateFile, ".pem") {
		return nil, errors.New(
			"The certificate profile requires an absolute .pem certificate path. (Parameter 'certificateFile')")
	}

	if !path.IsAbs(keyFile) || !strings.HasSuffix(keyFile, ".pem") {
		return nil, errors.New(
			"The certificate profile requires an absolute .pem key path. (Parameter 'keyFile')")
	}

	if !path.IsAbs(caFile) || !strings.HasSuffix(caFile, ".pem") {
		return nil, errors.New(
			"The certificate profile requires an absolute .pem CA path. (Parameter 'caFile')")
	}

	if len(expectedPeerIdentities) == 0 {
		return nil, errors.New(
			"The certificate profile must name at least one expected peer identity. (Parameter 'expectedPeerIdentities')")
	}

	for _, identity := range expectedPeerIdentities {
		if strings.TrimSpace(identity) == "" {
			return nil, errors.New(
				"The certificate profile must name at least one expected peer identity. (Parameter 'expectedPeerIdentities')")
		}
	}

	ordered := append([]string(nil), expectedPeerIdentities...)
	sort.Strings(ordered)

	return &NatsGatewayCertificateProfile{
		Transport:              transport,
		CertificateFile:        certificateFile,
		KeyFile:                keyFile,
		CaFile:                 caFile,
		ExpectedPeerIdentities: ordered,
	}, nil
}

// NatsGatewayProcessIdentity mirrors the C# record: the process identity of
// one nats-server — its dedicated systemd unit and cgroup.
type NatsGatewayProcessIdentity struct {
	UnitName string
	Cgroup   string
}

// NewNatsGatewayProcessIdentity mirrors the C# constructor.
func NewNatsGatewayProcessIdentity(unitName, cgroup string) (*NatsGatewayProcessIdentity, error) {
	if !strings.HasSuffix(unitName, ".service") || len(unitName) < 1 || len(unitName) > 256 {
		return nil, errors.New(
			"The NATS process unit must be a bounded systemd unit name. (Parameter 'unitName')")
	}

	if !strings.HasPrefix(cgroup, "/") || len(cgroup) < 1 || len(cgroup) > 256 ||
		strings.Contains(cgroup, "..") {
		return nil, errors.New(
			"The NATS cgroup must be a bounded absolute cgroup path. (Parameter 'cgroup')")
	}

	return &NatsGatewayProcessIdentity{UnitName: unitName, Cgroup: cgroup}, nil
}

// NatsGatewayServerIdentity mirrors the C# record: one immutable nats-server
// identity inside a regional cluster.
type NatsGatewayServerIdentity struct {
	ServerName          string
	FailureDomain       string
	Client              *NatsGatewayEndpoint
	Route               *NatsGatewayEndpoint
	Gateway             *NatsGatewayEndpoint
	CertificateProfiles []*NatsGatewayCertificateProfile
	Process             *NatsGatewayProcessIdentity
	StoreDirectory      string
}

// NewNatsGatewayServerIdentity mirrors the C# constructor.
func NewNatsGatewayServerIdentity(
	serverName string,
	failureDomain string,
	client *NatsGatewayEndpoint,
	route *NatsGatewayEndpoint,
	gateway *NatsGatewayEndpoint,
	certificateProfiles []*NatsGatewayCertificateProfile,
	process *NatsGatewayProcessIdentity,
	storeDirectory string,
) (*NatsGatewayServerIdentity, error) {
	if strings.TrimSpace(serverName) == "" || len(serverName) > 128 ||
		!isLowercaseDnsToken(serverName) {
		return nil, errors.New(
			"The server name is not a bounded lowercase DNS-style token. (Parameter 'serverName')")
	}

	if strings.TrimSpace(failureDomain) == "" || len(failureDomain) > 253 {
		return nil, errors.New(
			"The failure domain is not a bounded host identity. (Parameter 'failureDomain')")
	}

	clientProfiles := 0
	routeProfiles := 0
	gatewayProfiles := 0
	for _, profile := range certificateProfiles {
		switch profile.Transport {
		case NatsGatewayTransportClient:
			clientProfiles++
		case NatsGatewayTransportRoute:
			routeProfiles++
		case NatsGatewayTransportGateway:
			gatewayProfiles++
		}
	}

	if clientProfiles != 1 || routeProfiles != 1 {
		return nil, errors.New(
			"The server must declare exactly one certificate profile for each of client and route. (Parameter 'certificateProfiles')")
	}

	if (gateway == nil && gatewayProfiles > 0) || (gateway != nil && gatewayProfiles != 1) {
		return nil, errors.New(
			"A gateway certificate profile exists exactly when the server opens a gateway listener. (Parameter 'certificateProfiles')")
	}

	if !path.IsAbs(storeDirectory) || strings.Contains(storeDirectory, "..") {
		return nil, errors.New(
			"The store directory must be an absolute path without traversal. (Parameter 'storeDirectory')")
	}

	return &NatsGatewayServerIdentity{
		ServerName:          serverName,
		FailureDomain:       failureDomain,
		Client:              client,
		Route:               route,
		Gateway:             gateway,
		CertificateProfiles: certificateProfiles,
		Process:             process,
		StoreDirectory:      storeDirectory,
	}, nil
}

// Profile mirrors the C# Profile method.
func (s *NatsGatewayServerIdentity) Profile(transport NatsGatewayTransport) *NatsGatewayCertificateProfile {
	for _, profile := range s.CertificateProfiles {
		if profile.Transport == transport {
			return profile
		}
	}

	return nil
}

// Listeners mirrors the C# Listeners property.
func (s *NatsGatewayServerIdentity) Listeners() []*NatsGatewayEndpoint {
	listeners := []*NatsGatewayEndpoint{s.Client, s.Route}
	if s.Gateway != nil {
		listeners = append(listeners, s.Gateway)
	}

	return listeners
}

func isLowercaseDnsToken(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '-' {
			continue
		}

		return false
	}

	return true
}

// NatsGatewayAccountLimits mirrors the C# record: the account limits one
// account scope enforces.
type NatsGatewayAccountLimits struct {
	MaxConnections     int
	MaxSubscriptions   int
	MaxPayloadBytes    int64
	MaxStreams         int
	MaxConsumers       int
	MaxDiskStorageBytes int64
}

// NewNatsGatewayAccountLimits mirrors the C# constructor.
func NewNatsGatewayAccountLimits(
	maxConnections int,
	maxSubscriptions int,
	maxPayloadBytes int64,
	maxStreams int,
	maxConsumers int,
	maxDiskStorageBytes int64,
) (*NatsGatewayAccountLimits, error) {
	if maxConnections < 1 {
		return nil, errors.New("The account limit must be positive. (Parameter 'maxConnections')")
	}

	if maxSubscriptions < 1 {
		return nil, errors.New("The account limit must be positive. (Parameter 'maxSubscriptions')")
	}

	if maxPayloadBytes < 1 {
		return nil, errors.New("The account limit must be positive. (Parameter 'maxPayloadBytes')")
	}

	if maxStreams < 0 || maxConsumers < 0 {
		return nil, errors.New(
			"The stream and consumer limits must not be negative. (Parameter 'maxStreams')")
	}

	if maxDiskStorageBytes < 0 {
		return nil, errors.New(
			"The account limit must not be negative. (Parameter 'maxDiskStorageBytes')")
	}

	return &NatsGatewayAccountLimits{
		MaxConnections:     maxConnections,
		MaxSubscriptions:   maxSubscriptions,
		MaxPayloadBytes:    maxPayloadBytes,
		MaxStreams:         maxStreams,
		MaxConsumers:       maxConsumers,
		MaxDiskStorageBytes: maxDiskStorageBytes,
	}, nil
}

// NatsGatewayAccountScope mirrors the C# record: one separately scoped account
// inside the plane trust model.
type NatsGatewayAccountScope struct {
	Cell             string
	AccountName      string
	SigningKeyNames  []string
	Users            []string
	Limits           *NatsGatewayAccountLimits
}

// NewNatsGatewayAccountScope mirrors the C# constructor.
func NewNatsGatewayAccountScope(
	cell string,
	accountName string,
	signingKeyNames []string,
	users []string,
	limits *NatsGatewayAccountLimits,
) (*NatsGatewayAccountScope, error) {
	if strings.TrimSpace(cell) == "" || len(cell) > 63 ||
		!isLowercaseDnsToken(cell) {
		return nil, errors.New(
			"The account scope cell is not a bounded lowercase token. (Parameter 'cell')")
	}

	if !GlobalNatsAccountNamesIsValid(accountName) {
		return nil, errors.New(
			"The account scope name is not a valid NATS account name. (Parameter 'accountName')")
	}

	if len(signingKeyNames) == 0 {
		return nil, errors.New(
			"The account scope must reference at least one signing key name. (Parameter 'signingKeyNames')")
	}

	for _, key := range signingKeyNames {
		if strings.TrimSpace(key) == "" || len(key) > 128 {
			return nil, errors.New(
				"The account scope must reference at least one signing key name. (Parameter 'signingKeyNames')")
		}
	}

	if len(users) == 0 {
		return nil, errors.New(
			"The account scope must name at least one bounded user. (Parameter 'users')")
	}

	for _, user := range users {
		if len(user) < 1 || len(user) > 128 || !isBoundedUserName(user) {
			return nil, errors.New(
				"The account scope must name at least one bounded user. (Parameter 'users')")
		}
	}

	keys := distinctSorted(signingKeyNames)
	userNames := distinctSorted(users)

	return &NatsGatewayAccountScope{
		Cell:            cell,
		AccountName:     accountName,
		SigningKeyNames: keys,
		Users:           userNames,
		Limits:          limits,
	}, nil
}

func isBoundedUserName(user string) bool {
	for index := 0; index < len(user); index++ {
		character := user[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}

		return false
	}

	return true
}

func distinctSorted(values []string) []string {
	seen := map[string]struct{}{}
	ordered := make([]string, 0, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}

		seen[value] = struct{}{}
		ordered = append(ordered, value)
	}

	sort.Strings(ordered)
	return ordered
}

// NatsGatewayServiceExportScope mirrors the C# NatsGatewayServiceExport record.
type NatsGatewayServiceExportScope struct {
	AccountName string
	Subject     string
}

// NewNatsGatewayServiceExportScope mirrors the C# constructor.
func NewNatsGatewayServiceExportScope(accountName, subject string) (*NatsGatewayServiceExportScope, error) {
	if !GlobalNatsAccountNamesIsValid(accountName) {
		return nil, errors.New("The exporting account name is invalid. (Parameter 'accountName')")
	}

	if strings.TrimSpace(subject) == "" {
		return nil, errors.New("The exported subject must be a concrete subject. (Parameter 'subject')")
	}

	return &NatsGatewayServiceExportScope{AccountName: accountName, Subject: subject}, nil
}

// NatsGatewayServiceImportScope mirrors the C# NatsGatewayServiceImport record.
type NatsGatewayServiceImportScope struct {
	AccountName      string
	Subject          string
	SourceAccountName string
}

// NewNatsGatewayServiceImportScope mirrors the C# constructor.
func NewNatsGatewayServiceImportScope(accountName, subject, sourceAccountName string) (*NatsGatewayServiceImportScope, error) {
	if !GlobalNatsAccountNamesIsValid(accountName) {
		return nil, errors.New("The importing account name is invalid. (Parameter 'accountName')")
	}

	if strings.TrimSpace(subject) == "" {
		return nil, errors.New("The imported subject must be a concrete subject. (Parameter 'subject')")
	}

	if !GlobalNatsAccountNamesIsValid(sourceAccountName) {
		return nil, errors.New("The source account name is invalid. (Parameter 'sourceAccountName')")
	}

	return &NatsGatewayServiceImportScope{
		AccountName:      accountName,
		Subject:          subject,
		SourceAccountName: sourceAccountName,
	}, nil
}

// NatsGatewayRelationship mirrors the C# record: one directed gateway
// relationship from one cell's cluster to another's.
type NatsGatewayRelationship struct {
	FromCell string
	ToCell   string
}

// NatsGatewayCluster port constants mirror the C# consts.
const (
	NatsGatewayClusterControlClientPort = 4222
	NatsGatewayClusterControlRoutePort  = 6222
	NatsGatewayClusterControlGatewayPort = 7222
	NatsGatewayClusterProductClientPort = 4223
	NatsGatewayClusterProductRoutePort  = 6223
)

// NatsGatewayCluster mirrors the C# record: one immutable regional cluster of
// the plane.
type NatsGatewayCluster struct {
	Plane                 NatsGatewayPlane
	Cell                  string
	ClusterName           string
	JetStreamDomain       string
	OperatorName          string
	Servers               []*NatsGatewayServerIdentity
	Accounts              []string
	JetStreamAssets       []string
	CgroupSlice           string
	TrustGeneration       int
	ConfigurationGeneration int
}

// NewNatsGatewayCluster mirrors the C# constructor.
func NewNatsGatewayCluster(
	plane NatsGatewayPlane,
	cell string,
	clusterName string,
	jetStreamDomain string,
	operatorName string,
	servers []*NatsGatewayServerIdentity,
	accounts []string,
	jetStreamAssets []string,
	cgroupSlice string,
	trustGeneration int,
	configurationGeneration int,
) (*NatsGatewayCluster, error) {
	if !messagingCellTokenIsValid(cell) {
		return nil, errors.New(
			"The cluster cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	if strings.TrimSpace(clusterName) == "" || len(clusterName) > 256 {
		return nil, errors.New("The cluster name must be bounded. (Parameter 'clusterName')")
	}

	if strings.TrimSpace(jetStreamDomain) == "" || len(jetStreamDomain) > 64 ||
		!isUppercaseToken(jetStreamDomain) {
		return nil, errors.New(
			"The JetStream domain must be a bounded uppercase token. (Parameter 'jetStreamDomain')")
	}

	if strings.TrimSpace(operatorName) == "" || len(operatorName) > 128 {
		return nil, errors.New("The operator name must be bounded. (Parameter 'operatorName')")
	}

	if len(servers) == 0 {
		return nil, errors.New("The cluster must declare at least one server. (Parameter 'servers')")
	}

	if len(accounts) == 0 {
		return nil, errors.New(
			"The cluster must declare a non-empty set of valid account names. (Parameter 'accounts')")
	}

	for _, account := range accounts {
		if !GlobalNatsAccountNamesIsValid(account) {
			return nil, errors.New(
				"The cluster must declare a non-empty set of valid account names. (Parameter 'accounts')")
		}
	}

	for _, asset := range jetStreamAssets {
		if strings.TrimSpace(asset) == "" || len(asset) > 256 {
			return nil, errors.New(
				"The JetStream asset names must be bounded. (Parameter 'jetStreamAssets')")
		}
	}

	if !strings.HasPrefix(cgroupSlice, "/") || len(cgroupSlice) > 256 ||
		strings.Contains(cgroupSlice, "..") {
		return nil, errors.New(
			"The cgroup slice must be a bounded absolute cgroup path. (Parameter 'cgroupSlice')")
	}

	if trustGeneration < 1 || configurationGeneration < 1 {
		return nil, errors.New(
			"The trust and configuration generations must be positive. (Parameter 'trustGeneration')")
	}

	if plane == NatsGatewayPlaneProduct {
		for _, server := range servers {
			if server.Gateway != nil {
				return nil, errors.New(
					"A product-plane cluster must not declare a gateway listener. (Parameter 'servers')")
			}
		}
	}

	for _, server := range servers {
		if !strings.HasPrefix(server.Process.Cgroup, cgroupSlice+"/") {
			return nil, errors.New(
				"Every server process cgroup must live inside the cluster's cgroup slice. (Parameter 'servers')")
		}
	}

	return &NatsGatewayCluster{
		Plane:                 plane,
		Cell:                  cell,
		ClusterName:           clusterName,
		JetStreamDomain:       jetStreamDomain,
		OperatorName:          operatorName,
		Servers:               servers,
		Accounts:              distinctSorted(accounts),
		JetStreamAssets:       distinctSorted(jetStreamAssets),
		CgroupSlice:           cgroupSlice,
		TrustGeneration:       trustGeneration,
		ConfigurationGeneration: configurationGeneration,
	}, nil
}

// Profile mirrors the C# Profile method.
func (c *NatsGatewayCluster) Profile(serverName string, transport NatsGatewayTransport) (*NatsGatewayCertificateProfile, error) {
	server, err := c.Server(serverName)
	if err != nil {
		return nil, err
	}

	return server.Profile(transport), nil
}

// Server mirrors the C# Server method.
func (c *NatsGatewayCluster) Server(serverName string) (*NatsGatewayServerIdentity, error) {
	found := 0
	var match *NatsGatewayServerIdentity
	for _, server := range c.Servers {
		if server.ServerName == serverName {
			found++
			match = server
		}
	}

	if found != 1 {
		return nil, fmt.Errorf(
			"The server '%s' is not part of cluster '%s'. (Parameter 'serverName')",
			serverName, c.ClusterName)
	}

	return match, nil
}

func isUppercaseToken(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
			character == '_' {
			continue
		}

		return false
	}

	return true
}

// NatsGatewayPlan mirrors the C# record: the complete typed plan for one NATS
// plane.
type NatsGatewayPlan struct {
	Plane                NatsGatewayPlane
	OperatorName         string
	TrustGeneration      int
	ConfigurationGeneration int
	Clusters             []*NatsGatewayCluster
	GatewayRelationships []NatsGatewayRelationship
	Accounts             []*NatsGatewayAccountScope
	Exports              []*NatsGatewayServiceExportScope
	Imports              []*NatsGatewayServiceImportScope
}

// NewNatsGatewayPlan mirrors the C# constructor.
func NewNatsGatewayPlan(
	plane NatsGatewayPlane,
	operatorName string,
	trustGeneration int,
	configurationGeneration int,
	clusters []*NatsGatewayCluster,
	gatewayRelationships []NatsGatewayRelationship,
	accounts []*NatsGatewayAccountScope,
	exports []*NatsGatewayServiceExportScope,
	imports []*NatsGatewayServiceImportScope,
) (*NatsGatewayPlan, error) {
	if strings.TrimSpace(operatorName) == "" || len(operatorName) > 128 {
		return nil, errors.New("The operator name must be bounded. (Parameter 'operatorName')")
	}

	if trustGeneration < 1 || configurationGeneration < 1 {
		return nil, errors.New(
			"The trust and configuration generations must be positive. (Parameter 'trustGeneration')")
	}

	if len(clusters) == 0 {
		return nil, errors.New("The plan must declare at least one cluster. (Parameter 'clusters')")
	}

	for _, cluster := range clusters {
		if cluster.Plane != plane {
			return nil, errors.New(
				"Every cluster in the plan must belong to the plan's plane. (Parameter 'clusters')")
		}

		if cluster.OperatorName != operatorName {
			return nil, errors.New(
				"Every cluster in the plan must share the plan's operator trust root. (Parameter 'clusters')")
		}
	}

	if len(accounts) == 0 {
		return nil, errors.New("The plan must declare at least one account scope. (Parameter 'accounts')")
	}

	return &NatsGatewayPlan{
		Plane:                plane,
		OperatorName:         operatorName,
		TrustGeneration:      trustGeneration,
		ConfigurationGeneration: configurationGeneration,
		Clusters:             clusters,
		GatewayRelationships: gatewayRelationships,
		Accounts:             accounts,
		Exports:              exports,
		Imports:              imports,
	}, nil
}

// Cluster mirrors the C# Cluster method.
func (p *NatsGatewayPlan) Cluster(cell string) *NatsGatewayCluster {
	found := 0
	var match *NatsGatewayCluster
	for _, cluster := range p.Clusters {
		if cluster.Cell == cell {
			found++
			match = cluster
		}
	}

	if found != 1 {
		return nil
	}

	return match
}
