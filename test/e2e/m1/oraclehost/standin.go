package oraclehost

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/regionhost"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const (
	vaultRegion  = "sa-saopaulo-1"
	githubIssuer = "https://token.actions.githubusercontent.com"
	orchWorkflow = "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main"
)

var standInNames = []string{
	"secrets.vaults." + vaultRegion + ".oci.oraclecloud.com",
	"vaults." + vaultRegion + ".oci.oraclecloud.com",
	"token.actions.githubusercontent.com",
	registryHost,
	githubAPI,
	githubWeb,
	githubAssets,
}

type secret struct {
	ID       string
	Name     string
	VaultID  string
	Versions [][]byte
}

type standIn struct {
	fleet    *Fleet
	names    []string
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	caPEM    []byte
	identity [3][]byte
	signer   *rsa.PrivateKey
	mu       sync.Mutex
	secrets  map[string]*secret
	pinned   map[string]int
	changed  chan struct{}
	requests map[string]int
	servers  []*http.Server
	github   *GitHub
	callers  map[string]string
	grants   map[vaultGrant]string
	access   map[string]int
	hosts    []*Host
	gone     map[string]bool
}

type vaultGrant struct{ compartment, vault, secret string }

var grantStatement = regexp.MustCompile(`^Allow dynamic-group \S+ to (read secret-bundles|manage secret-family) in compartment id \S+ where all \{target\.vault\.id = '([^']+)', (.+), target\.secret\.name = '([^']+)'\}$`)

var grantPrincipal = regexp.MustCompile(`request\.principal\.compartment\.id = '([^']+)'`)

func (s *standIn) loadGrants() error {
	compartments := map[string]string{}
	for _, region := range s.fleet.Regions {
		compartments[region.Name] = region.CompartmentID
		for _, host := range region.Hosts {
			s.callers[host.Address] = region.CompartmentID
		}
	}
	statements, err := regionhost.Statements(compartments)
	if err != nil {
		return err
	}
	for _, statement := range statements {
		match := grantStatement.FindStringSubmatch(statement)
		if match == nil {
			continue
		}
		verb := strings.Fields(match[1])[0]
		for _, principal := range grantPrincipal.FindAllStringSubmatch(match[3], -1) {
			s.grants[vaultGrant{compartment: principal[1], vault: match[2], secret: match[4]}] = verb
		}
	}
	return nil
}

func (s *standIn) granted(r *http.Request, vault, name string, manage bool) bool {
	address, _, _ := net.SplitHostPort(r.RemoteAddr)
	compartment := s.callers[address]
	verb := s.grants[vaultGrant{compartment: compartment, vault: vault, secret: name}]
	allowed := verb == "manage" || verb == "read" && !manage
	verdict := "denied "
	if allowed {
		verdict = "granted "
	}
	s.access[verdict+name+" for "+address]++
	return allowed
}

func certificate(template, parent *x509.Certificate, public crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	template.SerialNumber = serial
	template.NotBefore, template.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (f *Fleet) EdgeMaterial(name string) ([]byte, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafPEM, err := certificate(&x509.Certificate{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, f.standIn.caCert, leafKey.Public(), f.standIn.caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	return append(leafPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...), nil
}

func newStandIn(f *Fleet) (*standIn, *tls.Certificate, error) {
	names := slices.Clone(standInNames)
	for _, region := range f.Regions {
		names = append(names, "auth."+region.OCIRegion+".oraclecloud.com", "iaas."+region.OCIRegion+".oraclecloud.com")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	s := &standIn{fleet: f, names: names, caKey: caKey, secrets: map[string]*secret{}, pinned: map[string]int{}, changed: make(chan struct{}), requests: map[string]int{}, github: newGitHub(),
		callers: map[string]string{}, grants: map[vaultGrant]string{}, access: map[string]int{}, hosts: slices.Clone(f.Hosts), gone: map[string]bool{}}
	if err := s.loadGrants(); err != nil {
		return nil, nil, err
	}
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "oracle-regions stand-in CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if s.caPEM, err = certificate(ca, nil, caKey.Public(), caKey); err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(s.caPEM)
	if ca, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, nil, err
	}
	s.caCert = ca
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serverPEM, err := certificate(&x509.Certificate{Subject: pkix.Name{CommonName: "stand-in"}, DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, serverKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	serverDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return nil, nil, err
	}
	pair, err := tls.X509KeyPair(serverPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverDER}))
	if err != nil {
		return nil, nil, err
	}
	identityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	identity := &x509.Certificate{Subject: pkix.Name{CommonName: "instance", OrganizationalUnit: []string{"opc-tenant:ocid1.tenancy.oc1..oracleregions", "opc-instance:ocid1.instance.oc1..oracleregions"}}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if s.identity[0], err = certificate(identity, ca, identityKey.Public(), caKey); err != nil {
		return nil, nil, err
	}
	s.identity[1] = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(identityKey)})
	s.identity[2] = s.caPEM
	if s.signer, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, nil, err
	}
	return s, &pair, s.seedProductionSecrets()
}

func (s *standIn) seedProductionSecrets() error {
	refs := []vaultsecret.Ref{}
	for _, ref := range vaultsecret.AlertDeliveryRefs() {
		refs = append(refs, ref)
	}
	entries, err := m1.Files.ReadDir("services")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := m1.Files.ReadFile("services/" + entry.Name())
		if err != nil {
			return err
		}
		var manifest struct {
			Secrets map[string]vaultsecret.Ref `json:"secrets"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return err
		}
		for _, ref := range manifest.Secrets {
			refs = append(refs, ref)
		}
	}
	for _, ref := range refs {
		region := strings.Split(ref.Vault, ".")[3]
		if region != vaultRegion {
			return fmt.Errorf("first-party secret %s lives in a %s Vault the stand-in does not serve", ref.Name, region)
		}
		digest := sha256.Sum256([]byte(ref.Name))
		value := []byte("stand-in " + ref.Name)
		if strings.HasSuffix(ref.Name, "-terrabase-peer-secret") {
			value = []byte(hex.EncodeToString(digest[:]))
		}
		s.secrets[ref.Name] = &secret{ID: "ocid1.vaultsecret.oc1." + region + "." + hex.EncodeToString(digest[:12]), Name: ref.Name, VaultID: ref.Vault, Versions: [][]byte{value}}
	}
	return nil
}

func (s *standIn) serve(listener net.Listener, handler http.HandlerFunc) {
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	s.servers = append(s.servers, server)
	go func() { _ = server.Serve(listener) }()
}

func (s *standIn) close() {
	for _, server := range s.servers {
		_ = server.Close()
	}
}

func (s *standIn) count(key string) {
	s.mu.Lock()
	s.requests[key]++
	s.mu.Unlock()
}

func (s *standIn) Requests() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := map[string]int{}
	for key, value := range s.requests {
		copied[key] = value
	}
	return copied
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func serviceError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("opc-request-id", "stand-in")
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}

func (s *standIn) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer Oracle" {
		http.Error(w, "IMDS v2 requires Authorization: Bearer Oracle", http.StatusUnauthorized)
		return
	}
	address, _, _ := net.SplitHostPort(r.RemoteAddr)
	host := s.fleet.hostByAddress(address)
	if host == nil {
		http.Error(w, "unknown instance", http.StatusNotFound)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/opc/v2/")
	s.count("imds " + strings.TrimSuffix(path, "/"))
	instance := map[string]any{
		"id": host.InstanceID, "displayName": host.Name, "hostname": host.Name,
		"region": host.Region.OCIRegion, "canonicalRegionName": host.Region.OCIRegion,
		"availabilityDomain": "stand-in:" + strings.ToUpper(host.Region.OCIRegion) + "-AD-1", "faultDomain": "FAULT-DOMAIN-1",
		"compartmentId": host.Region.CompartmentID, "shape": "VM.Standard.A1.Flex",
		"state": "Running", "metadata": map[string]string{}, "definedTags": map[string]any{}, "freeformTags": map[string]string{},
	}
	switch path {
	case "instance/", "instance":
		writeJSON(w, http.StatusOK, instance)
	case "instance/id", "instance/displayName", "instance/hostname", "instance/region", "instance/canonicalRegionName", "instance/availabilityDomain", "instance/compartmentId":
		_, _ = io.WriteString(w, fmt.Sprint(instance[strings.TrimPrefix(path, "instance/")]))
	case "vnics/", "vnics":
		writeJSON(w, http.StatusOK, []map[string]string{{"vnicId": "ocid1.vnic.oc1." + host.Region.OCIRegion + "." + host.Name, "privateIp": host.Address, "vlanTag": "0", "macAddr": "02:00:17:00:00:01", "virtualRouterIp": GatewayAddress, "subnetCidrBlock": subnetCIDR, "vcnCidrBlock": subnetCIDR}})
	case "identity/cert.pem":
		_, _ = w.Write(s.identity[0])
	case "identity/key.pem":
		_, _ = w.Write(s.identity[1])
	case "identity/intermediate.pem":
		_, _ = w.Write(s.identity[2])
	default:
		http.NotFound(w, r)
	}
}

func (s *standIn) cloud(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	s.count(r.Method + " " + host + strings.SplitN(r.URL.Path, "/", 3)[1])
	switch {
	case strings.HasPrefix(host, "auth.") && slices.Contains(s.names, host) && r.Method == http.MethodPost && r.URL.Path == "/v1/x509":
		s.federate(w, r)
	case host == "secrets.vaults."+vaultRegion+".oci.oraclecloud.com" && r.URL.Path == "/20190301/secretbundles/actions/getByName":
		s.bundle(w, r)
	case host == "vaults."+vaultRegion+".oci.oraclecloud.com" && strings.HasPrefix(r.URL.Path, "/20180608/secrets"):
		s.management(w, r)
	case host == "token.actions.githubusercontent.com" && r.URL.Path == "/.well-known/jwks":
		s.jwks(w)
	case host == registryHost && strings.HasPrefix(r.URL.Path, "/v2/"):
		s.registry(w, r)
	case strings.HasPrefix(host, "iaas.") && slices.Contains(s.names, host) && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/20160918/"):
		s.compute(w, r, strings.TrimSuffix(strings.TrimPrefix(host, "iaas."), ".oraclecloud.com"))
	case host == githubAPI || host == githubWeb || host == githubAssets:
		s.github.serve(w, r, host)
	default:
		serviceError(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "stand-in has no "+r.Method+" "+host+r.URL.Path)
	}
}

func (s *standIn) federate(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Certificate string `json:"certificate"`
		PublicKey   string `json:"publicKey"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil || request.Certificate == "" || request.PublicKey == "" {
		serviceError(w, http.StatusBadRequest, "InvalidParameter", "federation request needs the instance certificate and a session key")
		return
	}
	leaf, _ := pem.Decode(s.identity[0])
	if request.Certificate != base64.StdEncoding.EncodeToString(leaf.Bytes) {
		serviceError(w, http.StatusUnauthorized, "NotAuthenticated", "certificate is not the instance identity")
		return
	}
	claims, _ := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "opc-tenant": "ocid1.tenancy.oc1..oracleregions", "opc-instance": "ocid1.instance.oc1..oracleregions"})
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".c3RhbmQtaW4"
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *standIn) notify() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func secretJSON(item *secret) map[string]any {
	return map[string]any{
		"id": item.ID, "secretName": item.Name, "vaultId": item.VaultID, "compartmentId": "ocid1.compartment.oc1..oracleregions",
		"keyId": "ocid1.key.oc1." + vaultRegion + ".oracleregions", "lifecycleState": "ACTIVE",
		"currentVersionNumber": len(item.Versions), "timeCreated": time.Now().UTC().Format(time.RFC3339),
	}
}

func (s *standIn) bundle(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.secrets[query.Get("secretName")]
	if !s.granted(r, query.Get("vaultId"), query.Get("secretName"), false) || item == nil || item.VaultID != query.Get("vaultId") {
		serviceError(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "secret not found")
		return
	}
	version := len(item.Versions)
	if pinned := s.pinned[item.Name]; pinned != 0 {
		version = pinned
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secretId": item.ID, "versionNumber": version, "stages": []string{"CURRENT", "LATEST"},
		"timeCreated":         time.Now().UTC().Format(time.RFC3339),
		"secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(item.Versions[version-1])},
	})
}

func (s *standIn) management(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/20180608/secrets"), "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case id == "" && r.Method == http.MethodGet:
		items := []map[string]any{}
		for _, item := range s.secrets {
			if item.Name == r.URL.Query().Get("name") && item.VaultID == r.URL.Query().Get("vaultId") {
				items = append(items, secretJSON(item))
			}
		}
		writeJSON(w, http.StatusOK, items)
	case id == "" && r.Method == http.MethodPost:
		var request struct {
			SecretName    string `json:"secretName"`
			VaultID       string `json:"vaultId"`
			SecretContent struct {
				Content string `json:"content"`
			} `json:"secretContent"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil || request.SecretName == "" {
			serviceError(w, http.StatusBadRequest, "InvalidParameter", "create needs a secret name")
			return
		}
		value, err := base64.StdEncoding.DecodeString(request.SecretContent.Content)
		if err != nil || len(value) == 0 {
			serviceError(w, http.StatusBadRequest, "InvalidParameter", "create needs base64 content")
			return
		}
		if !s.granted(r, request.VaultID, request.SecretName, true) {
			serviceError(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "caller may not create "+request.SecretName)
			return
		}
		if s.secrets[request.SecretName] != nil {
			serviceError(w, http.StatusConflict, "Conflict", "secret name already exists")
			return
		}
		digest := sha256.Sum256([]byte(request.SecretName))
		item := &secret{ID: "ocid1.vaultsecret.oc1." + vaultRegion + "." + hex.EncodeToString(digest[:12]), Name: request.SecretName, VaultID: request.VaultID, Versions: [][]byte{value}}
		s.secrets[item.Name] = item
		s.notify()
		w.Header().Set("etag", fmt.Sprint(len(item.Versions)))
		writeJSON(w, http.StatusOK, secretJSON(item))
	default:
		var item *secret
		for _, candidate := range s.secrets {
			if candidate.ID == id {
				item = candidate
			}
		}
		if item == nil || !s.granted(r, item.VaultID, item.Name, true) {
			serviceError(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "secret not found")
			return
		}
		if r.Method == http.MethodPut {
			if r.Header.Get("if-match") != fmt.Sprint(len(item.Versions)) {
				serviceError(w, http.StatusPreconditionFailed, "NoEtagMatch", "etag differs")
				return
			}
			var request struct {
				SecretContent struct {
					Content string `json:"content"`
				} `json:"secretContent"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
				serviceError(w, http.StatusBadRequest, "InvalidParameter", "update needs content")
				return
			}
			value, err := base64.StdEncoding.DecodeString(request.SecretContent.Content)
			if err != nil || len(value) == 0 {
				serviceError(w, http.StatusBadRequest, "InvalidParameter", "update needs base64 content")
				return
			}
			item.Versions = append(item.Versions, value)
			s.notify()
		} else if r.Method != http.MethodGet {
			serviceError(w, http.StatusMethodNotAllowed, "NotAllowed", r.Method)
			return
		}
		w.Header().Set("etag", fmt.Sprint(len(item.Versions)))
		writeJSON(w, http.StatusOK, secretJSON(item))
	}
}

func (s *standIn) jwks(w http.ResponseWriter) {
	public := s.signer.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "oracle-regions",
		"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}})
}

func (s *standIn) token(sha, run string) (string, error) {
	return s.identityToken(sha, run, nil)
}

func (s *standIn) identityToken(sha, run string, identity map[string]any) (string, error) {
	encode := func(v any) (string, error) {
		data, err := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(data), err
	}
	header, err := encode(map[string]string{"alg": "RS256", "kid": "oracle-regions", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	values := map[string]any{
		"iss": githubIssuer, "aud": "ts-orch", "exp": time.Now().Add(10 * time.Minute).Unix(), "nbf": time.Now().Add(-time.Minute).Unix(),
		"repository": "TerraScale/ts-orchestrator", "repository_owner": "TerraScale", "ref": "refs/heads/main",
		"sha": sha, "run_id": run, "run_attempt": "1", "event_name": "push", "job_workflow_ref": orchWorkflow,
	}
	for name, value := range identity {
		values[name] = value
	}
	claims, err := encode(values)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(header + "." + claims))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.signer, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return header + "." + claims + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *standIn) writeFiles(dir string) error {
	return os.WriteFile(filepath.Join(dir, "ca.pem"), s.caPEM, 0o644)
}

func (s *standIn) compute(w http.ResponseWriter, r *http.Request, region string) {
	query := r.URL.Query()
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/20160918/"), "/")
	var items []map[string]any
	s.mu.Lock()
	gone := maps.Clone(s.gone)
	s.mu.Unlock()
	for _, host := range s.hosts {
		if host.Region.OCIRegion != region || gone[host.InstanceID] || query.Has("compartmentId") && query.Get("compartmentId") != host.Region.CompartmentID {
			continue
		}
		vnic := "ocid1.vnic.oc1." + region + "." + host.Name
		switch {
		case path == "instances":
			tags := map[string]string{}
			document, err := fleet.Embedded().Region(host.Region.Name)
			if err != nil {
				serviceError(w, http.StatusInternalServerError, "InternalError", err.Error())
				return
			}
			if !slices.Contains(document.Nodes.External, host.Name) {
				tags = ociresource.Ownership{Owner: fleet.Owner}.Stamp(document.Key("instance", "node"), 1, "stand-in").Freeform
			}
			items = append(items, map[string]any{"id": host.InstanceID, "displayName": host.Name, "compartmentId": host.Region.CompartmentID,
				"region": region, "availabilityDomain": "stand-in:" + strings.ToUpper(region) + "-AD-1", "shape": "VM.Standard.A1.Flex",
				"lifecycleState": "RUNNING", "timeCreated": "2026-11-19T00:00:00Z", "freeformTags": tags})
		case path == "vnicAttachments" && query.Get("instanceId") == host.InstanceID:
			items = append(items, map[string]any{"id": "ocid1.vnicattachment.oc1." + region + "." + host.Name, "instanceId": host.InstanceID, "vnicId": vnic,
				"compartmentId": host.Region.CompartmentID, "availabilityDomain": "stand-in:" + strings.ToUpper(region) + "-AD-1", "lifecycleState": "ATTACHED",
				"timeCreated": "2026-11-19T00:00:00Z"})
		case path == "vnics/"+vnic:
			writeJSON(w, http.StatusOK, map[string]any{"id": vnic, "privateIp": host.Address, "isPrimary": true, "lifecycleState": "AVAILABLE",
				"compartmentId": host.Region.CompartmentID, "availabilityDomain": "stand-in:" + strings.ToUpper(region) + "-AD-1", "timeCreated": "2026-11-19T00:00:00Z"})
			return
		}
	}
	if path != "instances" && path != "vnicAttachments" {
		serviceError(w, http.StatusNotFound, "NotAuthorizedOrNotFound", "stand-in has no compute "+r.URL.Path)
		return
	}
	writeJSON(w, http.StatusOK, items)
}
