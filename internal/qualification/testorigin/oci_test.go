package testorigin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

const ociWireLimit = 8 << 20
const ociBodyLimit = 1 << 20
const ociStateDirectory = "/var/lib/terrascale-orchestrator-testorigin/oci"

// TargetFile is the signed reference's basename, never an alternate disk path.
type ociVaultEntry struct {
	SecretID      string   `json:"secretId"`
	VersionNumber int64    `json:"versionNumber"`
	VersionName   string   `json:"versionName"`
	Stages        []string `json:"stages"`
	Contents      []byte   `json:"contents"`
	TargetFile    string   `json:"targetFile"`
}

type ociMetadata struct {
	Descriptor                 []byte `json:"descriptor"`
	ControllerManifest         []byte `json:"controllerManifest"`
	Identity                   []byte `json:"identity"`
	Anchor                     []byte `json:"anchor"`
	HostEnrollment             []byte `json:"hostEnrollment"`
	OperatorSSHKey             []byte `json:"operatorSshKey"`
	ManagedHostImageReceipt    []byte `json:"managedHostImageReceipt"`
	ManagedHostImageDelegation []byte `json:"managedHostImageDelegation"`
}

// Only public signed discovery is seedable. Mutable foundation, birth, policy,
// acceptance and journal records must originate in actual authenticated writes.
type ociDiscovery struct {
	Prefix    string `json:"prefix"`
	RootChain []byte `json:"rootChain"`
	Anchor    []byte `json:"anchor"`
	Grant     []byte `json:"grant"`
}

type ociWire struct {
	SchemaVersion        int                           `json:"schemaVersion"`
	Region               string                        `json:"region"`
	TenancyID            string                        `json:"tenancyId"`
	Namespace            string                        `json:"namespace"`
	TLSCertificate       []byte                        `json:"tlsCertificate"`
	TLSKey               []byte                        `json:"tlsKey"`
	IdentityCertificate  []byte                        `json:"identityCertificate"`
	IdentityKey          []byte                        `json:"identityKey"`
	IdentityIntermediate []byte                        `json:"identityIntermediate"`
	IdentityRoot         []byte                        `json:"identityRoot"`
	OperatorUserID       string                        `json:"operatorUserId"`
	OperatorFingerprint  string                        `json:"operatorFingerprint"`
	OperatorPublicKey    []byte                        `json:"operatorPublicKey"`
	Tenancy              identity.Tenancy              `json:"tenancy"`
	FederationSigningKey []byte                        `json:"federationSigningKey"`
	Instance             core.Instance                 `json:"instance"`
	VNIC                 core.Vnic                     `json:"vnic"`
	VNICAttachment       core.VnicAttachment           `json:"vnicAttachment"`
	BootVolume           core.BootVolume               `json:"bootVolume"`
	BootVolumeAttachment core.BootVolumeAttachment     `json:"bootVolumeAttachment"`
	Image                core.Image                    `json:"image"`
	Buckets              []objectstorage.Bucket        `json:"buckets"`
	Subscriptions        []identity.RegionSubscription `json:"subscriptions"`
	Metadata             ociMetadata                   `json:"metadata"`
	Discovery            ociDiscovery                  `json:"discovery"`
	Vault                []ociVaultEntry               `json:"vault"`
}

type ociEvidence struct {
	Region                string `json:"region"`
	InstanceID            string `json:"instanceId"`
	AuthenticatedRequests uint64 `json:"authenticatedRequests"`
	Federations           uint64 `json:"federations"`
	VaultReads            uint64 `json:"vaultReads"`
	RejectedRequests      uint64 `json:"rejectedRequests"`
	ObjectWrites          uint64 `json:"objectWrites"`
	PolicyWrites          uint64 `json:"policyWrites"`
	JournalRecords        uint64 `json:"journalRecords"`
	JournalSHA256         string `json:"journalSha256"`
}

type ociSession struct {
	public  *rsa.PublicKey
	expires time.Time
}

type ociObject struct {
	body []byte
	etag string
}

type ociPolicy struct {
	value identity.Policy
	etag  string
	size  int
}

type ociPolicyRetry struct {
	request string
	id      string
}

type ociManagedSecret struct {
	value    vault.Secret
	contents []byte
	etag     string
}

type ociWorld struct {
	mu             sync.Mutex
	wire           ociWire
	leaf           *x509.Certificate
	issuer         *rsa.PrivateKey
	leafKeyID      string
	operatorPublic *rsa.PublicKey
	operatorKeyID  string
	stateBytes     int
	journalBytes   int
	sessions       map[string]ociSession
	objects        map[string]ociObject
	policies       map[string]ociPolicy
	groups         map[string]identity.DynamicGroup
	groupETags     map[string]string
	secrets        map[string]ociManagedSecret
	retries        map[string]ociPolicyRetry
	journal        *os.File
	journalSHA     hash.Hash
	evidence       ociEvidence
	ctx            context.Context
	servers        []*http.Server
	done           chan struct{}
	closeOnce      sync.Once
	closeErr       error
	failed         bool
	closed         bool
}

func decodeOCIWire(wire []byte) (ociWire, error) {
	var input ociWire
	valid := false
	defer func() {
		if !valid {
			input.clearSecrets()
		}
	}()
	if len(wire) == 0 || len(wire) > ociWireLimit || protocol.DecodeStrict(wire, &input, ociWireLimit) != nil ||
		input.SchemaVersion != 1 || !catalog.IsOCIRegion(input.Region) ||
		!strings.HasPrefix(input.TenancyID, "ocid1.tenancy.oc1..") || input.Namespace == "" || len(input.Namespace) > 256 || len(input.TenancyID) > 256 ||
		strings.ContainsAny(input.Namespace, "/\\\x00") || len(input.Vault) > 256 || len(input.Buckets) == 0 || len(input.Buckets) > 8 || len(input.Subscriptions) > 64 {
		return ociWire{}, errors.New("invalid bounded test-origin OCI input")
	}
	seenBuckets := map[string]bool{}
	for _, bucket := range input.Buckets {
		if bucket.Name == nil || *bucket.Name == "" || len(*bucket.Name) > 256 || strings.ContainsAny(*bucket.Name, "/\\\x00") ||
			bucket.Namespace == nil || *bucket.Namespace != input.Namespace || seenBuckets[*bucket.Name] {
			return ociWire{}, errors.New("invalid or duplicate concrete OCI bucket")
		}
		seenBuckets[*bucket.Name] = true
	}
	if !seenBuckets["gru-1-head"] {
		return ociWire{}, errors.New("public home discovery bucket is absent")
	}
	seenTargets, seenVersions := map[string]bool{}, map[string]bool{}
	for _, secret := range input.Vault {
		version := secret.SecretID + "/" + strconv.FormatInt(secret.VersionNumber, 10)
		if !strings.HasPrefix(secret.SecretID, "ocid1.vaultsecret.oc1."+input.Region+".") || secret.VersionNumber <= 0 ||
			secret.TargetFile == "" || secret.TargetFile == "." || secret.TargetFile == ".." ||
			filepath.Base(secret.TargetFile) != secret.TargetFile || strings.ContainsAny(secret.TargetFile, "\\\x00") ||
			len(secret.Contents) == 0 || len(secret.Contents) > bootstrap.MaxSecretBytes ||
			seenTargets[secret.TargetFile] || seenVersions[version] || len(secret.Stages) == 0 || len(secret.Stages) > 5 {
			return ociWire{}, errors.New("invalid or duplicate exact Vault reference")
		}
		seenTargets[secret.TargetFile], seenVersions[version] = true, true
		seenStage := map[string]bool{}
		for _, stage := range secret.Stages {
			if !slices.Contains([]string{"CURRENT", "PENDING", "PREVIOUS", "DEPRECATED", "LATEST"}, stage) || seenStage[stage] {
				return ociWire{}, errors.New("invalid Vault version stage")
			}
			seenStage[stage] = true
		}
	}
	valid = true
	return input, nil
}

func validateOCIVaultMaterial(wire []byte, entries []ociVaultEntry) error {
	input, err := decodeOCIWire(wire)
	defer input.clearSecrets()
	if err != nil || len(entries) == 0 || len(entries) > 256 {
		return errors.New("test-origin Vault material binding is absent")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if seen[entry.TargetFile] {
			return errors.New("duplicate NATS material binding")
		}
		seen[entry.TargetFile] = true
		found := false
		for _, secret := range input.Vault {
			if entry.TargetFile != secret.TargetFile {
				continue
			}
			if entry.SecretID != secret.SecretID || entry.VersionNumber != secret.VersionNumber || entry.VersionName != secret.VersionName ||
				!slices.Equal(entry.Stages, secret.Stages) || !bytes.Equal(entry.Contents, secret.Contents) {
				return errors.New("NATS material differs from the exact Vault version")
			}
			found = true
			break
		}
		if !found {
			return errors.New("NATS material has no exact Vault reference")
		}
	}
	return nil
}

func (input *ociWire) clearSecrets() {
	clear(input.TLSKey)
	clear(input.IdentityKey)
	clear(input.FederationSigningKey)
	for _, secret := range input.Vault {
		clear(secret.Contents)
	}
}

func startOCIWorld(ctx context.Context, wire []byte) (_ *ociWorld, err error) {
	if ctx == nil {
		return nil, errors.New("OCI world requires a finite context")
	}
	deadline, bounded := ctx.Deadline()
	if os.Geteuid() != 0 || ctx.Err() != nil || !bounded || !time.Now().Before(deadline) || time.Until(deadline) > 120*time.Second {
		return nil, errors.New("OCI world requires the original finite root context")
	}
	input, err := decodeOCIWire(wire)
	if err != nil {
		return nil, err
	}
	world := &ociWorld{wire: input, ctx: ctx, sessions: map[string]ociSession{}, objects: map[string]ociObject{},
		policies: map[string]ociPolicy{}, groups: map[string]identity.DynamicGroup{}, groupETags: map[string]string{}, secrets: map[string]ociManagedSecret{},
		retries: map[string]ociPolicyRetry{}, journalSHA: sha256.New(), done: make(chan struct{})}
	defer func() {
		if err != nil {
			_ = world.Close()
		}
	}()
	pair, err := tls.X509KeyPair(input.TLSCertificate, input.TLSKey)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, errors.New("OCI world TLS identity is invalid")
	}
	serverCertificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || time.Now().Before(serverCertificate.NotBefore) || !deadline.Before(serverCertificate.NotAfter) {
		return nil, errors.New("OCI world TLS certificate does not cover the original context")
	}
	for _, host := range world.hosts() {
		if serverCertificate.VerifyHostname(host) != nil {
			return nil, errors.New("OCI world TLS certificate lacks an ordinary service hostname")
		}
	}
	identityPair, err := tls.X509KeyPair(input.IdentityCertificate, input.IdentityKey)
	if err != nil || len(identityPair.Certificate) != 1 {
		return nil, errors.New("OCI IMDS instance identity is invalid")
	}
	world.leaf, err = x509.ParseCertificate(identityPair.Certificate[0])
	if err != nil {
		return nil, errors.New("OCI IMDS certificate cannot be parsed")
	}
	if public, ok := world.leaf.PublicKey.(*rsa.PublicKey); !ok || public.N.BitLen() < 2048 || public.N.BitLen() > 8192 {
		return nil, errors.New("OCI instance identity must use an RSA public key")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(input.IdentityRoot) || !intermediates.AppendCertsFromPEM(input.IdentityIntermediate) {
		return nil, errors.New("OCI instance certificate chain is absent")
	}
	if _, err := world.leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil || !deadline.Before(world.leaf.NotAfter) {
		return nil, errors.New("OCI instance certificate chain is not currently valid")
	}
	tenant := false
	for _, name := range world.leaf.Subject.Names {
		if name.Value == "opc-tenant:"+input.TenancyID {
			tenant = true
		}
	}
	if !tenant || input.Instance.Id == nil || input.Instance.CompartmentId == nil || input.Instance.AvailabilityDomain == nil ||
		input.Instance.FaultDomain == nil || input.VNIC.Id == nil || input.Image.Id == nil || input.BootVolume.Id == nil ||
		!strings.HasPrefix(*input.Instance.Id, "ocid1.instance.oc1."+input.Region+".") {
		return nil, errors.New("OCI instance tenancy or resource identity is absent")
	}
	if err := world.configureOperator(); err != nil {
		return nil, err
	}
	world.issuer, err = ociRSAKey(input.FederationSigningKey)
	if err != nil {
		return nil, err
	}
	fingerprint := fmt.Sprintf("% x", sha256.Sum256(world.leaf.Raw))
	world.leafKeyID = input.TenancyID + "/fed-x509-sha256/" + strings.ReplaceAll(fingerprint, " ", ":")
	world.evidence.Region, world.evidence.InstanceID = input.Region, *input.Instance.Id
	world.journal, err = openOCIJournal()
	if err != nil {
		return nil, err
	}
	if err := world.seedDiscovery(); err != nil {
		return nil, err
	}
	// Fixed listeners require the separately reviewed private network, DNS and
	// system-CA realm. No transport override or host namespace setup occurs here.
	imds, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "169.254.169.254:80")
	if err != nil {
		return nil, errors.New("fixed OCI IMDS listener is unavailable")
	}
	imdsServer := world.server(http.HandlerFunc(world.serveIMDS))
	world.servers = append(world.servers, imdsServer)
	go world.serve(imdsServer, imds)
	https, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:443")
	if err != nil {
		return nil, errors.New("fixed OCI TLS listener is unavailable")
	}
	httpsServer := world.server(http.HandlerFunc(world.serveOCI))
	httpsServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	world.servers = append(world.servers, httpsServer)
	go world.serve(httpsServer, tls.NewListener(https, httpsServer.TLSConfig))
	go func() {
		select {
		case <-ctx.Done():
			_ = world.Close()
		case <-world.done:
		}
	}()
	return world, nil
}

func (world *ociWorld) hosts() []string {
	region := world.wire.Region
	return []string{"auth." + region + ".oraclecloud.com", "iaas." + region + ".oraclecloud.com",
		"identity." + region + ".oci.oraclecloud.com", "objectstorage." + region + ".oraclecloud.com",
		"secrets.vaults." + region + ".oci.oraclecloud.com", "vaults." + region + ".oci.oraclecloud.com"}
}

func (world *ociWorld) server(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 64 << 10,
		ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return world.ctx }}
}

func ociRSAKey(wire []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(wire)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("test federation signing key is absent")
	}
	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		parsed, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.Validate() != nil {
		return nil, errors.New("test federation signing key is invalid")
	}
	return key, nil
}

func openOCIDirectory() (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = unix.Close(fd)
		}
	}()
	// The later namespace packet creates this directory. Never create or cover
	// host ancestors here, follow a symlink, or reuse a successful old journal.
	for component := range strings.SplitSeq(strings.TrimPrefix(ociStateDirectory, "/"), "/") {
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return -1, errors.New("private OCI journal directory is absent")
		}
		_ = unix.Close(fd)
		fd = next
		var info unix.Stat_t
		if unix.Fstat(fd, &info) != nil || info.Uid != 0 || info.Gid != 0 || info.Mode&0o022 != 0 {
			return -1, errors.New("private OCI journal ancestors are unsafe")
		}
	}
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&0o7777 != 0o700 {
		return -1, errors.New("private OCI directory must have mode0700")
	}
	complete = true
	return fd, nil
}

func openOCIJournal() (*os.File, error) {
	fd, err := openOCIDirectory()
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	journalFD, err := unix.Openat(fd, "journal.jsonl", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("OCI journal must be a fresh private file")
	}
	var info unix.Stat_t
	if unix.Fstat(journalFD, &info) != nil || info.Uid != 0 || info.Gid != 0 || info.Mode&0o7777 != 0o600 || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Nlink != 1 {
		_ = unix.Close(journalFD)
		return nil, errors.New("fresh OCI journal has unsafe ownership or mode")
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(journalFD)
		return nil, err
	}
	return os.NewFile(uintptr(journalFD), "test-origin-oci-journal"), nil
}

func (world *ociWorld) record(kind, key string, body []byte) (string, error) {
	if world.failed || world.closed || world.ctx.Err() != nil || world.journal == nil {
		return "", errors.New("OCI journal is unavailable")
	}
	entry := struct {
		Sequence uint64 `json:"sequence"`
		Kind     string `json:"kind"`
		Key      string `json:"key"`
		Body     []byte `json:"body"`
	}{world.evidence.JournalRecords + 1, kind, key, body}
	wire, err := json.Marshal(entry, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	wire = append(wire, '\n')
	defer clear(wire)
	if world.evidence.JournalRecords >= 4096 || world.journalBytes+len(wire) > 64<<20 {
		world.failed = true
		return "", errors.New("OCI mutation journal bound reached")
	}
	n, writeErr := world.journal.Write(wire)
	if writeErr != nil || n != len(wire) || world.journal.Sync() != nil {
		world.failed = true
		return "", errors.New("OCI journal write did not durably complete")
	}
	_, _ = world.journalSHA.Write(wire)
	world.evidence.JournalRecords++
	world.journalBytes += len(wire)
	return fmt.Sprintf("\"%x\"", sha256.Sum256(wire)), nil
}

func (world *ociWorld) seedDiscovery() error {
	discovery := world.wire.Discovery
	if discovery.Prefix == "" || strings.HasPrefix(discovery.Prefix, "/") || strings.Contains(discovery.Prefix, "..") ||
		len(discovery.Prefix) > 4096 || len(discovery.RootChain) == 0 || len(discovery.RootChain) > ociBodyLimit ||
		len(discovery.Anchor) == 0 || len(discovery.Anchor) > ociBodyLimit || len(discovery.Grant) == 0 || len(discovery.Grant) > ociBodyLimit {
		return errors.New("public signed OCI discovery inputs are absent")
	}
	for _, seed := range []struct {
		name string
		body []byte
	}{
		{"orchestrator/foundation/v1/root-chain.json", discovery.RootChain},
		{"orchestrator/foundation/v1/anchor.json", discovery.Anchor},
		{strings.TrimSuffix(discovery.Prefix, "/") + "/foundation-scope-v1.json", discovery.Grant},
	} {
		key := "gru-1-head/" + seed.name
		etag, err := world.record("public-discovery-seed", key, seed.body)
		if err != nil {
			return err
		}
		world.objects[key] = ociObject{body: bytes.Clone(seed.body), etag: etag}
		world.stateBytes += len(seed.body)
	}
	return nil
}

func (world *ociWorld) Close() error {
	if world == nil {
		return nil
	}
	world.closeOnce.Do(func() {
		if world.done != nil {
			close(world.done)
		}
		for _, server := range world.servers {
			world.closeErr = errors.Join(world.closeErr, server.Close())
		}
		world.mu.Lock()
		defer world.mu.Unlock()
		world.closed = true
		if world.failed {
			world.closeErr = errors.Join(world.closeErr, errors.New("OCI world observed a server or journal failure"))
		}
		if world.journal != nil {
			world.closeErr = errors.Join(world.closeErr, world.journal.Sync(), world.journal.Close())
		}
		world.wire.clearSecrets()
		clear(world.sessions)
		for _, object := range world.objects {
			clear(object.body)
		}
		clear(world.objects)
		clear(world.policies)
		clear(world.groups)
		clear(world.groupETags)
		for _, secret := range world.secrets {
			clear(secret.contents)
		}
		clear(world.secrets)
		clear(world.retries)
	})
	return world.closeErr
}

func (world *ociWorld) Evidence() (ociEvidence, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	if world.closed || world.failed || world.ctx.Err() != nil || world.evidence.JournalRecords == 0 {
		return ociEvidence{}, errors.New("OCI evidence is unavailable")
	}
	evidence := world.evidence
	evidence.JournalSHA256 = hex.EncodeToString(world.journalSHA.Sum(nil))
	return evidence, nil
}

func ociJSON(w http.ResponseWriter, status int, value any) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		http.Error(w, "OCI response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(wire)
}

func (world *ociWorld) reject(w http.ResponseWriter, status int) {
	world.evidence.RejectedRequests++
	ociJSON(w, status, struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{"NotAuthorizedOrNotFound", "test-origin OCI request refused"})
}

func (world *ociWorld) serveIMDS(w http.ResponseWriter, request *http.Request) {
	world.mu.Lock()
	defer world.mu.Unlock()
	if world.closed || world.failed || world.ctx.Err() != nil || request.Method != http.MethodGet ||
		request.Host != "169.254.169.254" || request.Header.Get("Authorization") != "Bearer Oracle" || request.URL.RawQuery != "" {
		world.reject(w, http.StatusUnauthorized)
		return
	}
	var body []byte
	switch request.URL.Path {
	case "/opc/v2/instance/region":
		body = []byte(world.wire.Region)
	case "/opc/v2/instance/id":
		body = []byte(*world.wire.Instance.Id)
	case "/opc/v2/instance/availabilityDomain":
		body = []byte(*world.wire.Instance.AvailabilityDomain)
	case "/opc/v2/instance/faultDomain":
		body = []byte(*world.wire.Instance.FaultDomain)
	case "/opc/v2/identity/cert.pem":
		body = world.wire.IdentityCertificate
	case "/opc/v2/identity/key.pem":
		body = world.wire.IdentityKey
	case "/opc/v2/identity/intermediate.pem":
		body = world.wire.IdentityIntermediate
	case "/opc/v2/instance/metadata/terrascale-bootstrap":
		body = world.wire.Metadata.Descriptor
	case "/opc/v2/instance/metadata/terrascale-controller-manifest-v1":
		body = world.wire.Metadata.ControllerManifest
	case "/opc/v2/instance/metadata/" + bootstrapstart.IdentityMetadataKey:
		body = world.wire.Metadata.Identity
	case "/opc/v2/instance/metadata/" + bootstrapstart.AnchorMetadataKey:
		body = world.wire.Metadata.Anchor
	case "/opc/v2/instance/metadata/" + hostboot.EnrollmentMetadataKey:
		body = world.wire.Metadata.HostEnrollment
	case "/opc/v2/instance/metadata/" + bootstrapstart.OperatorSSHKeyMetadataKey:
		body = world.wire.Metadata.OperatorSSHKey
	case "/opc/v2/instance/metadata/" + bootstrapstart.ManagedHostImageReceiptMetadataKey:
		body = world.wire.Metadata.ManagedHostImageReceipt
	case "/opc/v2/instance/metadata/" + bootstrapstart.ManagedHostImageDelegationMetadataKey:
		body = world.wire.Metadata.ManagedHostImageDelegation
	default:
		world.reject(w, http.StatusNotFound)
		return
	}
	if len(body) == 0 {
		world.reject(w, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(body)
}

func (world *ociWorld) serveOCI(w http.ResponseWriter, request *http.Request) {
	world.mu.Lock()
	defer world.mu.Unlock()
	host := strings.TrimSuffix(request.Host, ":443")
	if world.closed || world.failed || world.ctx.Err() != nil || request.Context().Err() != nil ||
		request.TLS == nil || request.TLS.ServerName != host || !slices.Contains(world.hosts(), host) {
		world.reject(w, http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, ociBodyLimit+1))
	defer clear(body)
	if err != nil || len(body) > ociBodyLimit {
		world.reject(w, http.StatusRequestEntityTooLarge)
		return
	}
	if host == "auth."+world.wire.Region+".oraclecloud.com" {
		world.serveFederation(w, request, body)
		return
	}
	keyID, err := ociSignatureKeyID(request)
	var public *rsa.PublicKey
	operator := keyID == world.operatorKeyID
	if operator {
		public = world.operatorPublic
	} else if strings.HasPrefix(keyID, "ST$") {
		session, ok := world.sessions[strings.TrimPrefix(keyID, "ST$")]
		if ok && time.Now().Before(session.expires) {
			public = session.public
		}
	}
	if err != nil || public == nil || verifyOCISignature(request, body, keyID, public, true) != nil {
		world.reject(w, http.StatusUnauthorized)
		return
	}
	// A valid federation session proves identity, never permission. Evaluate the
	// current operator-created policy and dynamic-group state for every request.
	if !operator && !world.authorizeInstance(request, body) {
		world.reject(w, http.StatusForbidden)
		return
	}
	world.evidence.AuthenticatedRequests++
	switch host {
	case "iaas." + world.wire.Region + ".oraclecloud.com":
		world.serveCompute(w, request)
	case "objectstorage." + world.wire.Region + ".oraclecloud.com":
		world.serveObjects(w, request, body)
	case "identity." + world.wire.Region + ".oci.oraclecloud.com":
		world.serveIAM(w, request, body)
	case "secrets.vaults." + world.wire.Region + ".oci.oraclecloud.com":
		if !world.serveManagedBundle(w, request) {
			world.serveVault(w, request)
		}
	case "vaults." + world.wire.Region + ".oci.oraclecloud.com":
		world.serveManagedSecrets(w, request, body)
	default:
		world.reject(w, http.StatusNotFound)
	}
}

func ociSignatureFields(request *http.Request) (map[string]string, error) {
	prefix, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Signature ")
	if !ok {
		return nil, errors.New("OCI signature is absent")
	}
	fields := map[string]string{}
	for item := range strings.SplitSeq(prefix, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || fields[name] != "" || !slices.Contains([]string{"version", "keyId", "algorithm", "headers", "signature"}, name) {
			return nil, errors.New("OCI signature fields are invalid")
		}
		decoded, err := strconv.Unquote(value)
		if err != nil || decoded == "" {
			return nil, errors.New("OCI signature value is invalid")
		}
		fields[name] = decoded
	}
	if len(fields) != 5 || fields["version"] != "1" || fields["algorithm"] != "rsa-sha256" {
		return nil, errors.New("OCI signature algorithm is invalid")
	}
	return fields, nil
}

func ociSignatureKeyID(request *http.Request) (string, error) {
	fields, err := ociSignatureFields(request)
	return fields["keyId"], err
}

func verifyOCISignature(request *http.Request, body []byte, keyID string, public *rsa.PublicKey, requireHost bool) error {
	fields, err := ociSignatureFields(request)
	if err != nil || public == nil || fields["keyId"] != keyID {
		return errors.New("OCI request signer differs from its session")
	}
	seen := map[string]bool{}
	var lines []string
	for name := range strings.FieldsSeq(fields["headers"]) {
		if seen[name] {
			return errors.New("duplicate OCI signed header")
		}
		seen[name] = true
		var value string
		switch name {
		case "(request-target)":
			value = strings.ToLower(request.Method) + " " + request.URL.RequestURI()
		case "host":
			value = request.Host
		case "content-length":
			value = strconv.FormatInt(request.ContentLength, 10)
		case "date", "x-date", "content-type", "x-content-sha256":
			if len(request.Header.Values(name)) != 1 {
				return errors.New("OCI signed header is absent or repeated")
			}
			value = request.Header.Get(name)
		default:
			return errors.New("unrecognized OCI signed header")
		}
		lines = append(lines, name+": "+value)
	}
	if !seen["(request-target)"] || requireHost && !seen["host"] || !seen["date"] && !seen["x-date"] {
		return errors.New("required OCI signed headers are absent")
	}
	dateHeader := "date"
	if seen["x-date"] {
		dateHeader = "x-date"
	}
	date, err := http.ParseTime(request.Header.Get(dateHeader))
	if err != nil || time.Since(date) > time.Minute || time.Until(date) > time.Minute {
		return errors.New("OCI request date is stale")
	}
	if request.Method == http.MethodPost || request.Method == http.MethodPut || request.Method == http.MethodPatch {
		// The vendored SDK signs PutObject's generic headers only.
		objectPut := request.Method == http.MethodPut && strings.HasPrefix(request.Host, "objectstorage.") && strings.HasPrefix(request.URL.Path, "/n/") && strings.Contains(request.URL.Path, "/o/")
		if objectPut && !seen["content-length"] && !seen["content-type"] && !seen["x-content-sha256"] {
			if request.ContentLength != int64(len(body)) {
				return errors.New("OCI object body length is invalid")
			}
		} else {
			digest := sha256.Sum256(body)
			if !seen["content-length"] || !seen["content-type"] || !seen["x-content-sha256"] ||
				request.ContentLength != int64(len(body)) || request.Header.Get("X-Content-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
				return errors.New("OCI request body digest is invalid")
			}
		}
	} else if len(body) != 0 {
		return errors.New("unexpected OCI request body")
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	if err != nil || rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
		return errors.New("OCI request signature is invalid")
	}
	return nil
}

func (world *ociWorld) serveFederation(w http.ResponseWriter, request *http.Request, body []byte) {
	public, ok := world.leaf.PublicKey.(*rsa.PublicKey)
	if !ok || request.Method != http.MethodPost || request.URL.Path != "/v1/x509" || request.URL.RawQuery != "" ||
		verifyOCISignature(request, body, world.leafKeyID, public, false) != nil {
		world.reject(w, http.StatusUnauthorized)
		return
	}
	var federation struct {
		Certificate              string   `json:"certificate"`
		PublicKey                string   `json:"publicKey"`
		IntermediateCertificates []string `json:"intermediateCertificates"`
		FingerprintAlgorithm     string   `json:"fingerprintAlgorithm"`
	}
	if protocol.DecodeStrict(body, &federation, ociBodyLimit) != nil || federation.FingerprintAlgorithm != "SHA256" || len(federation.IntermediateCertificates) != 1 {
		world.reject(w, http.StatusBadRequest)
		return
	}
	certificate, certErr := base64.StdEncoding.DecodeString(federation.Certificate)
	intermediate, intermediateErr := base64.StdEncoding.DecodeString(federation.IntermediateCertificates[0])
	configuredIntermediate, _ := pem.Decode(world.wire.IdentityIntermediate)
	sessionDER, publicErr := base64.StdEncoding.DecodeString(federation.PublicKey)
	if certErr != nil || intermediateErr != nil || publicErr != nil || configuredIntermediate == nil ||
		!bytes.Equal(certificate, world.leaf.Raw) || !bytes.Equal(intermediate, configuredIntermediate.Bytes) {
		world.reject(w, http.StatusUnauthorized)
		return
	}
	parsed, err := x509.ParsePKIXPublicKey(sessionDER)
	sessionPublic, rsaKey := parsed.(*rsa.PublicKey)
	if err != nil || !rsaKey || sessionPublic.N.BitLen() < 2048 || sessionPublic.N.BitLen() > 8192 || world.ctx.Err() != nil || request.Context().Err() != nil {
		world.reject(w, http.StatusUnauthorized)
		return
	}
	deadline, _ := world.ctx.Deadline()
	expires := min(deadline.Unix(), world.leaf.NotAfter.Unix())
	if expires <= time.Now().Unix() || len(world.sessions) >= 256 {
		world.reject(w, http.StatusServiceUnavailable)
		return
	}
	claims := struct {
		Subject  string `json:"sub"`
		Instance string `json:"opc-instance"`
		Type     string `json:"ptype"`
		Tenancy  string `json:"tenant"`
		IssuedAt int64  `json:"iat"`
		Expiry   int64  `json:"exp"`
		Session  string `json:"sessionSha256"`
	}{*world.wire.Instance.Id, *world.wire.Instance.Id, "instance", world.wire.TenancyID,
		time.Now().Unix(), expires, fmt.Sprintf("%x", sha256.Sum256(sessionDER))}
	payload, err := json.Marshal(claims, json.Deterministic(true))
	if err != nil {
		world.reject(w, http.StatusInternalServerError)
		return
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, world.issuer, crypto.SHA256, digest[:])
	if err != nil {
		world.reject(w, http.StatusInternalServerError)
		return
	}
	token := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	world.sessions[token] = ociSession{public: sessionPublic, expires: time.Unix(expires, 0)}
	world.evidence.Federations++
	ociJSON(w, http.StatusOK, struct {
		Token string `json:"token"`
	}{token})
}

func (world *ociWorld) serveCompute(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		world.reject(w, http.StatusNotImplemented)
		return
	}
	input := world.wire
	path := request.URL.Path
	if request.URL.RawQuery == "" {
		switch path {
		case "/20160918/instances/" + *input.Instance.Id:
			ociJSON(w, http.StatusOK, input.Instance)
			return
		case "/20160918/vnics/" + *input.VNIC.Id:
			ociJSON(w, http.StatusOK, input.VNIC)
			return
		case "/20160918/images/" + *input.Image.Id:
			ociJSON(w, http.StatusOK, input.Image)
			return
		case "/20160918/bootVolumes/" + *input.BootVolume.Id:
			ociJSON(w, http.StatusOK, input.BootVolume)
			return
		}
	}
	query := request.URL.Query()
	if query.Get("compartmentId") != *input.Instance.CompartmentId || query.Get("instanceId") != *input.Instance.Id || query.Get("page") != "" {
		world.reject(w, http.StatusNotFound)
		return
	}
	switch path {
	case "/20160918/vnicAttachments":
		ociJSON(w, http.StatusOK, []core.VnicAttachment{input.VNICAttachment})
	case "/20160918/bootVolumeAttachments":
		if query.Get("availabilityDomain") != *input.Instance.AvailabilityDomain {
			world.reject(w, http.StatusNotFound)
			return
		}
		ociJSON(w, http.StatusOK, []core.BootVolumeAttachment{input.BootVolumeAttachment})
	default:
		world.reject(w, http.StatusNotFound)
	}
}

func (world *ociWorld) serveVault(w http.ResponseWriter, request *http.Request) {
	secretID, ok := strings.CutPrefix(request.URL.Path, "/20190301/secretbundles/")
	if !ok || request.Method != http.MethodGet || strings.Contains(secretID, "/") {
		world.reject(w, http.StatusNotFound)
		return
	}
	query := request.URL.Query()
	version, err := strconv.ParseInt(query.Get("versionNumber"), 10, 64)
	if err != nil || version <= 0 {
		world.reject(w, http.StatusBadRequest)
		return
	}
	for name, values := range query {
		if !slices.Contains([]string{"versionNumber", "secretVersionName", "stage"}, name) || len(values) != 1 {
			world.reject(w, http.StatusBadRequest)
			return
		}
	}
	for _, entry := range world.wire.Vault {
		if entry.SecretID != secretID || entry.VersionNumber != version {
			continue
		}
		if query.Get("secretVersionName") != "" && query.Get("secretVersionName") != entry.VersionName ||
			query.Get("stage") != "" && !slices.Contains(entry.Stages, query.Get("stage")) {
			world.reject(w, http.StatusNotFound)
			return
		}
		world.evidence.VaultReads++
		ociJSON(w, http.StatusOK, struct {
			SecretID      string   `json:"secretId"`
			VersionNumber int64    `json:"versionNumber"`
			VersionName   string   `json:"versionName"`
			Stages        []string `json:"stages"`
			Content       struct {
				ContentType string `json:"contentType"`
				Content     string `json:"content"`
			} `json:"secretBundleContent"`
		}{entry.SecretID, entry.VersionNumber, entry.VersionName, entry.Stages,
			struct {
				ContentType string `json:"contentType"`
				Content     string `json:"content"`
			}{"BASE64", base64.StdEncoding.EncodeToString(entry.Contents)}})
		return
	}
	world.reject(w, http.StatusNotFound)
}

func (world *ociWorld) configureOperator() error {
	input := &world.wire
	block, rest := pem.Decode(input.OperatorPublicKey)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 ||
		!strings.HasPrefix(input.OperatorUserID, "ocid1.user.oc1..") || len(input.OperatorUserID) > 256 ||
		input.Tenancy.Id == nil || *input.Tenancy.Id != input.TenancyID {
		return errors.New("test operator public identity or tenancy is absent")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok || public.N.BitLen() < 2048 || public.N.BitLen() > 8192 || public.E < 3 {
		return errors.New("test operator public key is invalid")
	}
	// OCI defines this identifier as MD5 of the public DER; authentication uses RSA-SHA256.
	fingerprint := strings.ReplaceAll(fmt.Sprintf("% x", md5.Sum(block.Bytes)), " ", ":")
	if input.OperatorFingerprint != fingerprint {
		return errors.New("test operator fingerprint differs from its public key")
	}
	if _, err := ociclient.TenancyHomeRegion(input.Tenancy.HomeRegionKey); err != nil {
		return err
	}
	world.operatorPublic = public
	world.operatorKeyID = input.TenancyID + "/" + input.OperatorUserID + "/" + fingerprint
	return nil
}

// OperatorFactory is called only after the caller verifies the public retained bundle.
// It never consults HOME, OCI config profiles, alternate paths or production keys.
func (world *ociWorld) OperatorFactory() (*ociclient.Factory, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	if world.closed || world.failed || world.ctx.Err() != nil || world.operatorPublic == nil {
		return nil, errors.New("test operator world is unavailable")
	}
	dir, err := openOCIDirectory()
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dir) }()
	fd, err := unix.Openat(dir, "operator-key.pem", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("fixed test operator key is absent")
	}
	file := os.NewFile(uintptr(fd), "test-origin-operator-key")
	defer func() { _ = file.Close() }()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Gid != 0 || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&0o7777 != 0o600 || before.Nlink != 1 || before.Size <= 0 || before.Size > 64<<10 {
		return nil, errors.New("fixed test operator key custody is invalid")
	}
	wire, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	defer clear(wire)
	if err != nil || int64(len(wire)) != before.Size || unix.Fstat(fd, &after) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Nlink != after.Nlink ||
		before.Uid != after.Uid || before.Gid != after.Gid || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || world.ctx.Err() != nil {
		return nil, errors.New("fixed test operator key read did not remain stable")
	}
	key, err := ociRSAKey(wire)
	if err != nil || !key.PublicKey.Equal(world.operatorPublic) {
		return nil, errors.New("fixed test operator key differs from the public request signer")
	}
	provider := common.NewRawConfigurationProvider(world.wire.TenancyID, world.wire.OperatorUserID,
		world.wire.Region, world.wire.OperatorFingerprint, string(wire), nil)
	return ociclient.New(provider, ociclient.Options{Region: world.wire.Region})
}

func (world *ociWorld) serve(server *http.Server, listener net.Listener) {
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		world.mu.Lock()
		if !world.closed {
			world.failed = true
		}
		world.mu.Unlock()
	}
}

func (world *ociWorld) serveObjects(w http.ResponseWriter, request *http.Request, body []byte) {
	if request.Method == http.MethodGet && request.URL.Path == "/n" {
		query := request.URL.Query()
		if request.URL.RawQuery != "" && (len(query) != 1 || len(query["compartmentId"]) != 1 || query.Get("compartmentId") != world.wire.TenancyID) {
			world.reject(w, http.StatusBadRequest)
			return
		}
		ociJSON(w, http.StatusOK, world.wire.Namespace)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(request.URL.Path, "/"), "/", 6)
	if len(parts) < 4 || parts[0] != "n" || parts[1] != world.wire.Namespace || parts[2] != "b" || request.URL.RawQuery != "" {
		world.reject(w, http.StatusNotFound)
		return
	}
	var bucket *objectstorage.Bucket
	for index := range world.wire.Buckets {
		value := &world.wire.Buckets[index]
		if value.Name != nil && *value.Name == parts[3] {
			bucket = value
			break
		}
	}
	if bucket == nil {
		world.reject(w, http.StatusNotFound)
		return
	}
	if len(parts) == 4 && request.Method == http.MethodGet {
		ociJSON(w, http.StatusOK, *bucket)
		return
	}
	if len(parts) != 6 || parts[4] != "o" || parts[5] == "" || len(parts[5]) > 4096 || strings.ContainsRune(parts[5], '\x00') {
		world.reject(w, http.StatusNotImplemented)
		return
	}
	key := parts[3] + "/" + parts[5]
	object, exists := world.objects[key]
	if request.Method == http.MethodGet || request.Method == http.MethodHead {
		if !exists {
			world.reject(w, http.StatusNotFound)
			return
		}
		if match := request.Header.Get("If-Match"); match != "" && match != object.etag {
			world.reject(w, http.StatusPreconditionFailed)
			return
		}
		w.Header().Set("ETag", object.etag)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
		if request.Method == http.MethodGet {
			_, _ = w.Write(object.body)
		}
		return
	}
	if request.Method != http.MethodPut && request.Method != http.MethodDelete {
		world.reject(w, http.StatusNotImplemented)
		return
	}
	if request.Context().Err() != nil {
		world.reject(w, http.StatusRequestTimeout)
		return
	}
	if len(request.Header.Values("If-Match")) > 1 || len(request.Header.Values("If-None-Match")) > 1 {
		world.reject(w, http.StatusPreconditionFailed)
		return
	}
	if exists {
		if request.Header.Get("If-Match") != object.etag || request.Header.Get("If-None-Match") != "" {
			world.reject(w, http.StatusPreconditionFailed)
			return
		}
	} else if request.Method != http.MethodPut || request.Header.Get("If-None-Match") != "*" || request.Header.Get("If-Match") != "" {
		world.reject(w, http.StatusPreconditionFailed)
		return
	}
	if request.Method == http.MethodDelete {
		if _, err := world.record("object-delete", key, nil); err != nil {
			world.reject(w, http.StatusServiceUnavailable)
			return
		}
		world.stateBytes -= len(object.body)
		clear(object.body)
		delete(world.objects, key)
		world.evidence.ObjectWrites++
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !exists && len(world.objects) >= 512 || world.stateBytes-len(object.body)+len(body) > 16<<20 {
		world.reject(w, http.StatusInsufficientStorage)
		return
	}
	etag, err := world.record("object-put", key, body)
	if err != nil {
		world.reject(w, http.StatusServiceUnavailable)
		return
	}
	world.stateBytes += len(body) - len(object.body)
	clear(object.body)
	world.objects[key] = ociObject{body: bytes.Clone(body), etag: etag}
	world.evidence.ObjectWrites++
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (world *ociWorld) serveIAM(w http.ResponseWriter, request *http.Request, body []byte) {
	path := request.URL.Path
	if strings.HasPrefix(path, "/20160918/dynamicGroups") {
		world.serveDynamicGroups(w, request, body)
		return
	}
	if request.Method == http.MethodGet && request.URL.RawQuery == "" && path == "/20160918/tenancies/"+world.wire.TenancyID {
		ociJSON(w, http.StatusOK, world.wire.Tenancy)
		return
	}
	if request.Method == http.MethodGet && request.URL.RawQuery == "" && path == "/20160918/tenancies/"+world.wire.TenancyID+"/regionSubscriptions" {
		ociJSON(w, http.StatusOK, world.wire.Subscriptions)
		return
	}
	if path == "/20160918/policies" {
		if request.Method == http.MethodPost && request.URL.RawQuery == "" {
			world.createPolicy(w, request, body)
			return
		}
		if request.Method == http.MethodGet {
			query := request.URL.Query()
			for key, values := range query {
				if !slices.Contains([]string{"compartmentId", "name", "limit", "sortBy", "sortOrder"}, key) || len(values) != 1 {
					world.reject(w, http.StatusBadRequest)
					return
				}
			}
			if query.Get("compartmentId") == "" || query.Get("limit") != "" || query.Get("sortBy") != "" || query.Get("sortOrder") != "" {
				world.reject(w, http.StatusNotImplemented)
				return
			}
			ids := make([]string, 0, len(world.policies))
			for id := range world.policies {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			policies := make([]identity.Policy, 0)
			for _, id := range ids {
				policy := world.policies[id].value
				if *policy.CompartmentId == query.Get("compartmentId") && (query.Get("name") == "" || *policy.Name == query.Get("name")) {
					policies = append(policies, policy)
				}
			}
			ociJSON(w, http.StatusOK, policies)
			return
		}
	}
	id, ok := strings.CutPrefix(path, "/20160918/policies/")
	if ok && !strings.Contains(id, "/") && request.URL.RawQuery == "" {
		policy, exists := world.policies[id]
		if !exists {
			world.reject(w, http.StatusNotFound)
			return
		}
		if request.Method == http.MethodGet {
			w.Header().Set("ETag", policy.etag)
			ociJSON(w, http.StatusOK, policy.value)
			return
		}
		if request.Method == http.MethodDelete {
			if request.Context().Err() != nil {
				world.reject(w, http.StatusRequestTimeout)
				return
			}
			if len(request.Header.Values("If-Match")) != 1 || request.Header.Get("If-Match") != policy.etag {
				world.reject(w, http.StatusPreconditionFailed)
				return
			}
			if _, err := world.record("policy-delete", id, nil); err != nil {
				world.reject(w, http.StatusServiceUnavailable)
				return
			}
			world.stateBytes -= policy.size
			delete(world.policies, id)
			world.evidence.PolicyWrites++
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	world.reject(w, http.StatusNotImplemented)
}

func (world *ociWorld) createPolicy(w http.ResponseWriter, request *http.Request, body []byte) {
	var details identity.CreatePolicyDetails
	if protocol.DecodeStrict(body, &details, ociBodyLimit) != nil || details.Name == nil || *details.Name == "" || len(*details.Name) > 128 ||
		details.CompartmentId == nil || !strings.HasPrefix(*details.CompartmentId, "ocid1.") ||
		details.Description == nil || len(*details.Description) > 400 || len(details.Statements) == 0 || len(details.Statements) > 128 ||
		request.Context().Err() != nil {
		world.reject(w, http.StatusBadRequest)
		return
	}
	for _, statement := range details.Statements {
		if statement == "" || len(statement) > 8192 {
			world.reject(w, http.StatusBadRequest)
			return
		}
	}
	token := request.Header.Get("Opc-Retry-Token")
	if len(request.Header.Values("Opc-Retry-Token")) != 1 || token == "" || len(token) > 128 {
		world.reject(w, http.StatusBadRequest)
		return
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	if retry, exists := world.retries[token]; exists {
		policy, present := world.policies[retry.id]
		if retry.request != digest || !present {
			world.reject(w, http.StatusConflict)
			return
		}
		w.Header().Set("ETag", policy.etag)
		ociJSON(w, http.StatusOK, policy.value)
		return
	}
	if len(world.policies) >= 128 || len(world.retries) >= 256 {
		world.reject(w, http.StatusInsufficientStorage)
		return
	}
	for _, policy := range world.policies {
		if *policy.value.Name == *details.Name {
			world.reject(w, http.StatusConflict)
			return
		}
	}
	createIdentity := strconv.FormatUint(world.evidence.JournalRecords+1, 10) + "\x00" + digest
	id := fmt.Sprintf("ocid1.policy.oc1..%x", sha256.Sum256([]byte(createIdentity)))
	now := common.SDKTime{Time: time.Now().UTC()}
	policy := identity.Policy{Id: new(id), CompartmentId: details.CompartmentId, Name: details.Name, Description: details.Description,
		Statements: details.Statements, LifecycleState: identity.PolicyLifecycleStateActive, TimeCreated: &now,
		VersionDate: details.VersionDate, FreeformTags: details.FreeformTags, DefinedTags: details.DefinedTags}
	value, err := json.Marshal(policy, json.Deterministic(true))
	if err != nil {
		world.reject(w, http.StatusInternalServerError)
		return
	}
	if world.stateBytes+len(value) > 16<<20 {
		world.reject(w, http.StatusInsufficientStorage)
		return
	}
	etag, err := world.record("policy-create", id, value)
	if err != nil {
		world.reject(w, http.StatusServiceUnavailable)
		return
	}
	world.policies[id] = ociPolicy{value: policy, etag: etag, size: len(value)}
	world.stateBytes += len(value)
	world.retries[token] = ociPolicyRetry{request: digest, id: id}
	world.evidence.PolicyWrites++
	w.Header().Set("ETag", etag)
	ociJSON(w, http.StatusOK, policy)
}
