//go:build fixturetest

package bootstrapstart

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sys/unix"
)

const controllerSDKFixtureDirectory = "/run/ts-installed-controller-sdk"
const controllerSDKFixtureFile = controllerSDKFixtureDirectory + "/source.json"
const controllerSDKFixtureMaxBytes = 32 << 10
const controllerSDKFixtureDomain = "terrascale.fixture.controller-sdk.v1\x00"

// ControllerSDKAcquisitionFixture reacquires actual SDKs over the original
// fixture's protocol state. It does not qualify production cold acquisition.
type ControllerSDKAcquisitionFixture struct {
	reader     *CurrentFounderAuthorityReader
	accepted   AcceptedIdentity
	storage    *objectstorage.ObjectStorageClient
	observer   *OCIInstanceObserver
	descriptor *IMDSClient
	ledgerRead *bootstrap.Ledger
	source     controllerSDKFixtureSource
	wire       []byte
	lifetime   context.Context
	file       atomic.Pointer[controllerSDKFixtureFilePin]
}

type controllerSDKFixtureFilePin struct {
	directory unix.Stat_t
	file      unix.Stat_t
}

type controllerSDKFixtureSource struct {
	Endpoint, Certificate, PrivateKey, Tenancy string
	MountNamespace, NetworkNamespace           string
	SourceSHA256, SelectionSHA256              string
	ExpiresAt                                  time.Time
}

type controllerSDKFixtureEnvelope struct {
	Payload   []byte
	KeyID     string
	Signature []byte
}

// NewControllerSDKAcquisitionFixture accepts only the installed signed producer.
// The simulator reads the existing shared SDK store; it creates no history.
func NewControllerSDKAcquisitionFixture(t *testing.T, ctx context.Context, fixture *ControllerManagerStartupFixture) *ControllerSDKAcquisitionFixture {
	t.Helper()
	if ctx == nil || ctx.Err() != nil || fixture == nil || fixture.Reader == nil || fixture.Storage == nil || fixture.retirementFixture == nil || fixture.retirementFixture.sdk == nil || len(fixture.Root) != ed25519.PrivateKeySize || os.Geteuid() != 0 {
		t.Fatal("controller SDK acquisition requires the original installed producer")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		t.Fatal("controller SDK acquisition requires the original finite runtime context")
	}
	mount, network, err := controllerSDKFixtureNamespace()
	if err != nil {
		t.Fatal(err)
	}
	installed, err := NewMarkerStore().ReadIdentity()
	if err != nil || installed.InstanceOCID != fixture.Accepted.InstanceOCID || installed.ManifestSHA256 != fixture.Accepted.ManifestSHA256 {
		t.Fatal("controller SDK acquisition differs from the actual installed marker", err)
	}
	authority, err := fixture.Reader.ReadRuntimeAuthority(ctx, installed, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config, err := currentLedgerConfig(authority.anchor, fixture.Reader.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	home, err := authority.anchor.FoundationScope()
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := url.Parse(fixture.Storage.Host)
	if err != nil || upstream.Scheme != "http" || net.ParseIP(upstream.Hostname()) == nil || !net.ParseIP(upstream.Hostname()).IsLoopback() {
		t.Fatal("controller SDK simulator requires its original local protocol store", err)
	}
	metadata := fixture.Launch.ControllerMetadata()
	descriptor, err := json.Marshal(Descriptor{SchemaVersion: 1, Slot: installed.Slot})
	if err != nil {
		t.Fatal(err)
	}
	metadata["terrascale-bootstrap"] = string(descriptor)
	metadata["terrascale-controller-manifest-v1"] = string(fixture.ManifestWire)
	expires := authority.ExpiresAt()
	if deadline.Before(expires) {
		expires = deadline
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if ctx.Err() != nil || t.Context().Err() != nil || !time.Now().Before(expires) || request.Method != http.MethodGet || request.ContentLength > 0 {
			http.Error(w, "original SDK fixture source ended", http.StatusForbidden)
			return
		}
		requestCtx, cancel := context.WithDeadline(request.Context(), expires)
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		defer cancel()
		request = request.WithContext(requestCtx)
		if strings.HasPrefix(request.URL.Path, "/opc/v2/instance/") {
			if request.Header.Get("Authorization") != "Bearer Oracle" || request.URL.RawQuery != "" {
				http.Error(w, "invalid metadata protocol request", http.StatusForbidden)
				return
			}
			var value string
			switch strings.TrimPrefix(request.URL.Path, "/opc/v2/instance/") {
			case "id":
				value = installed.InstanceOCID
			case "availabilityDomain":
				value = fixture.Instance.AvailabilityDomain
			case "faultDomain":
				value = fixture.Instance.FaultDomain
			default:
				if !strings.HasPrefix(request.URL.Path, "/opc/v2/instance/metadata/") {
					http.Error(w, "unknown metadata field", http.StatusNotFound)
					return
				}
				var ok bool
				value, ok = metadata[strings.TrimPrefix(strings.TrimPrefix(request.URL.Path, "/opc/v2/instance/"), "metadata/")]
				if !ok {
					http.Error(w, "unknown metadata field", http.StatusNotFound)
					return
				}
			}
			_, _ = io.WriteString(w, value)
			return
		}
		if !controllerSDKFixtureSignature(request, &key.PublicKey, home.TenancyID) {
			http.Error(w, "invalid actual SDK signature", http.StatusUnauthorized)
			return
		}
		objectPrefix := strings.Trim(config.Prefix+"/bootstrap/v1/"+config.DeploymentID+"/", "/") + "/"
		objectAllowed := false
		for _, bucket := range []string{config.HeadBucket, config.Bucket} {
			objectAllowed = objectAllowed || strings.HasPrefix(request.URL.Path, "/n/"+config.Namespace+"/b/"+bucket+"/o/"+objectPrefix) && request.URL.RawQuery == ""
		}
		observed, instanceAllowed := fixture.retirementFixture.sdk.lookup(request)
		if request.URL.Path == "/20160918/vnicAttachments" {
			query := request.URL.Query()
			instanceAllowed = instanceAllowed && query.Get("compartmentId") == observed.CompartmentOCID
			for name, values := range query {
				instanceAllowed = instanceAllowed && len(values) == 1 && (name == "compartmentId" || name == "instanceId" || name == "limit" || name == "page")
			}
		} else {
			instanceAllowed = instanceAllowed && request.URL.RawQuery == ""
		}
		if !objectAllowed && !instanceAllowed {
			http.Error(w, "SDK operation outside original fixture scope", http.StatusForbidden)
			return
		}
		forward := request.Clone(request.Context())
		forward.RequestURI = ""
		forward.URL.Scheme, forward.URL.Host = upstream.Scheme, upstream.Host
		forward.Host = upstream.Host
		response, err := fixture.Storage.HTTPClient.Do(forward)
		if err != nil {
			http.Error(w, "original SDK protocol store unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
		if err != nil || len(wire) > 2<<20 {
			http.Error(w, "original SDK response exceeds fixture bound", http.StatusBadGateway)
			return
		}
		for name, values := range response.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	source := controllerSDKFixtureSource{Endpoint: server.URL,
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		Tenancy:     home.TenancyID, MountNamespace: mount, NetworkNamespace: network,
		SourceSHA256: authority.ManagerSourceSHA256(), SelectionSHA256: authority.selectionDigest, ExpiresAt: expires}
	payload, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(fixture.Root.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(controllerSDKFixtureEnvelope{Payload: payload, KeyID: keyID,
		Signature: ed25519.Sign(fixture.Root, append([]byte(controllerSDKFixtureDomain), payload...))})
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := acquireControllerSDKFixture(ctx, wire, nil)
	if err != nil {
		t.Fatal("reacquire actual controller SDK protocol sources", err)
	}
	return acquired
}

func (source *ControllerSDKAcquisitionFixture) Reader() *CurrentFounderAuthorityReader {
	return source.reader
}
func (source *ControllerSDKAcquisitionFixture) Descriptor() *IMDSClient { return source.descriptor }
func (source *ControllerSDKAcquisitionFixture) Observer() *OCIInstanceObserver {
	return source.observer
}
func (source *ControllerSDKAcquisitionFixture) Storage() *objectstorage.ObjectStorageClient {
	return source.storage
}
func (source *ControllerSDKAcquisitionFixture) Ledger() *bootstrap.Ledger { return source.ledgerRead }

// InstallChildSource exposes only authenticated fixture acquisition material.
// The ordinary production launcher and environment remain unchanged.
func (source *ControllerSDKAcquisitionFixture) InstallChildSource() error {
	if os.Geteuid() != 0 || source == nil {
		return ErrAdmission
	}
	if _, _, err := controllerSDKFixtureNamespace(); err != nil {
		return err
	}
	if err := os.Mkdir(controllerSDKFixtureDirectory, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(controllerSDKFixtureDirectory, 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(controllerSDKFixtureFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o444)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(source.wire)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	wire, pin, err := readControllerSDKFixtureFile()
	if err != nil {
		return err
	}
	source.file.Store(pin)
	if !bytes.Equal(wire, source.wire) {
		return ErrAdmission
	}
	return nil
}

// AcquireControllerSDKAcquisitionFixture is available only in fixture binaries.
// It reopens installed authority; the descriptor carries no accepted identity.
func AcquireControllerSDKAcquisitionFixture(ctx context.Context) (*ControllerSDKAcquisitionFixture, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrAdmission
	}
	if _, _, err := controllerSDKFixtureNamespace(); err != nil {
		return nil, err
	}
	wire, pin, err := readControllerSDKFixtureFile()
	if err != nil {
		return nil, err
	}
	return acquireControllerSDKFixture(ctx, wire, pin)
}

func readControllerSDKFixtureFile() ([]byte, *controllerSDKFixtureFilePin, error) {
	var directory unix.Stat_t
	if err := unix.Lstat(controllerSDKFixtureDirectory, &directory); err != nil || directory.Uid != 0 || directory.Gid != 0 || directory.Mode != unix.S_IFDIR|0o755 {
		return nil, nil, ErrAdmission
	}
	file, err := os.OpenFile(controllerSDKFixtureFile, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode != unix.S_IFREG|0o444 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > controllerSDKFixtureMaxBytes {
		return nil, nil, ErrAdmission
	}
	wire, err := io.ReadAll(io.LimitReader(file, controllerSDKFixtureMaxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	return wire, &controllerSDKFixtureFilePin{directory: directory, file: stat}, nil
}

func acquireControllerSDKFixture(ctx context.Context, wire []byte, pin *controllerSDKFixtureFilePin) (*ControllerSDKAcquisitionFixture, error) {
	if ctx == nil || ctx.Err() != nil || len(wire) == 0 || len(wire) > controllerSDKFixtureMaxBytes {
		return nil, ErrAdmission
	}
	mount, network, err := controllerSDKFixtureNamespace()
	if err != nil {
		return nil, err
	}
	baked, err := LoadBakedInputs()
	if err != nil {
		return nil, err
	}
	var envelope controllerSDKFixtureEnvelope
	if json.Unmarshal(wire, &envelope, json.RejectUnknownMembers(true)) != nil || len(baked.Roots[envelope.KeyID]) != ed25519.PublicKeySize || !ed25519.Verify(baked.Roots[envelope.KeyID], append([]byte(controllerSDKFixtureDomain), envelope.Payload...), envelope.Signature) {
		return nil, ErrAdmission
	}
	var descriptor controllerSDKFixtureSource
	if json.Unmarshal(envelope.Payload, &descriptor, json.RejectUnknownMembers(true)) != nil || descriptor.MountNamespace != mount || descriptor.NetworkNamespace != network || !time.Now().Before(descriptor.ExpiresAt) {
		return nil, ErrAdmission
	}
	endpoint, err := url.Parse(descriptor.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" || net.ParseIP(endpoint.Hostname()) == nil || !net.ParseIP(endpoint.Hostname()).IsLoopback() {
		return nil, ErrAdmission
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(descriptor.Certificate)) {
		return nil, ErrAdmission
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, ResponseHeaderTimeout: imdsTimeout}
	acquired := &ControllerSDKAcquisitionFixture{source: descriptor, wire: bytes.Clone(wire), lifetime: ctx}
	acquired.file.Store(pin)
	client := &http.Client{Transport: &controllerSDKFixtureTransport{base: transport, endpoint: descriptor.Endpoint, expires: descriptor.ExpiresAt, source: acquired},
		Timeout: imdsTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAdmission }}
	provider := common.NewRawConfigurationProvider(descriptor.Tenancy, "ocid1.user.oc1..controllerfixture", "sa-saopaulo-1", "fixture-sdk", descriptor.PrivateKey, nil)
	storage, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, err
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, err
	}
	networkClient, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, err
	}
	storage.Host, storage.HTTPClient = descriptor.Endpoint, client
	compute.Host, compute.HTTPClient = descriptor.Endpoint, client
	networkClient.Host, networkClient.HTTPClient = descriptor.Endpoint, client
	initial, err := NewMarkerStore().ReadInitialFormation()
	if err != nil {
		return nil, err
	}
	accepted, err := NewMarkerStore().ReadIdentity()
	if err != nil {
		return nil, err
	}
	account, err := user.Lookup(controllerServiceUser)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	floor, err := NewServiceFounderSelectionFloorStore(uint32(uid))
	if err != nil {
		return nil, err
	}
	reader, err := NewCurrentFounderAuthorityReader(baked, initial, &storage, floor)
	if err != nil {
		return nil, err
	}
	acquired.reader, acquired.accepted, acquired.storage = reader, accepted, &storage
	acquired.observer = &OCIInstanceObserver{compute: &compute, network: &networkClient}
	acquired.descriptor = &IMDSClient{client: client}
	reader.runtimeSDK = acquired
	authority, err := acquired.current(ctx)
	if err != nil {
		return nil, err
	}
	config, err := currentLedgerConfig(authority.anchor, baked.Roots)
	if err != nil {
		return nil, err
	}
	acquired.ledgerRead, err = bootstrap.NewLedger(acquired.storage, config)
	return acquired, err
}

func (source *ControllerSDKAcquisitionFixture) current(ctx context.Context) (RuntimeAuthority, error) {
	if ctx == nil || ctx.Err() != nil || source.local() != nil {
		return RuntimeAuthority{}, ErrAdmission
	}
	accepted, err := NewMarkerStore().ReadIdentity()
	if err != nil || !reflect.DeepEqual(accepted, source.accepted) {
		return RuntimeAuthority{}, ErrAdmission
	}
	authority, err := source.reader.ReadRuntimeAuthority(ctx, source.accepted, time.Now().UTC())
	if err != nil {
		return RuntimeAuthority{}, err
	}
	home, err := authority.anchor.FoundationScope()
	if err != nil || home.TenancyID != source.source.Tenancy || authority.ManagerSourceSHA256() != source.source.SourceSHA256 || authority.selectionDigest != source.source.SelectionSHA256 || source.source.ExpiresAt.After(authority.ExpiresAt()) {
		return RuntimeAuthority{}, ErrAdmission
	}
	return authority, nil
}

func (source *ControllerSDKAcquisitionFixture) local() error {
	if source == nil || source.lifetime == nil || source.lifetime.Err() != nil || !time.Now().Before(source.source.ExpiresAt) {
		return ErrAdmission
	}
	if original := source.file.Load(); original != nil {
		wire, current, err := readControllerSDKFixtureFile()
		if err != nil || !bytes.Equal(wire, source.wire) || original.directory.Dev != current.directory.Dev || original.directory.Ino != current.directory.Ino ||
			original.file.Dev != current.file.Dev || original.file.Ino != current.file.Ino || original.file.Size != current.file.Size || original.file.Mtim != current.file.Mtim || original.file.Ctim != current.file.Ctim {
			return ErrAdmission
		}
	}
	return source.lifetime.Err()
}

func (source *ControllerSDKAcquisitionFixture) instanceObserver(ctx context.Context, config bootstrap.LedgerConfig) (*OCIInstanceObserver, error) {
	authority, err := source.current(ctx)
	if err != nil || config.DeploymentID != authority.identity.DeploymentID || config.Cell != authority.anchor.Anchor().Cell || config.Namespace != authority.anchor.Anchor().StorageDomain.Namespace {
		return nil, ErrAdmission
	}
	return source.observer, nil
}

func (source *ControllerSDKAcquisitionFixture) ledger(ctx context.Context, config bootstrap.LedgerConfig) (SlotReader, error) {
	if _, err := source.instanceObserver(ctx, config); err != nil {
		return nil, err
	}
	return bootstrap.NewLedger(source.storage, config)
}

func controllerSDKFixtureSignature(request *http.Request, key *rsa.PublicKey, tenancy string) bool {
	prefix := `Signature version="1",headers="date (request-target) host",keyId="` + tenancy + `/ocid1.user.oc1..controllerfixture/fixture-sdk",algorithm="rsa-sha256",signature="`
	raw, ok := strings.CutPrefix(request.Header.Get("Authorization"), prefix)
	raw, suffix := strings.CutSuffix(raw, `"`)
	signature, err := base64.StdEncoding.Strict().DecodeString(raw)
	stamp, stampErr := http.ParseTime(request.Header.Get("Date"))
	message := "date: " + request.Header.Get("Date") + "\n(request-target): get " + request.URL.RequestURI() + "\nhost: " + request.Host
	digest := sha256.Sum256([]byte(message))
	return ok && suffix && err == nil && stampErr == nil && time.Since(stamp).Abs() <= 5*time.Minute && rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
}

type controllerSDKFixtureTransport struct {
	base     *http.Transport
	endpoint string
	expires  time.Time
	source   *ControllerSDKAcquisitionFixture
}

func (transport *controllerSDKFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.source.local() != nil {
		return nil, ErrAdmission
	}
	ctx, cancel := context.WithDeadline(request.Context(), transport.expires)
	stop := context.AfterFunc(transport.source.lifetime, cancel)
	finish := func() { stop(); cancel() }
	clone := request.Clone(ctx)
	endpoint, _ := url.Parse(transport.endpoint)
	if request.URL.Scheme == "http" && request.URL.Host == "169.254.169.254" {
		clone.URL.Scheme, clone.URL.Host, clone.Host = endpoint.Scheme, endpoint.Host, endpoint.Host
	} else if request.URL.Scheme != endpoint.Scheme || request.URL.Host != endpoint.Host {
		finish()
		return nil, ErrAdmission
	}
	if transport.source.local() != nil || ctx.Err() != nil {
		finish()
		return nil, ErrAdmission
	}
	response, err := transport.base.RoundTrip(clone)
	if err != nil {
		finish()
		return nil, err
	}
	response.Body = &controllerSDKFixtureBody{ReadCloser: response.Body, cancel: finish}
	return response, nil
}

type controllerSDKFixtureBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *controllerSDKFixtureBody) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

func controllerSDKFixtureNamespace() (string, string, error) {
	mount, err := os.Readlink("/proc/self/ns/mnt")
	initial, initialErr := os.Readlink("/proc/1/ns/mnt")
	network, networkErr := os.Readlink("/proc/self/ns/net")
	if err != nil || initialErr != nil || networkErr != nil || mount == initial {
		return "", "", ErrAdmission
	}
	wire, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", "", err
	}
	for path, source := range map[string]string{"/etc": "ts-installed-controller-etc", "/var/lib": "ts-installed-controller-state", "/run": "ts-installed-controller-run"} {
		found := false
		for line := range strings.SplitSeq(string(wire), "\n") {
			fields := strings.Fields(line)
			found = found || len(fields) > 6 && fields[4] == path && strings.Contains(line, " - tmpfs "+source+" ")
		}
		if !found {
			return "", "", fmt.Errorf("controller SDK fixture requires private %s", path)
		}
	}
	return mount, network, nil
}
