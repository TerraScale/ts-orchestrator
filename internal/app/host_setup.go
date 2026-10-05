package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const pendingHostEnrollmentFile = ".host-enrollment-pending.json"

type pendingHostEnrollment struct {
	InstanceID    string `json:"instance_id"`
	IdentityKey   string `json:"identity_key"`
	NATSUserSeed  string `json:"nats_user_seed"`
	TLSPrivateKey string `json:"tls_private_key"`
	Request       []byte `json:"request"`
}

func runHostSetup(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("host-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	publicPath := flags.String("public-config", "", "public enrollment bundle, installed from launch metadata when absent")
	outputRoot := flags.String("output-root", "", "root-owned host configuration directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *publicPath == "" || *outputRoot == "" {
		return errors.New("usage: host-setup --public-config FILE --output-root DIRECTORY")
	}
	imds := hostenroll.NewIMDSClient()
	metadata, err := hostenroll.ReadInstanceMetadata(ctx, imds)
	if errors.Is(err, hostenroll.ErrNotManagedHost) {
		_, _ = fmt.Fprintln(output, "instance is not a managed host; nothing to enroll")
		return nil
	}
	if err != nil {
		return err
	}
	bundleWire, err := hostenroll.ReadEnrollmentMetadata(ctx, imds)
	if err != nil {
		return err
	}
	bundle, err := hostenroll.InstallPublicBundle(*publicPath, bundleWire)
	if err != nil {
		return err
	}
	return runHostSetupWithMetadata(ctx, bundle, metadata, *outputRoot, output,
		hostSetupRuntime{post: postHostEnrollment, ownerUID: 0})
}

type hostEnrollmentPoster func(context.Context, hostenroll.PublicBundle, []byte) ([]byte, error)

type hostSetupRuntime struct {
	post     hostEnrollmentPoster
	ownerUID uint32
}

// runHostSetupWithMetadata keeps the guest enrollment flow identical after the
// image bundle and current OCI metadata have been read. Tests use this seam to
// drive the real private TLS client without depending on OCI IMDS.
func runHostSetupWithMetadata(ctx context.Context, bundle hostenroll.PublicBundle,
	metadata hostenroll.InstanceMetadata, outputRoot string, output io.Writer, runtime hostSetupRuntime,
) error {
	if runtime.post == nil {
		return errors.New("host enrollment transport is unavailable")
	}
	if err := bundle.Validate(); err != nil {
		return err
	}
	currentDescriptor, err := hostboot.ParseHost(metadata.Wire)
	if err != nil || currentDescriptor != metadata.Descriptor || !validEnrollmentInstanceID(metadata.InstanceID) {
		return errors.New("current OCI host metadata is invalid")
	}
	if metadata.Descriptor.Cell != bundle.Cell || metadata.Descriptor.Region != bundle.Region {
		return errors.New("OCI host descriptor differs from image-pinned regional bundle")
	}
	if err := validateHostSetupRootOwner(outputRoot, runtime.ownerUID); err != nil {
		return err
	}
	pending, err := readOrCreateHostEnrollment(outputRoot, metadata)
	if err != nil {
		return err
	}
	var original hostenroll.Request
	if err := json.Unmarshal(pending.Request, &original, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	request, descriptor, err := hostenroll.ParseRequest(pending.Request, original.IssuedAt.Add(time.Second))
	if err != nil || request.InstanceID != metadata.InstanceID || request.Descriptor != string(metadata.Wire) ||
		descriptor != metadata.Descriptor || request.Operation != "enroll" {
		return errors.New("persisted host enrollment request differs from current OCI metadata")
	}
	active, err := installedHostCredentialActive(outputRoot, bundle, descriptor.Node, pending, request)
	if err != nil {
		return err
	}
	if active {
		_, _ = fmt.Fprintf(output, "host %s enrollment is current in cell %s\n", descriptor.Node, bundle.Cell)
		return nil
	}
	requestWire := pending.Request
	if _, err := os.Stat(filepath.Join(outputRoot, "host.json")); err == nil {
		requestWire, err = createRenewalRequest(outputRoot, pending, request)
		if err != nil {
			return err
		}
	}
	request, err = parsePersistedHostRequest(requestWire)
	if err != nil {
		return err
	}
	responseWire, err := runtime.post(ctx, bundle, requestWire)
	if status, ok := errors.AsType[*hostEnrollmentHTTPStatusError](err); ok &&
		status.Code == http.StatusPreconditionFailed && time.Since(request.IssuedAt) > 48*time.Hour {
		if request.Operation == "renew" {
			requestWire, err = createFreshRenewalRequest(outputRoot, pending, original)
		} else {
			requestWire, err = createFreshInitialRequest(outputRoot, pending, original)
		}
		if err != nil {
			return err
		}
		request, err = parsePersistedHostRequest(requestWire)
		if err != nil {
			return err
		}
		responseWire, err = runtime.post(ctx, bundle, requestWire)
	}
	if status, ok := errors.AsType[*hostEnrollmentHTTPStatusError](err); ok &&
		status.Code == http.StatusPreconditionFailed && status.Kind == staleUnclaimedRenewal &&
		request.Operation == "renew" && time.Since(request.IssuedAt) > 5*time.Minute {
		requestWire, err = createFreshRenewalRequest(outputRoot, pending, original)
		if err != nil {
			return err
		}
		request, err = parsePersistedHostRequest(requestWire)
		if err != nil {
			return err
		}
		responseWire, err = runtime.post(ctx, bundle, requestWire)
	}
	if err != nil {
		return err
	}
	responseKey, err := bundle.ResponsePublicKey()
	if err != nil {
		return err
	}
	response, err := hostenroll.VerifyResponse(responseWire, responseKey, request, requestWire, descriptor)
	if err != nil && time.Since(request.IssuedAt) > 5*time.Minute {
		if request.Operation == "renew" {
			requestWire, err = createFreshRenewalRequest(outputRoot, pending, original)
		} else {
			requestWire, err = createRenewalRequest(outputRoot, pending, original)
		}
		if err != nil {
			return err
		}
		request, err = parsePersistedHostRequest(requestWire)
		if err != nil {
			return err
		}
		responseWire, err = runtime.post(ctx, bundle, requestWire)
		if err != nil {
			return err
		}
		response, err = hostenroll.VerifyResponse(responseWire, responseKey, request, requestWire, descriptor)
	}
	if err != nil {
		return err
	}
	if err := validateHostCredentials(bundle, descriptor.Node, pending, request, response); err != nil {
		return err
	}
	if err := installHostEnrollment(outputRoot, bundle, descriptor, pending, response, runtime.ownerUID); err != nil {
		return err
	}
	if request.Operation == "renew" {
		if err := os.Remove(filepath.Join(outputRoot, ".host-enrollment-renewal.json")); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintf(output, "host %s enrolled in cell %s\n", descriptor.Node, bundle.Cell)
	return nil
}

func parsePersistedHostRequest(wire []byte) (hostenroll.Request, error) {
	var saved hostenroll.Request
	if err := json.Unmarshal(wire, &saved, json.RejectUnknownMembers(true)); err != nil {
		return hostenroll.Request{}, err
	}
	if saved.IssuedAt.IsZero() || saved.IssuedAt.After(time.Now().Add(30*time.Second)) {
		return hostenroll.Request{}, errors.New("persisted host enrollment request has an invalid time")
	}
	request, _, err := hostenroll.ParseRequest(wire, saved.IssuedAt.Add(time.Second))
	return request, err
}

func installedHostCredentialActive(root string, bundle hostenroll.PublicBundle, node string,
	pending pendingHostEnrollment, request hostenroll.Request,
) (bool, error) {
	configPath := filepath.Join(root, "host.json")
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		return false, err
	}
	credentialRoot := filepath.Dir(config.NATS.CredentialsFile)
	if filepath.Dir(credentialRoot) != root ||
		!strings.HasPrefix(filepath.Base(credentialRoot), "host-credentials-") ||
		config.NATS.Cell != bundle.Cell || config.NATS.Instance != node ||
		config.NATS.URL != strings.Join(bundle.NATSURLs, ",") ||
		config.Host.Node != node || config.Host.Environment != bundle.Environment ||
		config.Host.ControllerPublicKey != bundle.ControllerResponsePublicKey ||
		config.Host.IdentityKeyFile != filepath.Join(credentialRoot, "host-identity.key") ||
		config.NATS.CredentialsFile != filepath.Join(credentialRoot, "host-nats.creds") ||
		config.NATS.TLS.KeyFile != filepath.Join(credentialRoot, "host-tls-key.pem") ||
		config.NATS.TLS.CertFile != filepath.Join(credentialRoot, "host-tls-cert.pem") ||
		config.NATS.TLS.CAFile != filepath.Join(credentialRoot, "ca.pem") {
		return false, errors.New("installed host configuration differs from the enrolled regional bundle")
	}
	for _, path := range []string{config.Host.IdentityKeyFile, config.NATS.CredentialsFile,
		config.NATS.TLS.KeyFile, config.NATS.TLS.CAFile} {
		if _, err := os.Stat(path); err != nil {
			return false, errors.New("installed host credentials are incomplete")
		}
	}
	identityWire, err := os.ReadFile(config.Host.IdentityKeyFile)
	if err != nil || string(identityWire) != pending.IdentityKey+"\n" {
		return false, errors.New("installed host identity differs from the enrollment request")
	}
	tlsKeyWire, err := os.ReadFile(config.NATS.TLS.KeyFile)
	if err != nil || string(tlsKeyWire) != pending.TLSPrivateKey {
		return false, errors.New("installed host TLS key differs from the enrollment request")
	}
	caWire, err := os.ReadFile(config.NATS.TLS.CAFile)
	if err != nil || string(caWire) != bundle.CAPEM {
		return false, errors.New("installed host CA differs from the image-pinned regional CA")
	}
	chain, err := os.ReadFile(config.NATS.TLS.CertFile)
	if err != nil {
		return false, err
	}
	creds, err := os.ReadFile(config.NATS.CredentialsFile)
	if err != nil {
		return false, err
	}
	installedUser, err := nkeys.ParseDecoratedUserNKey(creds)
	if err != nil {
		return false, err
	}
	installedPublic, err := installedUser.PublicKey()
	installedUser.Wipe()
	if err != nil || installedPublic != request.NATSUserPublicKey {
		return false, errors.New("installed NATS seed differs from the enrollment request")
	}
	rawJWT, err := nkeys.ParseDecoratedJWT(creds)
	if err != nil {
		return false, err
	}
	claim, err := jwt.DecodeUserClaims(rawJWT)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("installed host TLS certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	if claim.Expires <= time.Now().Unix() || !certificate.NotAfter.After(time.Now()) {
		return false, nil
	}
	response := hostenroll.Response{NATSUserJWT: rawJWT, TLSCertificatePEM: string(chain), ExpiresAt: certificate.NotAfter}
	if err := validateHostCredentials(bundle, node, pending, request, response); err != nil {
		return false, err
	}
	if claim.Expires <= time.Now().Add(24*time.Hour).Unix() {
		return false, nil
	}
	return time.Until(certificate.NotAfter) > 24*time.Hour, nil
}

func createRenewalRequest(root string, pending pendingHostEnrollment,
	original hostenroll.Request,
) ([]byte, error) {
	path := filepath.Join(root, ".host-enrollment-renewal.json")
	if wire, err := os.ReadFile(path); err == nil {
		if len(wire) == 0 || len(wire) > hostenroll.MaxRequestBytes {
			return nil, errors.New("persisted host renewal request is invalid")
		}
		return wire, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return createFreshRenewalRequest(root, pending, original)
}

func createFreshRenewalRequest(root string, pending pendingHostEnrollment,
	original hostenroll.Request,
) ([]byte, error) {
	identity, err := base64.StdEncoding.DecodeString(pending.IdentityKey)
	if err != nil || len(identity) != ed25519.PrivateKeySize {
		return nil, errors.New("persisted host identity key is invalid")
	}
	defer clear(identity)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	renewal := original
	renewal.Operation = "renew"
	renewal.Nonce = base64.StdEncoding.EncodeToString(nonce)
	renewal.IssuedAt = time.Now().UTC()
	renewal.Signature = ""
	if err := renewal.Sign(ed25519.PrivateKey(identity)); err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(renewal)
	if err != nil {
		return nil, err
	}
	if err := writeAtomicHostFile(filepath.Join(root, ".host-enrollment-renewal.json"), wire, 0o600); err != nil {
		return nil, err
	}
	return wire, nil
}

func createFreshInitialRequest(root string, pending pendingHostEnrollment,
	original hostenroll.Request,
) ([]byte, error) {
	identity, err := base64.StdEncoding.DecodeString(pending.IdentityKey)
	if err != nil || len(identity) != ed25519.PrivateKeySize {
		return nil, errors.New("persisted host identity key is invalid")
	}
	defer clear(identity)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	initial := original
	initial.Nonce = base64.StdEncoding.EncodeToString(nonce)
	initial.IssuedAt = time.Now().UTC()
	initial.Signature = ""
	if err := initial.Sign(ed25519.PrivateKey(identity)); err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(initial)
	if err != nil {
		return nil, err
	}
	pending.Request = wire
	protected, err := protocol.EncodeJSON(pending)
	if err != nil {
		return nil, err
	}
	if err := writeAtomicHostFile(filepath.Join(root, pendingHostEnrollmentFile), protected, 0o600); err != nil {
		return nil, err
	}
	return wire, nil
}

func validateHostSetupRootOwner(root string, ownerUID uint32) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("host setup output root must be clean and absolute")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Uid != ownerUID || info.Mode().Perm()&0o022 != 0 {
		return errors.New("host setup output root must be a root-owned private directory")
	}
	return nil
}

func readOrCreateHostEnrollment(root string, metadata hostenroll.InstanceMetadata) (pendingHostEnrollment, error) {
	path := filepath.Join(root, pendingHostEnrollmentFile)
	if wire, err := os.ReadFile(path); err == nil {
		var pending pendingHostEnrollment
		if len(wire) == 0 || len(wire) > 32<<10 || json.Unmarshal(wire, &pending, json.RejectUnknownMembers(true)) != nil {
			return pendingHostEnrollment{}, errors.New("persisted host enrollment request is invalid")
		}
		return pending, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return pendingHostEnrollment{}, err
	}
	identityPublic, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	natsUser, err := nkeys.CreateUser()
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	defer natsUser.Wipe()
	natsPublic, err := natsUser.PublicKey()
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	natsSeed, err := natsUser.Seed()
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	defer clear(natsSeed)
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, tlsKey)
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	tlsKeyDER, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return pendingHostEnrollment{}, err
	}
	request := hostenroll.Request{SchemaVersion: 1, Operation: "enroll",
		InstanceID: metadata.InstanceID, Descriptor: string(metadata.Wire),
		IdentityPublicKey: base64.StdEncoding.EncodeToString(identityPublic),
		NATSUserPublicKey: natsPublic,
		CSRPEM:            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Nonce:             base64.StdEncoding.EncodeToString(nonce), IssuedAt: time.Now().UTC()}
	if err := request.Sign(identityPrivate); err != nil {
		return pendingHostEnrollment{}, err
	}
	requestWire, err := protocol.EncodeJSON(request)
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	pending := pendingHostEnrollment{InstanceID: metadata.InstanceID,
		IdentityKey:   base64.StdEncoding.EncodeToString(identityPrivate),
		NATSUserSeed:  base64.StdEncoding.EncodeToString(natsSeed),
		TLSPrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: tlsKeyDER})),
		Request:       requestWire}
	wire, err := protocol.EncodeJSON(pending)
	if err != nil {
		return pendingHostEnrollment{}, err
	}
	if err := writeAtomicHostFile(path, wire, 0o600); err != nil {
		return pendingHostEnrollment{}, err
	}
	return pending, nil
}

const staleUnclaimedRenewal = "stale-unclaimed-renewal"

type hostEnrollmentHTTPStatusError struct {
	Code int
	Kind string
}

func (status *hostEnrollmentHTTPStatusError) Error() string {
	return fmt.Sprintf("controller returned status %d", status.Code)
}

func postHostEnrollment(ctx context.Context, bundle hostenroll.PublicBundle, wire []byte) ([]byte, error) {
	return postHostEnrollmentWithDial(ctx, bundle, wire, nil)
}

func postHostEnrollmentWithDial(ctx context.Context, bundle hostenroll.PublicBundle, wire []byte,
	dial func(context.Context, string, string) (net.Conn, error),
) ([]byte, error) {
	roots, err := bundle.RootCAs()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	if dial != nil {
		transport.DialContext = dial
	}
	client := &http.Client{Timeout: 12 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last error
	staleWithoutGrant := false
	staleRenewal := false
	for _, endpoint := range bundle.ControllerEndpoints {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://"+endpoint+"/v1/host-enrollment", bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			last = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, hostenroll.MaxResponseBytes+1))
		_ = response.Body.Close()
		if readErr == nil && response.StatusCode == http.StatusOK && len(body) > 0 && len(body) <= hostenroll.MaxResponseBytes {
			return body, nil
		}
		if response.StatusCode == http.StatusPreconditionFailed {
			if response.Header.Get("X-TerraScale-Host-Enrollment-Error") == staleUnclaimedRenewal {
				staleRenewal = true
			} else {
				staleWithoutGrant = true
			}
		}
		last = &hostEnrollmentHTTPStatusError{Code: response.StatusCode}
	}
	if staleWithoutGrant {
		return nil, &hostEnrollmentHTTPStatusError{Code: http.StatusPreconditionFailed}
	}
	if staleRenewal {
		return nil, &hostEnrollmentHTTPStatusError{Code: http.StatusPreconditionFailed, Kind: staleUnclaimedRenewal}
	}
	return nil, fmt.Errorf("private host enrollment request failed: %w", last)
}

func validateHostCredentials(bundle hostenroll.PublicBundle, node string, pending pendingHostEnrollment,
	request hostenroll.Request, response hostenroll.Response,
) error {
	seed, err := base64.StdEncoding.DecodeString(pending.NATSUserSeed)
	if err != nil {
		return err
	}
	defer clear(seed)
	user, err := nkeys.FromSeed(seed)
	if err != nil {
		return err
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil || public != request.NATSUserPublicKey {
		return errors.New("issued NATS credential differs from persisted host key")
	}
	claim, err := jwt.DecodeUserClaims(response.NATSUserJWT)
	if err != nil || claim.Subject != public || claim.IssuerAccount != bundle.CellAccountNKey ||
		claim.Expires <= time.Now().Unix() || !claim.HasEmptyPermissions() {
		return errors.New("issued NATS JWT differs from host scope")
	}
	keyBlock, _ := pem.Decode([]byte(pending.TLSPrivateKey))
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return errors.New("persisted host TLS key is invalid")
	}
	tlsKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	leafBlock, rest := pem.Decode([]byte(response.TLSCertificatePEM))
	intermediateBlock, tail := pem.Decode(rest)
	if leafBlock == nil || intermediateBlock == nil || len(bytes.TrimSpace(tail)) != 0 {
		return errors.New("issued host TLS chain is incomplete")
	}
	leaf, leafErr := x509.ParseCertificate(leafBlock.Bytes)
	intermediate, issuerErr := x509.ParseCertificate(intermediateBlock.Bytes)
	if leafErr != nil || issuerErr != nil {
		return errors.New("issued host TLS chain cannot be parsed")
	}
	roots, err := bundle.RootCAs()
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	leafPublic, leafIsECDSA := leaf.PublicKey.(*ecdsa.PublicKey)
	dns := node + ".hosts." + bundle.Cell + ".terrascale.internal"
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		DNSName: dns, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return err
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != dns || len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() != "spiffe://hosts."+bundle.Cell+".terrascale.internal/instances/"+request.InstanceID ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		!leafIsECDSA || !leafPublic.Equal(&tlsKey.PublicKey) || !leaf.NotAfter.Equal(response.ExpiresAt) {
		return errors.New("issued host TLS certificate differs from enrolled key or instance")
	}
	return nil
}

func installHostEnrollment(root string, bundle hostenroll.PublicBundle, descriptor hostboot.Descriptor,
	pending pendingHostEnrollment, response hostenroll.Response, ownerUID uint32,
) error {
	node := descriptor.Node
	responseWire, err := protocol.EncodeJSON(response)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(responseWire)
	credentialRoot := filepath.Join(root, fmt.Sprintf("host-credentials-%x", sum[:12]))
	if err := os.Mkdir(credentialRoot, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := validateHostSetupRootOwner(credentialRoot, ownerUID); err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(pending.NATSUserSeed)
	if err != nil {
		return err
	}
	defer clear(seed)
	creds, err := jwt.FormatUserConfig(response.NATSUserJWT, seed)
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"host-identity.key", []byte(pending.IdentityKey + "\n"), 0o600},
		{"host-nats.creds", creds, 0o600},
		{"host-tls-key.pem", []byte(pending.TLSPrivateKey), 0o600},
		{"host-tls-cert.pem", []byte(response.TLSCertificatePEM), 0o600},
		{"ca.pem", []byte(bundle.CAPEM), 0o644},
	}
	for _, file := range files {
		if err := writeAtomicHostFile(filepath.Join(credentialRoot, file.name), file.data, file.mode); err != nil {
			return err
		}
	}
	config := Config{NATS: natscell.Config{Cell: bundle.Cell, Instance: node, Replicas: 3,
		URL: strings.Join(bundle.NATSURLs, ","), CredentialsFile: filepath.Join(credentialRoot, "host-nats.creds"),
		TLS: natscell.TLSFiles{CAFile: filepath.Join(credentialRoot, "ca.pem"),
			CertFile: filepath.Join(credentialRoot, "host-tls-cert.pem"), KeyFile: filepath.Join(credentialRoot, "host-tls-key.pem")}},
		Host: HostConfig{Node: node, Environment: bundle.Environment, Roles: []string{"terrabase"},
			IdentityKeyFile:     filepath.Join(credentialRoot, "host-identity.key"),
			ControllerPublicKey: bundle.ControllerResponsePublicKey,
			InstallRoot:         bundle.InstallRoot, StateRoot: bundle.StateRoot,
			ManagedRuntimeRoot: bundle.ManagedRuntimeRoot,
			WorkloadUID:        bundle.WorkloadUID, WorkloadGID: bundle.WorkloadGID}}
	// A renewal regenerates the credentials, not the operator's host-local
	// options: carry them forward from the configuration being replaced.
	local, err := readHostLocalOptions(filepath.Join(root, "host.json"))
	if err != nil {
		return err
	}
	local.applyTo(&config.Host)
	// A static host exists to run C# TerraBase members; it gets the image's
	// member root unless the operator chose another one.
	if descriptor.IsStatic() && config.Host.TerraBaseRoot == "" {
		config.Host.TerraBaseRoot = filepath.Join(bundle.ManagedRuntimeRoot, "terrabase")
	}
	wire, err := protocol.EncodeJSON(config)
	if err != nil {
		return err
	}
	return writeAtomicHostFile(filepath.Join(root, "host.json"), wire, 0o600)
}

// hostLocalOptions are the host.json settings an operator sets on the host
// itself. Enrollment and credential renewal do not know them, so they are
// preserved across a host.json rewrite.
type hostLocalOptions struct {
	ManagedVolumeOnlineGrow bool   `json:"managed_volume_online_grow,omitzero"`
	SelfUpdateProofFile     string `json:"self_update_proof_file,omitempty"`
	SelfUpdateRoot          string `json:"self_update_root,omitempty"`
	TerraBaseRoot           string `json:"terrabase_root,omitempty"`
	TSAuthRoot              string `json:"ts_auth_root,omitempty"`
	TerraBaseDataVolume     bool   `json:"terrabase_data_volume,omitzero"`
	TerraBaseDataVolumeID   string `json:"terrabase_data_volume_id,omitempty"`
}

func (o hostLocalOptions) applyTo(host *HostConfig) {
	host.ManagedVolumeOnlineGrow = o.ManagedVolumeOnlineGrow
	host.SelfUpdateProofFile = o.SelfUpdateProofFile
	host.SelfUpdateRoot = o.SelfUpdateRoot
	host.TerraBaseRoot = o.TerraBaseRoot
	host.TSAuthRoot = o.TSAuthRoot
	host.TerraBaseDataVolume = o.TerraBaseDataVolume
	host.TerraBaseDataVolumeID = o.TerraBaseDataVolumeID
}

// readHostLocalOptions reads the host-local options of an existing host.json.
// A first enrollment has none. An existing file that cannot be read or
// decoded fails the rewrite rather than silently dropping the options.
func readHostLocalOptions(path string) (hostLocalOptions, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return hostLocalOptions{}, nil
	}
	if err != nil {
		return hostLocalOptions{}, fmt.Errorf("read existing host config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return hostLocalOptions{}, fmt.Errorf("read existing host config: %w", err)
	}
	if len(data) > 1<<20 {
		return hostLocalOptions{}, errors.New("existing host config is too large")
	}
	var existing struct {
		Host hostLocalOptions `json:"host"`
	}
	if err := json.Unmarshal(data, &existing); err != nil {
		return hostLocalOptions{}, fmt.Errorf("decode existing host config %s (repair it before renewing): %w", path, err)
	}
	return existing.Host, nil
}

func writeAtomicHostFile(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	name := filepath.Base(path)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	temporary := filepath.Join(directory, "."+name+"."+base64.RawURLEncoding.EncodeToString(nonce))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
