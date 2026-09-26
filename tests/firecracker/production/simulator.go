// Package production contains the isolated OCI wire simulator used by the
// production-mode Firecracker qualification. It never forwards a request.
package production

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	json "encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	imdsHost      = "169.254.169.254"
	maxRequest    = 64 << 10
	maxClockSkew  = 5 * time.Minute
	tokenLifetime = time.Hour
)

var signatureRE = regexp.MustCompile(`^Signature version="1",headers="([a-z0-9() -]+)",keyId="([^"]+)",algorithm="rsa-sha256",signature="([A-Za-z0-9+/=]+)"$`)

// ReadResponse is one exact, preloaded OCI GET. RequestURI includes the raw
// query string. Supplying an entry does not enable a prefix or another method.
type ReadResponse struct {
	Host         string
	RequestURI   string
	Body         []byte
	ContentType  string
	ETag         string
	LastModified time.Time
}

// Config is fixture material; no value is read from guest-supplied metadata.
type Config struct {
	Region          string
	InstanceID      string
	DescriptorSlot  string
	TenancyID       string
	LeafCertificate []byte
	LeafPrivateKey  []byte
	Intermediate    []byte
	Reads           []ReadResponse
}

type RequestRecord struct {
	Method     string `json:"method"`
	Host       string `json:"host"`
	RequestURI string `json:"requestUri"`
	Status     int    `json:"status"`
}

type routeKey struct{ host, uri string }

type session struct {
	public  *rsa.PublicKey
	expires time.Time
}

// Simulator authenticates the SDK's federation and service signatures. Its
// snapshots include rejected requests so an offline run can prove the absence
// of unexpected cloud calls, including writes.
type Simulator struct {
	config      Config
	leaf        *x509.Certificate
	leafKey     *rsa.PrivateKey
	authHost    string
	computeHost string
	storageHost string
	reads       map[routeKey]ReadResponse
	mu          sync.Mutex
	sessions    map[string]session
	requests    []RequestRecord
	now         func() time.Time
}

func NewSimulator(config Config) (*Simulator, error) {
	if config.Region != "sa-saopaulo-1" || config.InstanceID == "" || config.DescriptorSlot == "" ||
		!strings.HasPrefix(config.TenancyID, "ocid1.tenancy.") {
		return nil, errors.New("simulator requires the pinned GRU fixture identity")
	}
	config.LeafCertificate = bytes.Clone(config.LeafCertificate)
	config.LeafPrivateKey = bytes.Clone(config.LeafPrivateKey)
	config.Intermediate = bytes.Clone(config.Intermediate)
	block, rest := pem.Decode(config.LeafCertificate)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid leaf certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	privateBlock, rest := pem.Decode(config.LeafPrivateKey)
	if privateBlock == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid leaf private key PEM")
	}
	var key *rsa.PrivateKey
	switch privateBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	default:
		return nil, errors.New("leaf private key must be RSA")
	}
	public, ok := leaf.PublicKey.(*rsa.PublicKey)
	if err != nil || key == nil || !ok || !public.Equal(&key.PublicKey) {
		return nil, errors.New("leaf certificate and RSA key do not match")
	}
	foundTenancy := false
	for _, name := range leaf.Subject.Names {
		if value, ok := name.Value.(string); ok && value == "opc-tenant:"+config.TenancyID {
			foundTenancy = true
		}
	}
	if !foundTenancy {
		return nil, errors.New("leaf certificate does not bind the fixture tenancy")
	}
	intermediate, extra := pem.Decode(config.Intermediate)
	if intermediate == nil || intermediate.Type != "CERTIFICATE" || len(bytes.TrimSpace(extra)) != 0 {
		return nil, errors.New("invalid intermediate certificate PEM")
	}
	issuer, err := x509.ParseCertificate(intermediate.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate certificate: %w", err)
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("leaf certificate is not signed by fixture intermediate: %w", err)
	}
	simulator := &Simulator{
		config: config, leaf: leaf, leafKey: key,
		authHost:    "auth.sa-saopaulo-1.oraclecloud.com",
		computeHost: "iaas.sa-saopaulo-1.oraclecloud.com",
		storageHost: "objectstorage.sa-saopaulo-1.oraclecloud.com",
		reads:       make(map[routeKey]ReadResponse), sessions: make(map[string]session), now: time.Now,
	}
	for _, response := range config.Reads {
		if err := simulator.addRead(response); err != nil {
			return nil, err
		}
	}
	return simulator, nil
}

func (simulator *Simulator) addRead(response ReadResponse) error {
	if len(response.Body) == 0 || response.ETag == "" || response.LastModified.IsZero() ||
		response.RequestURI == "" || strings.Contains(response.RequestURI, "#") {
		return errors.New("OCI read response requires exact path, bytes, ETag, and Last-Modified")
	}
	uri, err := url.ParseRequestURI(response.RequestURI)
	if err != nil || uri.IsAbs() || uri.Path == "" || strings.Contains(uri.Path, "..") ||
		strings.Contains(uri.Path, "//") {
		return errors.New("OCI read response has noncanonical request URI")
	}
	allowed := response.Host == simulator.computeHost && simulator.allowedComputeRead(uri) ||
		response.Host == simulator.storageHost && allowedObjectRead(uri)
	if !allowed {
		return fmt.Errorf("OCI read response host/path is outside pinned endpoints: %s%s", response.Host, response.RequestURI)
	}
	key := routeKey{response.Host, response.RequestURI}
	if _, exists := simulator.reads[key]; exists {
		return errors.New("duplicate OCI read response")
	}
	response.Body = bytes.Clone(response.Body)
	simulator.reads[key] = response
	return nil
}

func (simulator *Simulator) allowedComputeRead(uri *url.URL) bool {
	switch {
	case uri.Path == "/20160918/instances/"+simulator.config.InstanceID:
		return uri.RawQuery == ""
	case uri.Path == "/20160918/vnicAttachments":
		query := uri.Query()
		if query.Get("instanceId") != simulator.config.InstanceID ||
			!strings.HasPrefix(query.Get("compartmentId"), "ocid1.compartment.") ||
			query.Get("limit") != "50" || len(query) < 3 || len(query) > 4 {
			return false
		}
		for key, values := range query {
			if !slices.Contains([]string{"compartmentId", "instanceId", "limit", "page"}, key) || len(values) != 1 {
				return false
			}
		}
		return true
	case strings.HasPrefix(uri.Path, "/20160918/vnics/ocid1.vnic."):
		return uri.RawQuery == "" && !strings.Contains(strings.TrimPrefix(uri.Path, "/20160918/vnics/"), "/")
	default:
		return false
	}
}

func allowedObjectRead(uri *url.URL) bool {
	if uri.RawQuery != "" {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(uri.Path, "/"), "/", 6)
	return len(parts) == 6 && parts[0] == "n" && parts[1] != "" && parts[2] == "b" &&
		parts[3] != "" && parts[4] == "o" && parts[5] != ""
}

func (simulator *Simulator) Requests() []RequestRecord {
	simulator.mu.Lock()
	defer simulator.mu.Unlock()
	return slices.Clone(simulator.requests)
}

func (simulator *Simulator) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	status := simulator.serve(writer, request)
	simulator.mu.Lock()
	simulator.requests = append(simulator.requests, RequestRecord{
		Method: request.Method, Host: request.Host, RequestURI: request.URL.RequestURI(), Status: status,
	})
	simulator.mu.Unlock()
}

func (simulator *Simulator) serve(writer http.ResponseWriter, request *http.Request) int {
	if request.Host == imdsHost && request.Method == http.MethodGet && request.ContentLength == 0 {
		if request.Header.Get("Authorization") != "Bearer Oracle" {
			return reject(writer, http.StatusForbidden)
		}
		var body []byte
		switch request.URL.RequestURI() {
		case "/opc/v2/instance/id":
			body = []byte(simulator.config.InstanceID)
		case "/opc/v2/instance/metadata/terrascale-bootstrap":
			body = []byte(fmt.Sprintf(`{"schemaVersion":1,"slot":%q}`, simulator.config.DescriptorSlot))
		case "/opc/v2/instance/region":
			body = []byte(simulator.config.Region)
		case "/opc/v2/identity/cert.pem":
			body = simulator.config.LeafCertificate
		case "/opc/v2/identity/key.pem":
			body = simulator.config.LeafPrivateKey
		case "/opc/v2/identity/intermediate.pem":
			body = simulator.config.Intermediate
		default:
			return reject(writer, http.StatusNotFound)
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
		return http.StatusOK
	}
	if request.Host == simulator.authHost && request.URL.RequestURI() == "/v1/x509" && request.Method == http.MethodPost {
		return simulator.federate(writer, request)
	}
	if request.Method != http.MethodGet {
		return reject(writer, http.StatusMethodNotAllowed)
	}
	if request.ContentLength != 0 {
		return reject(writer, http.StatusBadRequest)
	}
	response, exists := simulator.reads[routeKey{request.Host, request.URL.RequestURI()}]
	if !exists {
		return reject(writer, http.StatusNotFound)
	}
	if err := simulator.verifyService(request); err != nil {
		return reject(writer, http.StatusForbidden)
	}
	writer.Header().Set("Content-Type", response.ContentType)
	writer.Header().Set("ETag", response.ETag)
	writer.Header().Set("Last-Modified", response.LastModified.UTC().Format(http.TimeFormat))
	writer.Header().Set("Date", simulator.now().UTC().Format(http.TimeFormat))
	writer.Header().Set("Content-Length", fmt.Sprint(len(response.Body)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response.Body)
	return http.StatusOK
}

func reject(writer http.ResponseWriter, status int) int {
	writer.WriteHeader(status)
	return status
}

type federationRequest struct {
	Certificate              string   `json:"certificate"`
	PublicKey                string   `json:"publicKey"`
	IntermediateCertificates []string `json:"intermediateCertificates"`
	FingerprintAlgorithm     string   `json:"fingerprintAlgorithm"`
}

func (simulator *Simulator) federate(writer http.ResponseWriter, request *http.Request) int {
	if request.ContentLength < 1 || request.ContentLength > maxRequest {
		return reject(writer, http.StatusBadRequest)
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxRequest+1))
	if err != nil || len(body) != int(request.ContentLength) || len(body) > maxRequest {
		return reject(writer, http.StatusBadRequest)
	}
	var submitted federationRequest
	if err := json.Unmarshal(body, &submitted); err != nil || submitted.FingerprintAlgorithm != "SHA256" ||
		len(submitted.IntermediateCertificates) != 1 ||
		submitted.Certificate != encodedPEM(simulator.config.LeafCertificate) ||
		submitted.IntermediateCertificates[0] != encodedPEM(simulator.config.Intermediate) {
		return reject(writer, http.StatusForbidden)
	}
	publicDER, err := base64.StdEncoding.DecodeString(submitted.PublicKey)
	if err != nil {
		return reject(writer, http.StatusForbidden)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	public, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok || public.N.BitLen() < 2048 {
		return reject(writer, http.StatusForbidden)
	}
	fingerprint := sha256.Sum256(simulator.leaf.Raw)
	parts := make([]string, len(fingerprint))
	for index, value := range fingerprint {
		parts[index] = hex.EncodeToString([]byte{value})
	}
	keyID := simulator.config.TenancyID + "/fed-x509-sha256/" + strings.Join(parts, ":")
	if err := verifySignature(request, body, &simulator.leafKey.PublicKey, keyID,
		"date (request-target) content-length content-type x-content-sha256", false, simulator.now()); err != nil {
		return reject(writer, http.StatusForbidden)
	}
	expires := simulator.now().Add(tokenLifetime)
	token, err := simulator.newToken(expires)
	if err != nil {
		return reject(writer, http.StatusInternalServerError)
	}
	simulator.mu.Lock()
	simulator.sessions[token] = session{public: public, expires: expires}
	simulator.mu.Unlock()
	response, err := json.Marshal(struct {
		Token string `json:"token"`
	}{Token: token})
	if err != nil {
		return reject(writer, http.StatusInternalServerError)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
	return http.StatusOK
}

func encodedPEM(wire []byte) string {
	block, _ := pem.Decode(wire)
	if block == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func (simulator *Simulator) newToken(expires time.Time) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		Expires int64  `json:"exp"`
		Subject string `json:"sub"`
		ID      string `json:"jti"`
	}{Expires: expires.Unix(), Subject: simulator.config.InstanceID,
		ID: base64.RawURLEncoding.EncodeToString(nonce)})
	if err != nil {
		return "", err
	}
	message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, simulator.leafKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (simulator *Simulator) verifyService(request *http.Request) error {
	match := signatureRE.FindStringSubmatch(request.Header.Get("Authorization"))
	if match == nil || !strings.HasPrefix(match[2], "ST$") {
		return errors.New("missing instance-principal token")
	}
	token := strings.TrimPrefix(match[2], "ST$")
	simulator.mu.Lock()
	session, exists := simulator.sessions[token]
	simulator.mu.Unlock()
	if !exists || !simulator.now().Before(session.expires) {
		return errors.New("unknown or expired instance-principal token")
	}
	return verifySignature(request, nil, session.public, match[2], "date (request-target) host", true, simulator.now())
}

func verifySignature(request *http.Request, body []byte, key *rsa.PublicKey, keyID, expectedHeaders string,
	includeHost bool, now time.Time,
) error {
	match := signatureRE.FindStringSubmatch(request.Header.Get("Authorization"))
	if match == nil || match[1] != expectedHeaders || match[2] != keyID {
		return errors.New("unexpected OCI signature fields")
	}
	date, err := http.ParseTime(request.Header.Get("Date"))
	if err != nil || date.Before(now.Add(-maxClockSkew)) || date.After(now.Add(maxClockSkew)) {
		return errors.New("OCI signature date is outside the allowed window")
	}
	lines := []string{"date: " + request.Header.Get("Date"),
		"(request-target): " + strings.ToLower(request.Method) + " " + request.URL.RequestURI()}
	if includeHost {
		lines = append(lines, "host: "+request.Host)
	} else {
		// net/http removes Content-Length from incoming Header after parsing it.
		// Reconstruct the value signed by the SDK from the validated length.
		contentLength := fmt.Sprint(request.ContentLength)
		if request.ContentLength != int64(len(body)) ||
			request.Header.Get("Content-Length") != "" && request.Header.Get("Content-Length") != contentLength ||
			request.Header.Get("Content-Type") != "application/json" {
			return errors.New("invalid signed federation body metadata")
		}
		digest := sha256.Sum256(body)
		if request.Header.Get("X-Content-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
			return errors.New("federation body hash mismatch")
		}
		lines = append(lines, "content-length: "+contentLength,
			"content-type: "+request.Header.Get("Content-Type"),
			"x-content-sha256: "+request.Header.Get("X-Content-Sha256"))
	}
	signature, err := base64.StdEncoding.DecodeString(match[3])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}
