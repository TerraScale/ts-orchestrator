// Package ociinstance provides an explicit mTLS OCI qualification endpoint. It
// exercises the official SDK metadata and federation exchange and verifies real
// HTTP signatures; it is not evidence of OCI IAM or real provider operation.
package ociinstance

import (
	"crypto"
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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	identity "terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

type Bucket struct {
	OCIRegion   string
	Observation provider.OCIBucketObservation
}
type Config struct {
	Buckets        []Bucket
	MaxObjectBytes int64
	TokenLifetime  time.Duration
	BeforeRequest  func(*http.Request)
}
type Request struct {
	Node, Method, Host, Path string
	Failure                  string
}
type credential struct {
	region, certificate, key string
	public                   *rsa.PublicKey
}
type object struct {
	body         []byte
	digest, etag string
}
type Server struct {
	mu         sync.Mutex
	server     *httptest.Server
	ca         *x509.Certificate
	caKey      *rsa.PrivateKey
	caPEM      string
	cfg        Config
	identities map[string]credential
	sessions   map[string]*rsa.PublicKey
	buckets    map[string]provider.OCIBucketObservation
	objects    map[string]object
	requests   []Request
}

func New(cfg Config) (*Server, error) {
	if cfg.MaxObjectBytes == 0 {
		cfg.MaxObjectBytes = 64 << 20
	}
	if cfg.MaxObjectBytes < 1 || cfg.MaxObjectBytes > 1<<30 {
		return nil, errors.New("OCI fixture: invalid object limit")
	}
	if cfg.TokenLifetime == 0 {
		cfg.TokenLifetime = time.Hour
	}
	s := &Server{cfg: cfg, identities: map[string]credential{}, sessions: map[string]*rsa.PublicKey{}, buckets: map[string]provider.OCIBucketObservation{}, objects: map[string]object{}}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OCI qualification CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	s.ca, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	s.caKey = caKey
	s.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	serverPEM, serverKey, _, err := s.issue("oci-fixture", true)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair([]byte(serverPEM), serverKey)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(s.caPEM))
	for _, bucket := range cfg.Buckets {
		if err = s.SetBucket(bucket); err != nil {
			return nil, err
		}
	}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.server.StartTLS()
	return s, nil
}
func (s *Server) Close() {
	if s != nil && s.server != nil {
		s.server.Close()
	}
}
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}
func (s *Server) SetBucket(bucket Bucket) error {
	if identity.ValidateConfig(identity.Config{Region: bucket.OCIRegion}) != nil || bucket.Observation.Namespace == "" || bucket.Observation.Name == "" {
		return errors.New("OCI fixture: invalid bucket")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o := bucket.Observation
	o.FreeformTags = provider.CopyOCITags(o.FreeformTags)
	s.buckets[bucket.OCIRegion+"/"+o.Namespace+"/"+o.Name] = o
	return nil
}
func (s *Server) Identity(node, region, keyFile string) (identity.Config, []byte, error) {
	if identity.ValidateConfig(identity.Config{Region: region}) != nil || node == "" {
		return identity.Config{}, nil, errors.New("OCI fixture: invalid identity")
	}
	clientPEM, clientKey, _, err := s.issue(node, false)
	if err != nil {
		return identity.Config{}, nil, err
	}
	instancePEM, instanceKey, instancePublic, err := s.issue("opc-tenant:ocid1.tenancy.oc1..qualification", false)
	if err != nil {
		return identity.Config{}, nil, err
	}
	cfg := identity.Config{Region: region, Qualification: &identity.QualificationConfig{Endpoint: s.server.URL, ServerName: "oci-fixture", RootCAPEM: s.caPEM, ClientCertificatePEM: clientPEM, ClientPrivateKeyFile: keyFile}}
	if identity.ValidateConfig(cfg) != nil {
		return identity.Config{}, nil, errors.New("OCI fixture: invalid qualification config")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.identities[node]; exists {
		return identity.Config{}, nil, errors.New("OCI fixture: duplicate identity")
	}
	s.identities[node] = credential{region: region, certificate: instancePEM, key: string(instanceKey), public: instancePublic}
	return cfg, clientKey, nil
}
func (s *Server) issue(name string, server bool) (string, []byte, *rsa.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", nil, nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert.DNSNames = []string{name}
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, s.ca, &key.PublicKey, s.caKey)
	if err != nil {
		return "", nil, nil, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), &key.PublicKey, nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if s.cfg.BeforeRequest != nil {
		s.cfg.BeforeRequest(r)
	}
	if r.Context().Err() != nil {
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "identity required", 403)
		return
	}
	node := r.TLS.PeerCertificates[0].Subject.CommonName
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.identities[node]
	if !ok {
		http.Error(w, "unknown identity", 403)
		return
	}
	s.requests = append(s.requests, Request{Node: node, Method: r.Method, Host: r.Host, Path: r.URL.Path})
	if r.Host == "169.254.169.254" {
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer Oracle" {
			http.Error(w, "invalid metadata request", 403)
			return
		}
		switch r.URL.Path {
		case "/opc/v2/instance/region":
			io.WriteString(w, credential.region)
		case "/opc/v2/identity/cert.pem", "/opc/v2/identity/intermediate.pem":
			io.WriteString(w, credential.certificate)
		case "/opc/v2/identity/key.pem":
			io.WriteString(w, credential.key)
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.Host == "auth."+credential.region+".oraclecloud.com" && r.URL.Path == "/v1/x509" && r.Method == "POST" {
		body, err := io.ReadAll(io.LimitReader(r.Body, (256<<10)+1))
		if err != nil || len(body) > 256<<10 || !verifySignature(r, body, credential.public, false) {
			s.requests[len(s.requests)-1].Failure = "federation signature rejected"
			http.Error(w, "invalid federation", 403)
			return
		}
		var payload struct {
			PublicKey string `json:"publicKey"`
		}
		if json.Unmarshal(body, &payload) != nil {
			s.requests[len(s.requests)-1].Failure = "federation rejected"
			http.Error(w, "invalid federation payload", 400)
			return
		}
		der, err := base64.StdEncoding.DecodeString(payload.PublicKey)
		if err != nil {
			s.requests[len(s.requests)-1].Failure = "federation key rejected"
			http.Error(w, "invalid federation key", 400)
			return
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			s.requests[len(s.requests)-1].Failure = "federation key rejected"
			http.Error(w, "invalid federation key", 400)
			return
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			s.requests[len(s.requests)-1].Failure = "federation key rejected"
			http.Error(w, "invalid federation key", 400)
			return
		}
		claims, _ := json.Marshal(map[string]any{"exp": time.Now().Add(s.cfg.TokenLifetime).Unix(), "iat": time.Now().Unix(), "sub": node, "jti": fmt.Sprint(len(s.sessions) + 1)})
		token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".qualification"
		s.sessions["ST$"+token] = key
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
		return
	}
	key := s.sessions[signatureFields(r.Header.Get("Authorization"))["keyId"]]
	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxObjectBytes+1))
	if err != nil || int64(len(body)) > s.cfg.MaxObjectBytes || key == nil || !verifySignature(r, body, key, true) {
		http.Error(w, "invalid object request", 403)
		return
	}
	const prefix = "objectstorage."
	const suffix = ".oraclecloud.com"
	if !strings.HasPrefix(r.Host, prefix) || !strings.HasSuffix(r.Host, suffix) {
		http.NotFound(w, r)
		return
	}
	region := strings.TrimSuffix(strings.TrimPrefix(r.Host, prefix), suffix)
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 6)
	if len(parts) < 4 || parts[0] != "n" || parts[2] != "b" {
		http.NotFound(w, r)
		return
	}
	bucket, bucketExists := s.buckets[region+"/"+parts[1]+"/"+parts[3]]
	if !bucketExists {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 4 && r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bucket)
		return
	}
	if len(parts) != 6 || parts[4] != "o" || parts[5] == "" {
		http.NotFound(w, r)
		return
	}
	objectKey := r.Host + r.URL.Path
	prior, found := s.objects[objectKey]
	switch r.Method {
	case "PUT":
		if r.Header.Get("If-None-Match") != "*" {
			http.Error(w, "immutable put required", 400)
			return
		}
		if found {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		digest := sha256.Sum256(body)
		hexDigest := hex.EncodeToString(digest[:])
		if r.Header.Get("opc-meta-terrascale-sha256") != hexDigest {
			http.Error(w, "digest mismatch", 400)
			return
		}
		s.objects[objectKey] = object{body: append([]byte(nil), body...), digest: hexDigest, etag: hexDigest}
		w.Header().Set("Etag", hexDigest)
		w.WriteHeader(200)
	case "HEAD", "GET":
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Etag", prior.etag)
		w.Header().Set("Content-Length", strconv.Itoa(len(prior.body)))
		w.Header().Set("opc-meta-terrascale-sha256", prior.digest)
		if r.Method == "GET" {
			w.Write(prior.body)
		}
	default:
		http.Error(w, "method not allowed", 405)
	}
}

var signaturePattern = regexp.MustCompile(`([A-Za-z]+)="([^"]*)"`)

func signatureFields(value string) map[string]string {
	out := map[string]string{}
	for _, match := range signaturePattern.FindAllStringSubmatch(value, -1) {
		out[match[1]] = match[2]
	}
	return out
}
func verifySignature(r *http.Request, body []byte, key *rsa.PublicKey, requireHost bool) bool {
	fields := signatureFields(r.Header.Get("Authorization"))
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") || fields["algorithm"] != "rsa-sha256" || fields["version"] != "1" {
		return false
	}
	names := strings.Fields(fields["headers"])
	if len(names) < 3 {
		return false
	}
	var canonical []string
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			return false
		}
		seen[name] = true
		value := r.Header.Get(name)
		switch name {
		case "(request-target)":
			value = strings.ToLower(r.Method) + " " + r.URL.RequestURI()
		case "host":
			value = r.Host
		case "content-length":
			value = strconv.FormatInt(r.ContentLength, 10)
		}
		canonical = append(canonical, name+": "+value)
	}
	if !seen["(request-target)"] || (requireHost && !seen["host"]) || !seen["date"] {
		return false
	}
	if len(body) > 0 {
		digest := sha256.Sum256(body)
		if !seen["x-content-sha256"] || !seen["content-length"] || !seen["content-type"] || r.Header.Get("x-content-sha256") != base64.StdEncoding.EncodeToString(digest[:]) || r.ContentLength != int64(len(body)) {
			return false
		}
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return false
	}
	hash := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature) == nil
}

// Object returns a copy for qualification assertions only. Workers use the
// real signed HTTP GET path above.
func (s *Server) Object(region, namespace, bucket, key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.objects["objectstorage."+region+".oraclecloud.com/n/"+namespace+"/b/"+bucket+"/o/"+key]
	return append([]byte(nil), stored.body...), ok
}
