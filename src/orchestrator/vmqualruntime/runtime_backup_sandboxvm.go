//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/objectstore"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

const backupFixtureHostname = "fly.storage.tigris.dev"

type backupFixtureCredential struct {
	access, secret []byte
	bucket, region string
}
type qualificationBackupFixture struct {
	credentials []backupFixtureCredential
	store       *objectstore.Server
	server      *http.Server
	listener    net.Listener
	done        chan error
}

func loadQualificationBackup(path string) (*qualificationBackupFixture, error) {
	if path == "" {
		return nil, nil
	}
	data, err := initialgrant.ReadMaterialFile(path, 1<<20, false)
	if err != nil {
		return nil, err
	}
	var declaration vmengineconfig.Declaration
	if err := json.Unmarshal(data, &declaration); err != nil {
		return nil, err
	}
	fixture := &qualificationBackupFixture{}
	success := false
	defer func() {
		if !success {
			_ = fixture.close(context.Background())
		}
	}()
	for _, db := range declaration.Databases {
		if db.Backup == nil {
			continue
		}
		for _, destination := range db.Backup.Destinations {
			if destination.Provider != "tigris" || destination.Endpoint != "https://"+backupFixtureHostname || destination.SigningRegion != "auto" {
				return nil, errors.New("vmqual: local backup fixture requires its isolated declared Tigris endpoint")
			}
			access, err := initialgrant.ReadMaterialFile(destination.AccessKeyFile, 16<<10, true)
			if err != nil {
				return nil, err
			}
			secret, err := initialgrant.ReadMaterialFile(destination.SecretKeyFile, 16<<10, true)
			if err != nil {
				clear(access)
				return nil, err
			}
			fixture.credentials = append(fixture.credentials, backupFixtureCredential{access: bytes.TrimSpace(access), secret: bytes.TrimSpace(secret), bucket: destination.Bucket, region: destination.SigningRegion})
		}
	}
	success = true
	return fixture, nil
}

func (services *qualificationRuntimeServices) startBackup(ctx context.Context) error {
	fixture := services.backup
	if fixture == nil || len(fixture.credentials) == 0 {
		return nil
	}
	store, err := objectstore.New(objectstore.Config{Namespace: "vmqual-backup", MaxBytes: 256 << 20, MaxObjectBytes: 16 << 20})
	if err != nil {
		return err
	}
	fixture.store = store
	buckets := map[string]bool{}
	for _, credential := range fixture.credentials {
		if buckets[credential.bucket] {
			continue
		}
		buckets[credential.bucket] = true
		body, _ := json.Marshal(map[string]string{"name": credential.bucket})
		request := httptest.NewRequest(http.MethodPost, "http://fixture/n/vmqual-backup/b", bytes.NewReader(body))
		response := httptest.NewRecorder()
		store.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			return errors.New("vmqual: create local backup fixture bucket")
		}
	}
	plan, _ := services.plan.Listener("backup")
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", net.JoinHostPort(plan.Address, strconv.Itoa(int(plan.Port))))
	if err != nil {
		return err
	}
	fixture.listener = listener
	fixture.server = &http.Server{Handler: fixture, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	fixture.done = make(chan error, 1)
	go func() {
		fixture.done <- fixture.server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{services.tlsCertificate}}))
	}()
	return nil
}

// ServeHTTP adapts the signed S3 single-object contract to the durable local OCI
// handler. It deliberately does not claim provider or residency qualification.
func (fixture *qualificationBackupFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != backupFixtureHostname || r.URL.RawQuery != "" || (r.Method != http.MethodPut && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodDelete) {
		http.Error(w, "unsupported fixture request", http.StatusBadRequest)
		return
	}
	bucket, key, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !ok || key == "" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
	if err != nil {
		http.Error(w, "object too large", http.StatusRequestEntityTooLarge)
		return
	}
	authenticated := false
	for _, credential := range fixture.credentials {
		if credential.bucket == bucket && verifyBackupSignature(r, body, credential) {
			authenticated = true
			break
		}
	}
	if !authenticated {
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}
	forwarded := r.Clone(r.Context())
	forwarded.URL = r.URL.Clone()
	forwarded.URL.Path = "/n/vmqual-backup/b/" + bucket + "/o/" + key
	forwarded.URL.RawPath = "/n/vmqual-backup/b/" + url.PathEscape(bucket) + "/o/" + url.PathEscape(key)
	forwarded.Body = io.NopCloser(bytes.NewReader(body))
	fixture.store.ServeHTTP(w, forwarded)
}

func backupHMAC(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = io.WriteString(h, value)
	return h.Sum(nil)
}
func backupSHA(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func verifyBackupSignature(r *http.Request, body []byte, c backupFixtureCredential) bool {
	auth, ok := strings.CutPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ")
	if !ok {
		return false
	}
	fields := map[string]string{}
	for part := range strings.SplitSeq(auth, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || fields[key] != "" {
			return false
		}
		fields[key] = value
	}
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 || scope[0] != string(c.access) || scope[2] != c.region || scope[3] != "s3" || scope[4] != "aws4_request" {
		return false
	}
	stamp := r.Header.Get("X-Amz-Date")
	when, err := time.Parse("20060102T150405Z", stamp)
	if err != nil || len(stamp) < 8 || stamp[:8] != scope[1] || time.Since(when) > 5*time.Minute || time.Until(when) > 5*time.Minute {
		return false
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload != "UNSIGNED-PAYLOAD" && payload != backupSHA(body) {
		return false
	}
	names := strings.Split(fields["SignedHeaders"], ";")
	var headers strings.Builder
	host, date := false, false
	for i, name := range names {
		if name == "" || name != strings.ToLower(name) || (i > 0 && names[i-1] >= name) {
			return false
		}
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
			host = true
		}
		if name == "x-amz-date" {
			date = true
		}
		if value == "" {
			return false
		}
		headers.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	if !host || !date {
		return false
	}
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n\n" + headers.String() + "\n" + fields["SignedHeaders"] + "\n" + payload
	signingScope := strings.Join(scope[1:], "/")
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + signingScope + "\n" + backupSHA([]byte(canonical))
	key := backupHMAC(append([]byte("AWS4"), c.secret...), scope[1])
	defer clear(key)
	regionKey := backupHMAC(key, c.region)
	defer clear(regionKey)
	serviceKey := backupHMAC(regionKey, "s3")
	defer clear(serviceKey)
	signingKey := backupHMAC(serviceKey, "aws4_request")
	defer clear(signingKey)
	signature, err := hex.DecodeString(fields["Signature"])
	return err == nil && hmac.Equal(signature, backupHMAC(signingKey, toSign))
}

func (fixture *qualificationBackupFixture) close(ctx context.Context) error {
	if fixture == nil {
		return nil
	}
	var errs []error
	if fixture.server != nil {
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		err := fixture.server.Shutdown(bounded)
		if err != nil {
			_ = fixture.server.Close()
		}
		errs = append(errs, err)
		if fixture.done != nil {
			err = <-fixture.done
			if !errors.Is(err, http.ErrServerClosed) {
				errs = append(errs, err)
			}
		}
		fixture.server, fixture.listener, fixture.done = nil, nil, nil
	}
	if fixture.store != nil {
		errs = append(errs, fixture.store.Close())
		fixture.store = nil
	}
	for _, credential := range fixture.credentials {
		clear(credential.access)
		clear(credential.secret)
	}
	fixture.credentials = nil
	return errors.Join(errs...)
}
