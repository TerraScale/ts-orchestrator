// Package scenario contains fixtures used only inside disposable native image qualification hosts.
package scenario

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ObjectStore retains actual backup archives on the replacement host. Every
// request crosses the signed OCI SDK HTTP boundary, including recovery reads.
type ObjectStore struct {
	Root      string
	PublicKey *rsa.PublicKey
	mu        sync.Mutex
}

func (s *ObjectStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := verifySDKSignature(r, s.PublicKey); err != nil {
		http.Error(w, "SDK signature rejected", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/n/tenancy/b/"), "/", 3)
	if len(parts) == 0 || parts[0] != "netbird-gru" && parts[0] != "netbird-sfo" || !strings.HasPrefix(r.URL.Path, "/n/tenancy/b/") {
		http.Error(w, "fixture bucket absent", http.StatusNotFound)
		return
	}
	bucket := parts[0]
	region := "sa-saopaulo-1"
	if bucket == "netbird-sfo" {
		region = "us-sanjose-1"
	}
	kms := "ocid1.key.oc1." + region + "." + bucket
	write := func(value any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.MarshalWrite(w, value); err != nil {
			return
		}
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		write(map[string]any{"id": "ocid1.bucket.oc1." + region + "." + bucket, "name": bucket, "namespace": "tenancy", "compartmentId": "ocid1.compartment.oc1..control", "kmsKeyId": kms, "publicAccessType": "NoPublicAccess", "etag": "fixture-bucket", "timeCreated": "2026-01-01T00:00:00Z", "createdBy": "native-qualification"})
		return
	}
	if len(parts) == 2 && parts[1] == "retentionRules" && r.Method == http.MethodGet {
		write(map[string]any{"items": []any{map[string]any{"id": "native-retention", "displayName": "native-retention", "etag": "fixture-retention", "timeCreated": "2020-01-01T00:00:00Z", "timeModified": "2020-01-01T00:00:00Z", "timeRuleLocked": "2020-01-01T00:00:00Z", "duration": map[string]any{"timeAmount": 7, "timeUnit": "DAYS"}}}})
		return
	}
	if len(parts) == 2 && parts[1] == "o" && r.Method == http.MethodGet {
		inventory := []map[string]any{}
		root := filepath.Join(s.Root, bucket)
		err := filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if strings.HasPrefix(relative, r.URL.Query().Get("prefix")) {
				inventory = append(inventory, map[string]any{"name": relative, "size": info.Size()})
			}
			return nil
		})
		if err != nil {
			http.Error(w, "inventory failed", 500)
			return
		}
		slices.SortFunc(inventory, func(a, b map[string]any) int { return strings.Compare(a["name"].(string), b["name"].(string)) })
		write(map[string]any{"objects": inventory})
		return
	}
	if len(parts) != 3 || parts[1] != "o" || !filepath.IsLocal(parts[2]) {
		http.Error(w, "invalid fixture object", 400)
		return
	}
	name := filepath.Join(s.Root, bucket, parts[2])
	switch r.Method {
	case http.MethodPut:
		if r.ContentLength < 0 || r.ContentLength > 256<<20 || r.Header.Get("If-None-Match") != "*" || r.Header.Get("Opc-Sse-Kms-Key-Id") != kms {
			http.Error(w, "backup protection rejected", 400)
			return
		}
		wire, err := io.ReadAll(io.LimitReader(r.Body, (256<<20)+1))
		if err != nil || int64(len(wire)) != r.ContentLength {
			http.Error(w, "backup body rejected", 400)
			return
		}
		defer clear(wire)
		digest := sha256.Sum256(wire)
		if r.Header.Get("Opc-Content-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) || !strings.HasSuffix(parts[2], "/"+hex.EncodeToString(digest[:])+".tar") {
			http.Error(w, "backup checksum rejected", 400)
			return
		}
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			http.Error(w, "storage failed", 500)
			return
		}
		file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		if err != nil {
			http.Error(w, "storage failed", 500)
			return
		}
		_, writeErr := file.Write(wire)
		err = errors.Join(writeErr, file.Sync(), file.Close())
		if err != nil {
			_ = os.Remove(name)
			http.Error(w, "storage failed", 500)
			return
		}
		w.Header().Set("etag", hex.EncodeToString(digest[:]))
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		file, err := os.Open(name)
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "storage failed", 500)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			http.Error(w, "storage failed", 500)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		w.Header().Set("etag", strings.TrimSuffix(filepath.Base(name), ".tar"))
		_, _ = io.Copy(w, file)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func verifySDKSignature(r *http.Request, key *rsa.PublicKey) error {
	if key == nil {
		return errors.New("missing fixture public key")
	}
	authorization, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Signature ")
	if !ok {
		return errors.New("missing SDK signature")
	}
	parameters := map[string]string{}
	for part := range strings.SplitSeq(authorization, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return errors.New("invalid SDK signature")
		}
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return err
		}
		parameters[name] = decoded
	}
	if parameters["algorithm"] != "rsa-sha256" {
		return errors.New("wrong SDK signing algorithm")
	}
	date, err := http.ParseTime(r.Header.Get("Date"))
	if err != nil || time.Since(date) > 5*time.Minute || time.Until(date) > 5*time.Minute {
		return errors.New("stale SDK signature")
	}
	var canonical []string
	hasTarget, hasDate, hasHost := false, false, false
	for header := range strings.FieldsSeq(parameters["headers"]) {
		value := r.Header.Get(header)
		switch header {
		case "(request-target)":
			value = strings.ToLower(r.Method) + " " + r.URL.RequestURI()
			hasTarget = true
		case "host":
			value = r.Host
			hasHost = true
		case "content-length":
			value = strconv.FormatInt(r.ContentLength, 10)
		case "date":
			hasDate = true
		}
		canonical = append(canonical, header+": "+value)
	}
	if !hasTarget || !hasDate || !hasHost {
		return errors.New("incomplete SDK signature")
	}
	signature, err := base64.StdEncoding.DecodeString(parameters["signature"])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}
