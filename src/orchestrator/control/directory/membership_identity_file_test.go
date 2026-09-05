package directory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func membershipKeyPEM(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestMembershipIdentityPersistsAcrossLoads(t *testing.T) {
	data := membershipKeyPEM(t, elliptic.P256())
	path := filepath.Join(t.TempDir(), "identity.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := RegionalRuntimeMembershipIdentityLoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Dispose()
	second, err := RegionalRuntimeMembershipIdentityLoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Dispose()
	keyID, public, err := RegionalRuntimeMembershipPublicKeyFromPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyId != second.KeyId || first.PublicKey != second.PublicKey || first.KeyId != keyID || first.PublicKey != public {
		t.Fatal("restart changed persisted membership identity")
	}
	membership := newRegionalRuntimeMembershipForHeartbeat(nil, nil)
	defer membership.identity.Dispose()
	record, err := membership.document(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record.IdentityKeyId = first.KeyId
	record.IdentityPublicKey = first.PublicKey
	record.IdentitySignature = first.Sign(record)
	if !RegionalRuntimeMembershipIdentityVerify(record) {
		t.Fatal("persisted identity broke PKIX P-256 wire verification")
	}
	first.Dispose()
	if first.Sign(record) != "" || second.Sign(record) == "" {
		t.Fatal("identity disposal affected another load or retained signing ability")
	}
}

func TestMembershipIdentityFilesRejectUnsafeInputs(t *testing.T) {
	valid := membershipKeyPEM(t, elliptic.P256())
	for _, kind := range []string{"missing", "public-mode", "symlink", "parent-symlink", "hardlink", "fifo", "p384", "trailing", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "identity.pem")
			data := valid
			if kind == "p384" {
				data = membershipKeyPEM(t, elliptic.P384())
			}
			if kind == "trailing" {
				data = append(append([]byte(nil), valid...), valid...)
			}
			if kind == "malformed" {
				data = []byte("SECRET_CANARY")
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "missing":
				err = os.Remove(path)
			case "public-mode":
				err = os.Chmod(path, 0644)
			case "symlink":
				target := filepath.Join(dir, "link")
				err = os.Symlink(path, target)
				path = target
			case "parent-symlink":
				target := filepath.Join(t.TempDir(), "link")
				err = os.Symlink(dir, target)
				path = filepath.Join(target, "identity.pem")
			case "hardlink":
				err = os.Link(path, filepath.Join(dir, "other"))
			case "fifo":
				path = filepath.Join(dir, "fifo")
				err = syscall.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RegionalRuntimeMembershipIdentityLoadFile(path); err == nil || strings.Contains(err.Error(), "SECRET_CANARY") {
				t.Fatalf("key admission: %v", err)
			}
			if kind == "missing" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("missing identity was regenerated")
				}
			}
		})
	}
}

func TestMembershipPinsRequireExplicitCanonicalP256Keys(t *testing.T) {
	_, public, err := RegionalRuntimeMembershipPublicKeyFromPEM(membershipKeyPEM(t, elliptic.P256()))
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"controller-1":"` + public + `"}`
	for _, data := range []string{`{}`, `null`, valid + `{}`, `{"controller-1":null}`, `{"bad.instance":"` + public + `"}`, strings.TrimSuffix(valid, "}") + `,"controller-1":"` + public + `"}`, `{"controller-1":"invalid"}`} {
		if _, err := parseMembershipPins([]byte(data)); err == nil {
			t.Fatal("invalid pin map accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "pins.json")
	if err := os.WriteFile(path, []byte(valid), 0444); err != nil {
		t.Fatal(err)
	}
	pins, err := RegionalRuntimeMembershipPinsLoadFile(path)
	if err != nil || pins["controller-1"] != public {
		t.Fatalf("public pin file admission: %v", err)
	}
}

type pinWatchStore struct {
	jetstream.KeyValue
	watcher jetstream.KeyWatcher
}

func (s pinWatchStore) Watch(context.Context, string, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	return s.watcher, nil
}

type pinWatcher struct {
	jetstream.KeyWatcher
	updates chan jetstream.KeyValueEntry
}

func (w pinWatcher) Updates() <-chan jetstream.KeyValueEntry { return w.updates }
func (w pinWatcher) Stop() error                             { return nil }

type pinEntry struct {
	jetstream.KeyValueEntry
	key   string
	value []byte
}

func (e pinEntry) Key() string                     { return e.key }
func (e pinEntry) Value() []byte                   { return e.value }
func (e pinEntry) Operation() jetstream.KeyValueOp { return jetstream.KeyValuePut }

func TestMembershipWatchNeverLearnsOrReplacesPins(t *testing.T) {
	for _, kind := range []string{"unknown", "changed-after-expiry", "admitted"} {
		t.Run(kind, func(t *testing.T) {
			membership := newRegionalRuntimeMembershipForHeartbeat(nil, nil)
			defer membership.identity.Dispose()
			updates := make(chan jetstream.KeyValueEntry)
			membership.store = pinWatchStore{watcher: pinWatcher{updates: updates}}
			record, err := membership.document(time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			key := "controller." + record.Instance
			if kind == "changed-after-expiry" {
				old, err := RegionalRuntimeMembershipIdentityCreate()
				if err != nil {
					t.Fatal(err)
				}
				defer old.Dispose()
				membership.identityPins[key] = old.PublicKey
				previous := record
				previous.LeaseExpiresAt = time.Now().Add(-time.Hour)
				previous.IdentityPublicKey = old.PublicKey
				membership.members[key] = previous
			}
			if kind == "admitted" {
				membership.identityPins[key] = record.IdentityPublicKey
			}
			wantPin := membership.identityPins[key]
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			go membership.watchLoop()
			updates <- pinEntry{key: key, value: data}
			deadline := time.After(time.Second)
			for {
				membership.membersMu.Lock()
				_, accepted := membership.members[key]
				membership.membersMu.Unlock()
				if (kind == "admitted" && accepted) || (kind != "admitted" && atomic.LoadInt64(&membership.rejectedRecords) > 0) {
					break
				}
				select {
				case <-deadline:
					t.Fatal("unadmitted identity not rejected")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			membership.stopping()
			close(updates)
			<-membership.watchLoopDone
			wantMembers := 0
			if kind == "admitted" {
				wantMembers = 1
			}
			if len(membership.members) != wantMembers || membership.identityPins[key] != wantPin {
				t.Fatal("observed key learned, replaced or deleted explicit admission pin")
			}
		})
	}
}

func TestMembershipRequiresExplicitMatchingSelfPin(t *testing.T) {
	membership := newRegionalRuntimeMembershipForHeartbeat(nil, nil)
	defer membership.identity.Dispose()
	for _, pins := range []map[string]string{nil, {"other-controller": membership.identity.PublicKey}, {membership.topology.Instance: "invalid"}} {
		_, err := RegionalRuntimeMembershipStartAsync(context.Background(), membership.store, membership.topology, membership.build, membership.capabilities, membership.startedAt, membership.authority, membership.identity, pins)
		if err == nil {
			t.Fatal("membership started without its admitted self pin")
		}
	}
}
