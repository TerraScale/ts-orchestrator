package preliminarycapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

func storeConfig(t *testing.T) StoreConfig {
	t.Helper()
	verified, signed := verifiedRequest(t)
	return StoreConfig{Context: context.Background(), OutputDir: filepath.Join(t.TempDir(), "capture"), Request: verified, SignedRequest: signed, MaxSnapshotBytes: 1024, MaxTotalBytes: 2048}
}
func TestStoreImmutableReadbackQuotaAndRequestPin(t *testing.T) {
	c := storeConfig(t)
	s, err := NewStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	key, _ := ObjectKey("REGIONAL", "EVENTS", 1)
	body := bytes.Repeat([]byte{1}, 1024)
	if err := s.Put(ctx, "gru", "REGIONAL", key, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "gru", "REGIONAL", key, body); err != nil {
		t.Fatal(err)
	}
	altered := append([]byte(nil), body...)
	altered[0]++
	if s.Put(ctx, "gru", "REGIONAL", key, altered) == nil {
		t.Fatal("immutable overwrite allowed")
	}
	id, found, err := s.Head(ctx, "gru", "REGIONAL", key)
	if err != nil || !found || id.Digest != delivery.SHA256Digest(body) || id.Size != 1024 {
		t.Fatalf("identity: %+v %v", id, err)
	}
	got, found, err := s.GetSnapshot(ctx, "gru", "REGIONAL", key)
	if err != nil || !found || !bytes.Equal(got, body) {
		t.Fatal("durable readback changed")
	}
	second, _ := ObjectKey("REGIONAL", "KV_STATE", 1)
	third, _ := ObjectKey("GLOBAL", "SPEC", 1)
	if err := s.Put(ctx, "gru", "REGIONAL", second, body); err != nil {
		t.Fatal(err)
	}
	if s.Put(ctx, "gru", "GLOBAL", third, []byte("over quota")) == nil {
		t.Fatal("total quota ignored")
	}
	if s.Put(ctx, "sfo", "REGIONAL", key, body) == nil || s.Put(ctx, "gru", "GLOBAL", key, body) == nil {
		t.Fatal("unadmitted region/account accepted")
	}
	if _, err := NewStore(c); err == nil {
		t.Fatal("concurrent exclusive owner accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A crashed writer's validated unreferenced temporary file is removable.
	if err := os.WriteFile(filepath.Join(c.OutputDir, ".staging-0123456789abcdef0123456789abcdef"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.OutputDir, ".staging-0123456789abcdef0123456789abcdef")); !os.IsNotExist(err) {
		t.Fatal("stale partial was not removed")
	}
	alternate := storeConfig(t)
	alternate.OutputDir = c.OutputDir
	if _, err := NewStore(alternate); err == nil {
		t.Fatal("output repinned to other signed request")
	}
}
func TestStoreRejectsLinksForeignEntriesAndWritableAncestry(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "foreign", "writable", "staging-impostor"} {
		t.Run(kind, func(t *testing.T) {
			c := storeConfig(t)
			s, err := NewStore(c)
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			key, _ := ObjectKey("REGIONAL", "EVENTS", 1)
			target := filepath.Join(c.OutputDir, objectFile(key))
			external := filepath.Join(t.TempDir(), "external")
			if err := os.WriteFile(external, []byte("protected"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				err = os.Symlink(external, target)
			case "hardlink":
				err = os.Link(external, target)
			case "staging-impostor":
				err = os.WriteFile(filepath.Join(c.OutputDir, ".staging-foo"), []byte("user-file"), 0600)
			case "foreign":
				err = os.WriteFile(filepath.Join(c.OutputDir, "foreign"), nil, 0600)
			case "writable":
				err = os.Chmod(c.OutputDir, 0777)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewStore(c); err == nil {
				t.Fatal("unsafe output accepted")
			}
			if kind == "staging-impostor" {
				raw, err := os.ReadFile(filepath.Join(c.OutputDir, ".staging-foo"))
				if err != nil || string(raw) != "user-file" {
					t.Fatal("non-staging user file removed")
				}
			}
			raw, _ := os.ReadFile(external)
			if string(raw) != "protected" {
				t.Fatal("external file changed")
			}
		})
	}
}
func TestStoreReceiptRequiresCompleteDurableInventory(t *testing.T) {
	c := storeConfig(t)
	c.MaxTotalBytes = 4096
	s, err := NewStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	signer, public := captureSigner(t)
	receipt := Receipt{Version: 1, Preliminary: true, TransitionID: c.Request.Request.TransitionID, RequestSHA256: c.Request.Digest, SourceNodeID: c.Request.Request.SourceNodeID, ControlEpoch: 1, CreatedAt: time.Now().UTC()}
	for _, account := range c.Request.Request.Accounts {
		for _, stream := range account.Streams {
			key, _ := ObjectKey(account.Account, stream, 1)
			body := []byte(stream)
			if err := s.Put(context.Background(), "gru", account.Account, key, body); err != nil {
				t.Fatal(err)
			}
			receipt.Objects = append(receipt.Objects, Object{Account: account.Account, Stream: stream, Key: key, SHA256: delivery.SHA256Digest(body), Size: int64(len(body)), CreatedAt: receipt.CreatedAt})
		}
	}
	raw, err := SignReceipt(signer, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(public, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequest(public, raw); err == nil {
		t.Fatal("source receipt authorizes request")
	}
	if err := s.PublishReceipt(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishReceipt(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	stored, found, err := s.ReadReceipt()
	if err != nil || !found || !bytes.Equal(stored, raw) {
		t.Fatal("receipt changed")
	}
	_, other := captureSigner(t)
	if _, err := VerifyReceipt(other, raw); err == nil {
		t.Fatal("other source identity accepted")
	}
	if err := os.WriteFile(filepath.Join(c.OutputDir, objectFile(receipt.Objects[0].Key)), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadReceipt(); err == nil {
		t.Fatal("receipt outlived corrupted artifact")
	}
}
func TestStoreProcessExclusiveOwnership(t *testing.T) {
	if raw := os.Getenv("TS_PRELIMINARY_LOCK_HELPER"); raw != "" {
		var c StoreConfig
		if json.Unmarshal([]byte(raw), &c) != nil {
			os.Exit(3)
		}
		public, err := hex.DecodeString(os.Getenv("TS_PRELIMINARY_PUBLIC"))
		if err != nil {
			os.Exit(3)
		}
		verified, err := VerifyRequest(public, c.SignedRequest)
		if err != nil {
			os.Exit(3)
		}
		c.Request = verified
		c.Context = context.Background()
		if s, err := NewStore(c); err == nil {
			s.Close()
			os.Exit(4)
		}
		return
	}
	c := storeConfig(t)
	s, err := NewStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreProcessExclusiveOwnership$")
	cmd.Env = append(os.Environ(), "TS_PRELIMINARY_LOCK_HELPER="+string(raw), "TS_PRELIMINARY_PUBLIC="+hex.EncodeToString(c.Request.public))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child lock result: %s %v", output, err)
	}
	sum := sha256.Sum256(c.SignedRequest)
	if c.Request.Digest != hex.EncodeToString(sum[:]) {
		t.Fatal("request digest does not pin signed bytes")
	}
}

func TestStoreRetryReestablishesDirectoryDurability(t *testing.T) {
	c := storeConfig(t)
	s, err := NewStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// O_PATH supports descriptor-relative opens and rename, but cannot fsync.
	// This induces the real failure after successful atomic publication without
	// replacing filesystem primitives with an implementation-mirroring mock.
	fd, err := unix.Open(c.OutputDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	pathOnly := os.NewFile(uintptr(fd), "unsyncable directory")
	defer pathOnly.Close()
	original := s.dir
	s.dir = pathOnly
	defer func() { s.dir = original }()
	key, _ := ObjectKey("REGIONAL", "EVENTS", 1)
	body := []byte("published but directory sync failed")
	if s.Put(context.Background(), "gru", "REGIONAL", key, body) == nil {
		t.Fatal("publication ignored failed directory sync")
	}
	if _, err := os.Stat(filepath.Join(c.OutputDir, objectFile(key))); err != nil {
		t.Fatal("fixture did not publish before fsync failure")
	}
	if s.Put(context.Background(), "gru", "REGIONAL", key, body) == nil {
		t.Fatal("identical retry bypassed failed directory sync")
	}
	if _, _, err := s.GetSnapshot(context.Background(), "gru", "REGIONAL", key); err == nil {
		t.Fatal("readback claimed durability despite failed directory sync")
	}
	s.dir = original
	if err := s.Put(context.Background(), "gru", "REGIONAL", key, body); err != nil {
		t.Fatal(err)
	}
	if got, found, err := s.GetSnapshot(context.Background(), "gru", "REGIONAL", key); err != nil || !found || !bytes.Equal(got, body) {
		t.Fatal("durable retry changed artifact")
	}
}

func TestStoreCanceledMutationsNeverPublish(t *testing.T) {
	c := storeConfig(t)
	s, err := NewStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key, _ := ObjectKey("REGIONAL", "EVENTS", 1)
	if s.Put(ctx, "gru", "REGIONAL", key, []byte("canceled")) == nil {
		t.Fatal("canceled write accepted")
	}
	if _, found, err := s.GetSnapshot(context.Background(), "gru", "REGIONAL", key); err != nil || found {
		t.Fatal("canceled object appeared")
	}
	if s.PublishReceipt(ctx, []byte("{}")) == nil {
		t.Fatal("canceled receipt accepted")
	}
	c.OutputDir = filepath.Join(t.TempDir(), "never-created")
	c.Context = ctx
	if _, err := NewStore(c); err == nil {
		t.Fatal("canceled staging owner accepted")
	}
	if _, err := os.Stat(c.OutputDir); !os.IsNotExist(err) {
		t.Fatal("canceled admission created output")
	}
}
