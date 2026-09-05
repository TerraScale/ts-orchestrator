package preliminarycapture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

func completedFixture(t *testing.T) CompletedStoreConfig {
	t.Helper()
	c := storeConfig(t)
	owner, public := captureSigner(t)
	request := c.Request.Request
	request.IssuedAt = time.Now().UTC().Add(-2 * time.Hour)
	request.ExpiresAt = request.IssuedAt.Add(time.Hour)
	signed, err := SignRequest(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRequest(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(c.OutputDir, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(c.OutputDir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(".lock", nil)
	write("request.json", signed)
	signer, sourcePublic := captureSigner(t)
	receipt := Receipt{Version: 1, Preliminary: true, TransitionID: request.TransitionID, RequestSHA256: verified.Digest, SourceNodeID: request.SourceNodeID, ControlEpoch: request.ControlEpoch, CreatedAt: request.IssuedAt.Add(time.Minute)}
	for _, account := range request.Accounts {
		for _, stream := range account.Streams {
			key, _ := ObjectKey(account.Account, stream, request.ControlEpoch)
			body := []byte(stream)
			write(objectFile(key), body)
			receipt.Objects = append(receipt.Objects, Object{Account: account.Account, Stream: stream, Key: key, SHA256: delivery.SHA256Digest(body), Size: int64(len(body)), CreatedAt: receipt.CreatedAt})
		}
	}
	raw, err := SignReceipt(signer, receipt)
	if err != nil {
		t.Fatal(err)
	}
	write("receipt.json", raw)
	return CompletedStoreConfig{Context: context.Background(), OutputDir: c.OutputDir, Request: verified, SignedRequest: signed, SourcePublicKeyPEM: sourcePublic, ExpectedReceiptSHA256: strings.TrimPrefix(delivery.SHA256Digest(raw), "sha256:"), MaxSnapshotBytes: 1024, MaxTotalBytes: 4096}
}

func TestCompletedStoreExpiredEvidenceAndRevocation(t *testing.T) {
	c := completedFixture(t)
	if c.Request.Check(time.Now()) == nil {
		t.Fatal("fixture is not expired")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Context = ctx
	revoked := false
	c.CheckAuthorization = func(context.Context) error {
		if revoked {
			return errors.New("revoked")
		}
		return nil
	}
	s, err := OpenCompletedStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := OpenCompletedStore(c); err == nil {
		t.Fatal("concurrent ownership accepted")
	}
	if _, found, err := s.ReadReceipt(); err != nil || !found {
		t.Fatal(err)
	}
	key, _ := ObjectKey("REGIONAL", "EVENTS", 1)
	if id, found, err := s.Head(ctx, "gru", "REGIONAL", key); err != nil || !found || id.Size == 0 {
		t.Fatal(err)
	}
	revoked = true
	if _, _, err := s.GetSnapshot(ctx, "gru", "REGIONAL", key); err == nil {
		t.Fatal("revocation ignored")
	}
	revoked = false
	cancel()
	if _, _, err := s.ReadReceipt(); err == nil {
		t.Fatal("context cancellation ignored")
	}
}

func TestCompletedStoreRefusesIncompleteOrChangedEvidenceWithoutMutation(t *testing.T) {
	for _, kind := range []string{"missing-dir", "missing-lock", "missing-pin", "missing-receipt", "missing-object", "corrupt-object", "foreign-signer", "wrong-digest", "changed-request", "stale-file", "canceled", "quota"} {
		t.Run(kind, func(t *testing.T) {
			c := completedFixture(t)
			key, _ := ObjectKey("REGIONAL", "EVENTS", 1)
			switch kind {
			case "missing-dir":
				c.OutputDir = filepath.Join(filepath.Dir(c.OutputDir), "absent")
			case "missing-lock":
				if err := os.Remove(filepath.Join(c.OutputDir, ".lock")); err != nil {
					t.Fatal(err)
				}
			case "missing-pin":
				if err := os.Remove(filepath.Join(c.OutputDir, "request.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-receipt":
				if err := os.Remove(filepath.Join(c.OutputDir, "receipt.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-object":
				if err := os.Remove(filepath.Join(c.OutputDir, objectFile(key))); err != nil {
					t.Fatal(err)
				}
			case "corrupt-object":
				if err := os.WriteFile(filepath.Join(c.OutputDir, objectFile(key)), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-signer":
				_, c.SourcePublicKeyPEM = captureSigner(t)
			case "wrong-digest":
				c.ExpectedReceiptSHA256 = strings.Repeat("0", 64)
			case "changed-request":
				c.Request.Request.ControlEpoch++
			case "stale-file":
				if err := os.WriteFile(filepath.Join(c.OutputDir, ".staging-0123456789abcdef0123456789abcdef"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				c.Context = ctx
			case "quota":
				c.MaxTotalBytes = 1
			}
			before := directoryContents(t, c.OutputDir)
			if s, err := OpenCompletedStore(c); err == nil {
				s.Close()
				t.Fatal("invalid completed evidence accepted")
			}
			after := directoryContents(t, c.OutputDir)
			if len(before) != len(after) {
				t.Fatal("reader created or removed files")
			}
			for name, body := range before {
				if after[name] != body {
					t.Fatalf("reader changed %s", name)
				}
			}
		})
	}
}
func directoryContents(t *testing.T, path string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = string(body)
	}
	return result
}

func TestCompletedStoreRechecksPinnedBytesAndAuthorizationAfterRead(t *testing.T) {
	c := completedFixture(t)
	calls := 0
	denyAt := 0
	c.CheckAuthorization = func(context.Context) error {
		calls++
		if calls == denyAt {
			return errors.New("revoked during read")
		}
		return nil
	}
	s, err := OpenCompletedStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key, _ := ObjectKey("REGIONAL", "EVENTS", 1)
	denyAt = calls + 2
	if body, _, err := s.GetSnapshot(c.Context, "gru", "REGIONAL", key); err == nil || body != nil {
		t.Fatal("post-read authorization ignored")
	}
	denyAt = 0
	if err := os.WriteFile(filepath.Join(c.OutputDir, objectFile(key)), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if body, _, err := s.GetSnapshot(c.Context, "gru", "REGIONAL", key); err == nil || body != nil {
		t.Fatal("changed snapshot returned")
	}
	if _, _, err := s.ReadReceipt(); err == nil {
		t.Fatal("receipt ignored changed bytes")
	}
}
