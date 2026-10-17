package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// The retained scenario sends each read through the signed real OCI SDK.
type snapshotDiscoveryObjects struct {
	foundationDiscoveryObjects
	namespaces int
	objects    []string
	after      func(string)
}

func (c *snapshotDiscoveryObjects) GetNamespace(ctx context.Context, request objectstorage.GetNamespaceRequest) (objectstorage.GetNamespaceResponse, error) {
	c.namespaces++
	return c.foundationDiscoveryObjects.GetNamespace(ctx, request)
}

func (c *snapshotDiscoveryObjects) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	name := *request.ObjectName
	c.objects = append(c.objects, name)
	response, err := c.foundationDiscoveryObjects.GetObject(ctx, request)
	if c.after != nil {
		c.after(name)
	}
	return response, err
}

type snapshotBlockedDispatcher struct {
	test     *testing.T
	deadline time.Time
	called   bool
}

func (d *snapshotBlockedDispatcher) Do(request *http.Request) (*http.Response, error) {
	d.called = true
	deadline, ok := request.Context().Deadline()
	if !ok || !deadline.Equal(d.deadline) || request.Context().Done() == nil ||
		!strings.HasPrefix(request.Header.Get("Authorization"), "Signature ") {
		d.test.Errorf("SDK attempt lost original authenticated lifetime: deadline=%v want=%v", deadline, d.deadline)
		return nil, errors.New("incorrect SDK read lifetime")
	}
	<-request.Context().Done()
	return nil, request.Context().Err()
}

func TestCurrentFoundationSnapshotSingleDiscoveryAndFixedGuard(t *testing.T) {
	f := newCurrentDiscoveryScenario(t)
	objects := &snapshotDiscoveryObjects{foundationDiscoveryObjects: f.client}
	original, cancel := context.WithCancel(t.Context())
	defer cancel()
	snapshot, err := discoverCurrentFoundationSnapshot(original, objects, f.grant.TenancyID, f.genesis)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{foundationDiscoveryObject, foundationRootChainObject, "bootstrap/" + foundationGrantObject}
	if objects.namespaces != 1 || !slices.Equal(objects.objects, want) {
		t.Fatalf("discovery read count/keys: namespace=%d objects=%v", objects.namespaces, objects.objects)
	}
	if snapshot.Context() != original || !snapshot.ExpiresAt().Equal(f.now.Add(time.Hour)) || snapshot.Resolver().Footprint == nil || snapshot.Resolver().Store == nil {
		t.Fatal("snapshot lost its original resolver, context or expiry")
	}
	documents := snapshot.Documents()
	documents.AnchorWire[0] ^= 1
	documents.RootChainWire[0] ^= 1
	documents.GrantWire[0] ^= 1
	for _, key := range snapshot.Roots() {
		key[0] ^= 1
	}
	anchor := snapshot.Anchor().Anchor()
	anchor.ControllerSlots[0] = "caller-changed-slot"
	before, err := os.ReadFile(f.floorPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Guard(t.Context()); err != nil {
		t.Fatalf("caller modified retained authority: %v", err)
	}
	if objects.namespaces != 1 || !slices.Equal(objects.objects, append(slices.Clone(want), want...)) {
		t.Fatalf("guard rediscovered or changed fixed objects: namespace=%d objects=%v", objects.namespaces, objects.objects)
	}
	after, err := os.ReadFile(f.floorPath())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("guard rewrote adopted floor: %v", err)
	}
	cancel()
	count := len(objects.objects)
	if err := snapshot.Guard(context.Background()); !errors.Is(err, context.Canceled) || len(objects.objects) != count {
		t.Fatalf("fresh caller context revived original cancellation: %v", err)
	}
}

func TestCurrentFoundationSnapshotRejectsChangedCurrentDocuments(t *testing.T) {
	for _, name := range []string{"missing anchor", "missing chain", "missing grant", "tampered chain", "unknown root", "expired successor", "renewed expiry", "new generation", "root rotation"} {
		t.Run(name, func(t *testing.T) {
			f := newCurrentDiscoveryScenario(t)
			snapshot, err := discoverCurrentFoundationSnapshot(t.Context(), f.client, f.grant.TenancyID, f.genesis)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(f.floorPath())
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing anchor":
				delete(f.objects, foundationDiscoveryObject)
			case "missing chain":
				delete(f.objects, foundationRootChainObject)
			case "missing grant":
				delete(f.objects, "bootstrap/"+foundationGrantObject)
			case "tampered chain":
				f.objects[foundationRootChainObject] = []byte(`{"version":1,"rotations":[{}]}`)
			case "unknown root":
				_, f.root, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.publish()
			case "expired successor":
				f.now = f.now.Add(-2 * time.Hour)
				f.publish()
			case "renewed expiry":
				f.now = f.now.Add(time.Minute)
				f.publish()
			case "new generation":
				f.grant.Generation++
				f.grant.Regions[0].Generation++
				f.publish()
			case "root rotation":
				f.rotate()
				f.publish()
			}
			if err := snapshot.Guard(t.Context()); err == nil {
				t.Fatal("changed current authority renewed the original attempt")
			}
			after, err := os.ReadFile(f.floorPath())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected current documents changed floor: %v", err)
			}
		})
	}
}

func TestCurrentFoundationSnapshotRejectsChangedOrMissingFloor(t *testing.T) {
	for _, name := range []string{"advanced", "equivocated", "deleted file", "deleted directory", "symlink"} {
		t.Run(name, func(t *testing.T) {
			f := newCurrentDiscoveryScenario(t)
			snapshot, err := discoverCurrentFoundationSnapshot(t.Context(), f.client, f.grant.TenancyID, f.genesis)
			if err != nil {
				t.Fatal(err)
			}
			original := snapshot.Documents()
			switch name {
			case "advanced":
				f.grant.Generation++
				f.grant.Regions[0].Generation++
				f.publish()
				if _, err := f.discover(t.Context()); err != nil {
					t.Fatal(err)
				}
				// A rollback to the frozen valid remote documents cannot bypass
				// the newer authority genuinely adopted by another discovery.
				f.objects[foundationDiscoveryObject] = original.AnchorWire
				f.objects[foundationRootChainObject] = original.RootChainWire
				f.objects["bootstrap/"+foundationGrantObject] = original.GrantWire
			case "equivocated":
				if err := os.WriteFile(f.floorPath(), []byte(`{`), 0600); err != nil {
					t.Fatal(err)
				}
			case "deleted file", "symlink":
				if err := os.Remove(f.floorPath()); err != nil {
					t.Fatal(err)
				}
				if name == "symlink" {
					outside := filepath.Join(t.TempDir(), "floor-copy")
					if err := os.WriteFile(outside, []byte(`{`), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, f.floorPath()); err != nil {
						t.Fatal(err)
					}
				}
			case "deleted directory":
				if err := os.Rename(filepath.Dir(f.floorPath()), filepath.Dir(f.floorPath())+"-removed"); err != nil {
					t.Fatal(err)
				}
			}
			if err := snapshot.Guard(t.Context()); err == nil {
				t.Fatal("missing or changed protected floor admitted old authority")
			}
			if name == "deleted directory" {
				if _, err := os.Stat(filepath.Dir(f.floorPath())); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("guard recreated deleted floor directory: %v", err)
				}
			}
		})
	}
}

func TestCurrentFoundationSnapshotOriginalLifetimeAcrossReads(t *testing.T) {
	for _, name := range []string{"original deadline", "source expiry", "cancel after final response"} {
		t.Run(name, func(t *testing.T) {
			f := newCurrentDiscoveryScenario(t)
			objects := &snapshotDiscoveryObjects{foundationDiscoveryObjects: f.client}
			original, cancel := context.WithCancel(t.Context())
			defer cancel()
			if name == "original deadline" {
				var deadlineCancel context.CancelFunc
				original, deadlineCancel = context.WithTimeout(original, time.Second)
				defer deadlineCancel()
			}
			if name == "source expiry" {
				f.now = time.Now().UTC().Add(-time.Hour + time.Second)
				f.publish()
			}
			snapshot, err := discoverCurrentFoundationSnapshot(original, objects, f.grant.TenancyID, f.genesis)
			if err != nil {
				t.Fatal(err)
			}
			var blocked *snapshotBlockedDispatcher
			finalResponse := false
			if name == "cancel after final response" {
				objects.after = func(key string) {
					if key == "bootstrap/"+foundationGrantObject {
						finalResponse = true
						cancel()
					}
				}
			} else {
				deadline := snapshot.ExpiresAt()
				if name == "original deadline" {
					deadline, _ = original.Deadline()
				}
				client := f.client.(*objectstorage.ObjectStorageClient)
				blocked = &snapshotBlockedDispatcher{test: t, deadline: deadline}
				client.HTTPClient = blocked
			}
			if err := snapshot.Guard(context.Background()); err == nil {
				t.Fatal("a fresh caller context renewed the original lifetime")
			}
			if blocked != nil && !blocked.called || name == "cancel after final response" && !finalResponse {
				t.Fatal("guard failed before reaching the lifetime boundary under test")
			}
		})
	}
}

func TestCurrentFoundationSnapshotRequiresAuthenticConstruction(t *testing.T) {
	var absent *CurrentFoundationSnapshot
	if absent.Guard(t.Context()) == nil || new(CurrentFoundationSnapshot).Guard(t.Context()) == nil {
		t.Fatal("unconstructed snapshot admitted authority")
	}
}
