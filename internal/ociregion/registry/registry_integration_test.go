package registry

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
)

type ocirServer struct {
	mu           sync.Mutex
	repo         artifacts.ContainerRepository
	token        string
	images       map[string]artifacts.ContainerImage
	deleted      []string
	loseCreate   bool
	loseDelete   bool
	conflict     bool
	beforeDelete func()
}

func (s *ocirServer) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("etag", "revision-1")
	write := func(value any) {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(wire)
	}
	fail := func(status int) {
		w.WriteHeader(status)
		write(map[string]string{"code": "Conflict", "message": "simulated OCI interruption"})
	}
	switch {
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/container/repositories"):
		var details artifacts.CreateContainerRepositoryDetails
		if err := json.UnmarshalRead(r.Body, &details); err != nil {
			t.Error(err)
			fail(400)
			return
		}
		token := r.Header.Get("opc-retry-token")
		if token == "" {
			t.Error("create lacks retry token")
			fail(400)
			return
		}
		if s.token != "" && s.token != token {
			fail(409)
			return
		}
		if s.repo.Id == nil {
			s.token = token
			s.repo = artifacts.ContainerRepository{Id: new("ocid1.containerrepo.oc1..owned"), CompartmentId: details.CompartmentId, DisplayName: details.DisplayName,
				CreatedBy: new("ocid1.user.oc1..u"), IsPublic: details.IsPublic, IsImmutable: details.IsImmutable, Namespace: new("namespace"),
				LifecycleState: artifacts.ContainerRepositoryLifecycleStateAvailable, FreeformTags: details.FreeformTags}
		}
		if s.loseCreate {
			s.loseCreate = false
			fail(503)
			return
		}
		write(s.repo)
	case r.Method == "GET" && strings.Contains(r.URL.Path, "/container/repositories/"):
		write(s.repo)
	case r.Method == "PUT" && strings.Contains(r.URL.Path, "/container/repositories/"):
		if r.Header.Get("if-match") != "revision-1" || s.conflict {
			fail(412)
			return
		}
		var details artifacts.UpdateContainerRepositoryDetails
		if err := json.UnmarshalRead(r.Body, &details); err != nil {
			t.Error(err)
			fail(400)
			return
		}
		s.repo.IsPublic, s.repo.IsImmutable = details.IsPublic, details.IsImmutable
		write(s.repo)
	case strings.Contains(r.URL.Path, "/container/images/"):
		_, id, _ := strings.Cut(r.URL.Path, "/container/images/")
		image, ok := s.images[id]
		if !ok {
			fail(404)
			return
		}
		if r.Method == "GET" {
			write(image)
			return
		}
		if r.Method != "DELETE" {
			fail(405)
			return
		}
		if s.beforeDelete != nil {
			s.beforeDelete()
		}
		if r.Header.Get("if-match") != "revision-1" || s.conflict {
			fail(412)
			return
		}
		if r.Header.Get("opc-request-id") == "" {
			t.Error("delete lacks stable operation ID")
		}
		s.deleted = append(s.deleted, *image.Digest)
		delete(s.images, id)
		if s.loseDelete {
			s.loseDelete = false
			fail(503)
			return
		}
		w.WriteHeader(204)
	default:
		t.Errorf("unexpected OCI request %s %s", r.Method, r.URL.Path)
		fail(404)
	}
}

func setup(t *testing.T) (*Controller, *ocirServer, Repository, *atomic.Bool) {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	nc, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "REGISTRY", Storage: jetstream.FileStorage, History: 5})
	if err != nil {
		t.Fatal(err)
	}
	remote := &ocirServer{images: map[string]artifacts.ContainerImage{}}
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) { remote.serve(t, w, r) })
	fenced := new(atomic.Bool)
	guard := func(context.Context) error {
		if fenced.Load() {
			return errors.New("authority fenced")
		}
		return nil
	}
	controller, err := New(factory, kv, guard)
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&controller.client.BaseClient, endpoint)
	controller.client.Configuration.RetryPolicy = new(common.NoRetryPolicy())
	repository := Repository{CompartmentID: "ocid1.compartment.oc1..c", Name: "terrascale/terrabase", PrincipalID: "ocid1.user.oc1..u", Owner: "platform"}
	return controller, remote, repository, fenced
}

func TestSDKRepositoryLostCreateResponsePrivateRepairAndOwnership(t *testing.T) {
	c, remote, repository, _ := setup(t)
	remote.loseCreate = true
	if _, err := c.Ensure(t.Context(), repository); err == nil {
		t.Fatal("lost response reported success")
	}
	operation := remote.token
	// A fresh controller recovers from the real JetStream checkpoint, not process memory.
	restarted := *c
	repository.PrincipalID = "ocid1.instance.oc1..replacement-leader"
	if _, err := restarted.Ensure(t.Context(), repository); err != nil {
		t.Fatal(err)
	}
	if remote.token != operation {
		t.Fatal("create retry identity changed across restart")
	}
	remote.repo.IsPublic, remote.repo.IsImmutable = new(true), new(false)
	got, err := restarted.Ensure(t.Context(), repository)
	if err != nil || *got.IsPublic || !*got.IsImmutable {
		t.Fatalf("private immutable repair: %v %+v", err, got)
	}
	remote.repo.FreeformTags["terrascale-owner"] = "someone-else"
	if _, err := c.Ensure(t.Context(), repository); !errors.Is(err, ErrOwnership) {
		t.Fatalf("foreign repository accepted: %v", err)
	}
}

func seedImages(t *testing.T, c *Controller, remote *ocirServer, repo Repository, labels ...string) map[string]string {
	t.Helper()
	if _, err := c.Ensure(t.Context(), repo); err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{}
	for index, label := range labels {
		digest := "sha256:" + strings.Repeat(string(rune('a'+index)), 64)
		id := "ocid1.containerimage.oc1.." + label
		digests[label] = digest
		remote.images[id] = artifacts.ContainerImage{Id: new(id), Digest: new(digest), RepositoryId: remote.repo.Id, RepositoryName: new(repo.Name), CompartmentId: new(repo.CompartmentID), LifecycleState: artifacts.ContainerImageLifecycleStateAvailable}
		if err := c.RememberImage(t.Context(), repo, id, digest); err != nil {
			t.Fatal(err)
		}
	}
	// Age provider fixture admissions without waiting one hour; the production clock is fixed.
	state, err := c.load(t.Context(), repo)
	if err != nil {
		t.Fatal(err)
	}
	for digest, image := range state.Images {
		image.RecordedAt = time.Now().Add(-2 * time.Hour)
		state.Images[digest] = image
	}
	if err := c.save(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	return digests
}

func TestSDKRetentionKeepsCurrentRollbackTasksAndIndexChildren(t *testing.T) {
	c, remote, repo, _ := setup(t)
	d := seedImages(t, c, remote, repo, "current", "child", "rollback", "task", "garbage")
	pins := Pins{Generation: 1, ObservedAt: time.Now(), Current: []string{d["current"]}, Rollback: []string{d["rollback"]}, Tasks: []string{d["task"]}, Children: map[string][]string{d["current"]: {d["child"]}, d["child"]: {}, d["rollback"]: {}, d["task"]: {}}}
	if err := c.SetPins(t.Context(), repo, pins); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Collect(t.Context(), repo); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(remote.deleted, []string{d["garbage"]}) {
		t.Fatalf("wrong retention: %v", remote.deleted)
	}
	pins.Generation++
	pins.Tasks = append(pins.Tasks, d["garbage"])
	pins.Children[d["garbage"]] = nil
	if err := c.SetPins(t.Context(), repo, pins); !errors.Is(err, ErrRetiring) {
		t.Fatalf("retired image admitted: %v", err)
	}
}

func TestSDKRetentionPinDuringDeleteAndLostResponseRecovery(t *testing.T) {
	c, remote, repo, _ := setup(t)
	d := seedImages(t, c, remote, repo, "garbage")
	pins := Pins{Generation: 1, ObservedAt: time.Now(), Children: map[string][]string{}}
	if err := c.SetPins(t.Context(), repo, pins); err != nil {
		t.Fatal(err)
	}
	var pinErr error
	remote.beforeDelete = func() {
		pinErr = c.SetPins(t.Context(), repo, Pins{Generation: 2, ObservedAt: time.Now(), Tasks: []string{d["garbage"]}, Children: map[string][]string{d["garbage"]: {}}})
	}
	remote.loseDelete = true
	if _, err := c.Collect(t.Context(), repo); err == nil {
		t.Fatal("lost delete response reported success")
	}
	if !errors.Is(pinErr, ErrRetiring) {
		t.Fatalf("concurrent pin accepted: %v", pinErr)
	}
	restarted := *c
	if _, err := restarted.Collect(t.Context(), repo); err != nil {
		t.Fatal(err)
	}
	if len(remote.deleted) != 1 {
		t.Fatalf("duplicate delete: %v", remote.deleted)
	}
}

func TestSDKMissingPinsAndConditionalConflictPreventDeletion(t *testing.T) {
	c, remote, repo, fenced := setup(t)
	seedImages(t, c, remote, repo, "garbage")
	if _, err := c.Collect(t.Context(), repo); !errors.Is(err, ErrPins) {
		t.Fatalf("missing pins: %v", err)
	}
	if err := c.SetPins(t.Context(), repo, Pins{Generation: 1, ObservedAt: time.Now(), Children: map[string][]string{}}); err != nil {
		t.Fatal(err)
	}
	remote.conflict = true
	if _, err := c.Collect(t.Context(), repo); err == nil {
		t.Fatal("conditional conflict accepted")
	}
	if len(remote.deleted) != 0 {
		t.Fatal("conditional conflict deleted image")
	}
	remote.conflict = false
	fenced.Store(true)
	if _, err := c.Collect(t.Context(), repo); err == nil {
		t.Fatal("fenced authority deleted image")
	}
	if len(remote.deleted) != 0 {
		t.Fatal("fenced delete reached OCI")
	}
}

func TestSDKRetryRechecksAuthorityAndIncompletePinsStay(t *testing.T) {
	c, remote, repo, fenced := setup(t)
	remote.loseCreate = true
	policy := common.NewRetryPolicy(2, func(common.OCIOperationResponse) bool {
		fenced.Store(true)
		return true
	}, func(common.OCIOperationResponse) time.Duration { return 0 })
	c.client.Configuration.RetryPolicy = &policy
	if _, err := c.Ensure(t.Context(), repo); err == nil {
		t.Fatal("retry ignored authority loss")
	}
	fenced.Store(false)
	c.client.Configuration.RetryPolicy = new(common.NoRetryPolicy())
	if _, err := c.Ensure(t.Context(), repo); err != nil {
		t.Fatal(err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	for _, pins := range []Pins{
		{Generation: 1, ObservedAt: time.Now(), Current: []string{d}, Children: map[string][]string{}},
		{Generation: 1, ObservedAt: time.Now().Add(-3 * time.Minute), Children: map[string][]string{}},
	} {
		if err := c.SetPins(t.Context(), repo, pins); !errors.Is(err, ErrPins) {
			t.Fatalf("unsafe inventory accepted: %v", err)
		}
	}
}

func TestSDKExistingForeignRepositoryCannotBeAdopted(t *testing.T) {
	c, remote, repo, _ := setup(t)
	remote.repo = artifacts.ContainerRepository{Id: new("ocid1.containerrepo.oc1..foreign"), CreatedBy: new(repo.PrincipalID), CompartmentId: new(repo.CompartmentID), DisplayName: new(repo.Name), LifecycleState: artifacts.ContainerRepositoryLifecycleStateAvailable}
	if _, err := c.Ensure(t.Context(), repo); !errors.Is(err, ErrOwnership) {
		t.Fatalf("existing name was adopted: %v", err)
	}
}
