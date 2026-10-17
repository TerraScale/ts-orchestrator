package rootfoundation

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	ocir "github.com/TerraScale/ts-orchestrator/internal/ociregion/registry"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/common"
)

const repositoryCreator = "ocid1.instance.oc1.sa-saopaulo-1.creator"

type ocirRepositoryProtocol struct {
	base       *ocirJournalProtocol
	mu         sync.Mutex
	repository artifacts.ContainerRepository
	token      string
	bodyHash   string
	accepted   int
	calls      int
	loseCreate bool
}

func (p *ocirRepositoryProtocol) serve(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.URL.Path, "/container/repositories") {
		p.base.serve(w, r)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	w.Header().Set("etag", "repository-revision")
	write := func(value any) { _ = json.MarshalWrite(w, value) }
	fail := func(status int) {
		w.WriteHeader(status)
		write(map[string]string{"code": "Conflict", "message": "accepted response withheld or foreign name"})
	}
	switch r.Method {
	case http.MethodPost:
		p.calls++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fail(400)
			return
		}
		var details artifacts.CreateContainerRepositoryDetails
		if err := json.Unmarshal(body, &details, json.RejectUnknownMembers(true)); err != nil || r.Header.Get("opc-retry-token") == "" {
			fail(400)
			return
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(body))
		if p.repository.Id != nil && (p.token != r.Header.Get("opc-retry-token") || p.bodyHash != hash) {
			fail(409)
			return
		}
		if p.repository.Id == nil {
			p.accepted++
			p.token, p.bodyHash = r.Header.Get("opc-retry-token"), hash
			p.repository = artifacts.ContainerRepository{Id: new("ocid1.containerrepo.oc1.sa-saopaulo-1.owned"), CreatedBy: new(repositoryCreator), Namespace: new("ns"), CompartmentId: details.CompartmentId, DisplayName: details.DisplayName,
				IsImmutable: details.IsImmutable, IsPublic: details.IsPublic, FreeformTags: details.FreeformTags, LifecycleState: artifacts.ContainerRepositoryLifecycleStateAvailable}
		}
		if p.loseCreate {
			p.loseCreate = false
			fail(503)
			return
		}
		write(p.repository)
	case http.MethodGet:
		write(p.repository)
	default:
		fail(405)
	}
}

func TestOCIRProtectedRepositorySDKRestartRetainsCreate(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprintf("foreign=%t", foreign), func(t *testing.T) {
			remote := &ocirRepositoryProtocol{base: &ocirJournalProtocol{path: filepath.Join(t.TempDir(), "own-cell")}, loseCreate: true}
			factory, endpoint := ociresourcetest.Server(t, remote.serve)
			scope := journalIssuerScope(t, remote.base, factory, endpoint)
			objects, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			ociclient.PinHost(&objects.BaseClient, endpoint)
			open := func() region.FoundationStore {
				store, err := region.NewObjectFoundationStore(&objects, "ns", "heads")
				if err != nil {
					t.Fatal(err)
				}
				return store
			}
			store := open()
			now := time.Now().UTC()
			deadline := now.Add(time.Minute)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()
			original := region.FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: factory.Region(), TenancyID: scope.TenancyID(), ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Generation: scope.Generation(), GrantSHA256: scope.GrantDigest(), IntentDigest: strings.Repeat("a", 64), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now, ResourceIDs: map[string]string{"vault": scope.Intent().VaultTarget.VaultID}}
			if _, err := store.CompareAndSwap(ctx, original, ""); err != nil {
				t.Fatal(err)
			}
			guard := func(ctx context.Context) error { return ctx.Err() }
			reopen := func(principal string) *ocirRepositoryJournal {
				return &ocirRepositoryJournal{ocirJournal: &ocirJournal{store: open(), cell: "GRU", original: original, scope: scope, deadline: deadline, guard: guard}, principal: principal}
			}
			journal := reopen(repositoryCreator)
			intent := scope.Intent()
			repository := ocir.Repository{CompartmentID: intent.RepositoryCompartmentID, Namespace: intent.RegistryNamespace, Name: intent.RepositoryName, PrincipalID: repositoryCreator, Owner: scope.InstallationID()}
			key := fmt.Sprintf("ocir.%x", sha256.Sum256([]byte(intent.OCIRegion+"\x00"+intent.RepositoryCompartmentID+"\x00"+intent.RepositoryName)))
			if _, err := journal.Load(ctx, key); !errors.Is(err, jetstream.ErrKeyNotFound) {
				t.Fatalf("first lifecycle: %v", err)
			}
			state := ocir.Record{Repository: repository, OperationID: uuid.New().String(), CreateExpiresAt: deadline, Images: map[string]ocir.ImageRecord{}}
			if err := journal.CompareAndSwap(ctx, key, state); err != nil {
				t.Fatal(err)
			}
			state, err = journal.Load(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"pins", "images"} {
				t.Run("lifecycle-only-"+field, func(t *testing.T) {
					changed := state
					if field == "pins" {
						changed.Pins.Children = map[string][]string{}
					} else {
						changed.Images = map[string]ocir.ImageRecord{"sha256:" + strings.Repeat("c", 64): {ID: "ocid1.containerimage.oc1..unapproved"}}
					}
					if err := journal.CompareAndSwap(ctx, key, changed); err == nil {
						t.Fatal("repository authority accepted image inventory")
					}
				})
			}
			client, err := factory.Artifacts()
			if err != nil {
				t.Fatal(err)
			}
			destination, err := url.Parse(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			client.HTTPClient = ocirJournalRedirect{destination: destination}
			ociclient.ConfigureRequestCancellation(&client.BaseClient)
			create := func(journal *ocirRepositoryJournal) (artifacts.CreateContainerRepositoryResponse, error) {
				effect, stop := context.WithDeadline(ctx, state.CreateExpiresAt)
				defer stop()
				effect = ociclient.WithAuthority(effect, guard)
				effect = ociclient.WithWireAttempt(effect, journal.BeginEffect)
				return client.CreateContainerRepository(ociclient.RequestContext(effect), artifacts.CreateContainerRepositoryRequest{CompartmentId: new(repository.CompartmentID), DisplayName: new(repository.Name), IsImmutable: new(true), IsPublic: new(false),
					FreeformTags: map[string]string{"terrascale-managed-by": "ts-orchestrator", "terrascale-owner": repository.Owner, "terrascale-ocir-operation": state.OperationID}, OpcRetryToken: new(state.OperationID), RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())}})
			}
			if foreign {
				remote.repository = artifacts.ContainerRepository{Id: new("ocid1.containerrepo.oc1.sa-saopaulo-1.foreign"), CompartmentId: new(repository.CompartmentID), DisplayName: new(repository.Name), Namespace: new(repository.Namespace), CreatedBy: new(repositoryCreator), IsPublic: new(false), IsImmutable: new(true), LifecycleState: artifacts.ContainerRepositoryLifecycleStateAvailable}
			}
			if _, err := create(journal); err == nil {
				t.Fatal("lost or foreign create succeeded")
			}
			// Reopen both protected SDK store and adapter. A replacement creator
			// remains current authority, but cannot replace the original creator.
			journal = reopen("ocid1.instance.oc1.sa-saopaulo-1.replacement")
			loaded, err := journal.Load(ctx, key)
			if err != nil || loaded.OperationID != state.OperationID || loaded.Repository.PrincipalID != repositoryCreator || !loaded.CreateExpiresAt.Equal(deadline) {
				t.Fatalf("restart lost original create: %+v %v", loaded, err)
			}
			if foreign {
				loaded.RepositoryID = *remote.repository.Id
				if err := journal.CompareAndSwap(ctx, key, loaded); err == nil {
					t.Fatal("foreign name adopted without original successful dispatch")
				}
				if remote.accepted != 0 || remote.calls != 1 {
					t.Fatal("foreign name created or retried")
				}
				return
			}
			response, err := create(journal)
			if err != nil || response.Id == nil || *response.CreatedBy != repositoryCreator || *response.Namespace != repository.Namespace || *response.IsPublic || !*response.IsImmutable {
				t.Fatalf("exact create recovery: %+v %v", response, err)
			}
			loaded.RepositoryID = *response.Id
			remote.base.mu.Lock()
			remote.base.lostCAS = true
			remote.base.mu.Unlock()
			if err := journal.CompareAndSwap(ctx, key, loaded); err == nil {
				t.Fatal("lost committed CAS reported success")
			}
			journal = reopen(repositoryCreator)
			receipt, err := journal.Load(ctx, key)
			if err != nil || receipt.RepositoryID != loaded.RepositoryID || receipt.Revision != loaded.Revision+1 || receipt.OperationID != loaded.OperationID {
				t.Fatalf("repository receipt lost on disk restart: %+v %v", receipt, err)
			}
			if err := journal.CompareAndSwap(ctx, key, loaded); err == nil {
				t.Fatal("stale pre-response repository revision accepted")
			}
			protected, etag, err := store.Load(ctx, "GRU")
			if err != nil {
				t.Fatal(err)
			}
			issuerKey, err := scope.JournalKey()
			if err != nil {
				t.Fatal(err)
			}
			entry := protected.OCIRIssuances[issuerKey]
			if len(entry.Requests) != 1 || remote.accepted != 1 || remote.calls != 2 || protected.ResourceIDs["vault"] != original.ResourceIDs["vault"] {
				t.Fatal("recovery duplicated creation or lost sibling")
			}
			for _, request := range entry.Requests {
				if request.RetryToken != state.OperationID || request.BodySHA256 != remote.bodyHash || !request.Deadline.Equal(deadline) || len(request.Dispatches) != 2 || request.Dispatches[0].Status != 503 || request.Dispatches[1].Status != 200 {
					t.Fatal("original create body, token, deadline or outcomes lost")
				}
			}
			for _, field := range []string{"creator", "operation", "deadline", "repository", "requests"} {
				t.Run("retain-"+field, func(t *testing.T) {
					wire, err := json.Marshal(protected)
					if err != nil {
						t.Fatal(err)
					}
					var changed region.FoundationRecord
					if err := json.Unmarshal(wire, &changed); err != nil {
						t.Fatal(err)
					}
					entry := changed.OCIRIssuances[issuerKey]
					switch field {
					case "creator":
						entry.Repository.PrincipalID = "ocid1.instance.oc1.sa-saopaulo-1.replacement"
					case "operation":
						entry.Repository.OperationID = uuid.New().String()
					case "deadline":
						entry.Repository.Origin.ExpiresAt = deadline.Add(time.Hour)
					case "repository":
						entry.Repository = nil
					case "requests":
						entry.Requests = nil
					}
					changed.OCIRIssuances[issuerKey] = entry
					if _, err := store.CompareAndSwap(ctx, changed, etag); err == nil {
						t.Fatal("another writer removed original repository authority or history")
					}
				})
			}
			// This fixture exercises the real SDK/protected CAS restart path.
			// HomeIAM, actual Controller.Ensure and startup admission are separate.
		})
	}
}
