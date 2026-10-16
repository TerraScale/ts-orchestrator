// Package registry reconciles the platform's private OCI container repositories.
// Repository metadata uses instance principals; pull credentials remain Vault references.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

var (
	ErrOwnership = errors.New("OCIR repository ownership is not proven")
	ErrPins      = errors.New("OCIR retention inventory is missing, stale, or incomplete")
	ErrRetiring  = errors.New("OCIR image retirement already started")
)

// Repository identifies one platform repository and the admitted creating principal.
// PrincipalID is persisted before creation; later leaders retain that original
// creator from the journal even when their own admitted principal differs.
type Repository struct {
	CompartmentID string `json:"compartment_id"`
	Name          string `json:"name"`
	PrincipalID   string `json:"principal_id"`
	Owner         string `json:"owner"`
}

// Controller consumes a persistent regional KV bucket and the shared SDK client.
// Guard checks the current authority before every OCI and journal write.
type Controller struct {
	client  artifacts.ArtifactsClient
	journal jetstream.KeyValue
	guard   func(context.Context) error
	region  string
}

// New builds the registry metadata client through the shared OCI factory.
func New(factory *ociclient.Factory, journal jetstream.KeyValue, guard func(context.Context) error) (*Controller, error) {
	if factory == nil || journal == nil || guard == nil {
		return nil, errors.New("OCIR requires the OCI factory, durable journal and authority guard")
	}
	client, err := artifacts.NewArtifactsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return nil, err
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.Service("artifacts"))
	client.HTTPClient = ociclient.Instrument(client.HTTPClient, "artifacts")
	previous := client.Interceptor
	client.Interceptor = func(request *http.Request) error {
		if previous != nil {
			if err := previous(request); err != nil {
				return err
			}
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			return guard(request.Context())
		}
		return nil
	}
	return &Controller{client: client, journal: journal, guard: guard, region: factory.Region()}, nil
}

type imageRecord struct {
	ID         string    `json:"id"`
	RecordedAt time.Time `json:"recorded_at"`
	Retiring   string    `json:"retiring,omitempty"`
}

type record struct {
	Repository   Repository             `json:"repository"`
	OperationID  string                 `json:"operation_id"`
	RepositoryID string                 `json:"repository_id,omitempty"`
	Pins         Pins                   `json:"pins"`
	Images       map[string]imageRecord `json:"images"`
	Revision     uint64                 `json:"-"`
}

func (c *Controller) key(repository Repository) (string, error) {
	if c == nil || c.journal == nil || c.guard == nil || repository.CompartmentID == "" || repository.PrincipalID == "" ||
		repository.Name == "" || len(repository.Name) > 256 || strings.TrimSpace(repository.Name) != repository.Name ||
		strings.ContainsAny(repository.Name, "@:\\ \t\r\n") || c.region == "" {
		return "", errors.New("invalid OCIR repository identity or controller")
	}
	if err := (ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: repository.Owner}).Validate(); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(c.region + "\x00" + repository.CompartmentID + "\x00" + repository.Name))
	return "ocir." + hex.EncodeToString(sum[:]), nil
}

func (c *Controller) load(ctx context.Context, repository Repository) (record, error) {
	key, err := c.key(repository)
	if err != nil {
		return record{}, err
	}
	status, err := c.journal.Status(ctx)
	if err != nil {
		return record{}, err
	}
	config := status.Config()
	if config.Storage != jetstream.FileStorage || config.TTL != 0 {
		return record{}, errors.New("OCIR journal requires persistent non-expiring storage")
	}
	entry, err := c.journal.Get(ctx, key)
	if err != nil {
		return record{}, err
	}
	var state record
	if len(entry.Value()) > 1<<20 {
		return record{}, errors.New("OCIR journal exceeds its size bound")
	}
	if err := json.Unmarshal(entry.Value(), &state, json.RejectUnknownMembers(true)); err != nil {
		return record{}, err
	}
	if state.Repository.CompartmentID != repository.CompartmentID || state.Repository.Name != repository.Name || state.Repository.Owner != repository.Owner ||
		state.Repository.PrincipalID == "" || state.OperationID == "" || state.Images == nil {
		return record{}, ErrOwnership
	}
	state.Revision = entry.Revision()
	return state, nil
}

func (c *Controller) save(ctx context.Context, state record) error {
	key, err := c.key(state.Repository)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(wire) > 1<<20 {
		return errors.New("OCIR journal exceeds its size bound")
	}
	if err := c.guard(ctx); err != nil {
		return err
	}
	if state.Revision == 0 {
		_, err = c.journal.Create(ctx, key, wire)
	} else {
		_, err = c.journal.Update(ctx, key, wire, state.Revision)
	}
	return err
}

func (c *Controller) tags(state record) map[string]string {
	return map[string]string{"terrascale-managed-by": "ts-orchestrator", "terrascale-owner": state.Repository.Owner,
		"terrascale-ocir-operation": state.OperationID}
}

func (c *Controller) validate(state record, repo artifacts.ContainerRepository) error {
	if repo.Id == nil || *repo.Id == "" || text(repo.CompartmentId) != state.Repository.CompartmentID ||
		text(repo.DisplayName) != state.Repository.Name || text(repo.CreatedBy) != state.Repository.PrincipalID ||
		state.RepositoryID != "" && *repo.Id != state.RepositoryID {
		return ErrOwnership
	}
	for key, want := range c.tags(state) {
		if repo.FreeformTags[key] != want {
			return ErrOwnership
		}
	}
	if repo.LifecycleState != artifacts.ContainerRepositoryLifecycleStateAvailable {
		return errors.New("OCIR repository is not available")
	}
	return nil
}

// Ensure checkpoints creation before calling OCI and binds the returned OCID.
// An unrecorded existing name is refused; an interrupted create reuses its token.
func (c *Controller) Ensure(ctx context.Context, repository Repository) (artifacts.ContainerRepository, error) {
	state, err := c.load(ctx, repository)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		state = record{Repository: repository, OperationID: common.RetryToken(), Images: map[string]imageRecord{}}
		if err := c.save(ctx, state); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		state, err = c.load(ctx, repository)
	}
	if err != nil {
		return artifacts.ContainerRepository{}, err
	}
	if state.RepositoryID == "" {
		// A name match never grants adoption. Only this durable create operation may bind an OCID.
		if err := c.guard(ctx); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		response, err := c.client.CreateContainerRepository(ctx, artifacts.CreateContainerRepositoryRequest{
			CompartmentId: new(repository.CompartmentID), DisplayName: new(repository.Name), IsPublic: new(false), IsImmutable: new(true), FreeformTags: c.tags(state),
			OpcRetryToken: new(state.OperationID)})
		if err != nil {
			return artifacts.ContainerRepository{}, fmt.Errorf("create/recover OCIR repository: %w", err)
		}
		if err := c.validate(state, response.ContainerRepository); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		state.RepositoryID = text(response.Id)
		if err := c.save(ctx, state); err != nil {
			return artifacts.ContainerRepository{}, err
		}
	}
	response, err := c.client.GetContainerRepository(ctx, artifacts.GetContainerRepositoryRequest{RepositoryId: new(state.RepositoryID)})
	if err != nil {
		return artifacts.ContainerRepository{}, err
	}
	if err := c.validate(state, response.ContainerRepository); err != nil {
		return artifacts.ContainerRepository{}, err
	}
	if response.IsPublic == nil || response.IsImmutable == nil || text(response.Namespace) == "" {
		return artifacts.ContainerRepository{}, errors.New("OCIR repository metadata is incomplete")
	}
	if *response.IsPublic || !*response.IsImmutable {
		if text(response.Etag) == "" {
			return artifacts.ContainerRepository{}, errors.New("OCIR repository has no concurrency token")
		}
		if err := c.guard(ctx); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		_, err := c.client.UpdateContainerRepository(ctx, artifacts.UpdateContainerRepositoryRequest{RepositoryId: new(state.RepositoryID), IfMatch: response.Etag, OpcRequestId: new(state.OperationID),
			IsPublic: new(false), IsImmutable: new(true)})
		if err != nil {
			return artifacts.ContainerRepository{}, err
		}
		// Re-observe before dependents receive the repository.
		observed, err := c.client.GetContainerRepository(ctx, artifacts.GetContainerRepositoryRequest{RepositoryId: new(state.RepositoryID)})
		if err != nil {
			return artifacts.ContainerRepository{}, err
		}
		if err := c.validate(state, observed.ContainerRepository); err != nil {
			return artifacts.ContainerRepository{}, err
		}
		if observed.IsPublic == nil || *observed.IsPublic || observed.IsImmutable == nil || !*observed.IsImmutable || text(observed.Namespace) == "" {
			return artifacts.ContainerRepository{}, errors.New("OCIR private immutable repository update is not observed")
		}
		return observed.ContainerRepository, nil
	}
	return response.ContainerRepository, nil
}

func text(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
