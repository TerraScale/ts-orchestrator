package rootfoundation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/http"
	"reflect"
	"strings"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	ocir "github.com/TerraScale/ts-orchestrator/internal/ociregion/registry"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/nats-io/nats.go/jetstream"
)

// The root adapter admits repository lifecycle metadata only. Image retirement
// and pin inventory belong to their regional journal, not this signed purpose.
type ocirRepositoryJournal struct {
	*ocirJournal
	principal string
}

func (s *ocirRepositoryJournal) key(key string) (string, error) {
	intent := s.scope.Intent()
	sum := sha256.Sum256([]byte(intent.OCIRegion + "\x00" + intent.RepositoryCompartmentID + "\x00" + intent.RepositoryName))
	if key != "ocir."+hex.EncodeToString(sum[:]) || intent.RepositoryLifecycle != "private-immutable" {
		return "", ErrScope
	}
	return s.scope.JournalKey()
}

func (s *ocirRepositoryJournal) Load(ctx context.Context, key string) (ocir.Record, error) {
	issuerKey, err := s.key(key)
	if err != nil {
		return ocir.Record{}, err
	}
	record, _, err := s.read(ctx)
	if err != nil {
		return ocir.Record{}, err
	}
	entry := record.OCIRIssuances[issuerKey]
	checkpoint := entry.Repository
	if checkpoint == nil {
		if entry.State.RepositoryID != "" {
			return ocir.Record{}, ErrScope
		}
		return ocir.Record{}, jetstream.ErrKeyNotFound
	}
	return ocir.Record{Repository: ocir.Repository{CompartmentID: checkpoint.CompartmentID, Namespace: checkpoint.Namespace, Name: checkpoint.Name, PrincipalID: checkpoint.PrincipalID, Owner: checkpoint.Owner},
		OperationID: checkpoint.OperationID, RepositoryID: checkpoint.RepositoryID, CreateExpiresAt: checkpoint.Origin.ExpiresAt, Revision: checkpoint.Revision, Images: map[string]ocir.ImageRecord{}}, nil
}

func (s *ocirRepositoryJournal) CompareAndSwap(ctx context.Context, key string, state ocir.Record) error {
	issuerKey, err := s.key(key)
	if err != nil {
		return err
	}
	intent := s.scope.Intent()
	if state.Repository.CompartmentID != intent.RepositoryCompartmentID || state.Repository.Namespace != intent.RegistryNamespace || state.Repository.Name != intent.RepositoryName || state.Repository.Owner != s.scope.InstallationID() ||
		len(state.Images) != 0 || !reflect.DeepEqual(state.Pins, ocir.Pins{}) {
		return ErrScope
	}
	record, etag, err := s.read(ctx)
	if err != nil {
		return err
	}
	entry, exists := record.OCIRIssuances[issuerKey]
	previous := entry.Repository
	if previous == nil && state.Revision != 0 || previous != nil && state.Revision != previous.Revision || previous == nil && entry.State.RepositoryID != "" {
		return ErrScope
	}
	checkpoint := region.OCIRRepositoryCheckpoint{Namespace: state.Repository.Namespace, CompartmentID: state.Repository.CompartmentID, Name: state.Repository.Name, PrincipalID: state.Repository.PrincipalID,
		Owner: state.Repository.Owner, OperationID: state.OperationID, RepositoryID: state.RepositoryID, Revision: state.Revision + 1}
	if checkpoint.Revision == 0 {
		return ErrScope
	}
	if previous == nil {
		deadline, ok := ctx.Deadline()
		if !ok || !state.CreateExpiresAt.Equal(minTime(deadline, s.deadline)) || !time.Now().Before(state.CreateExpiresAt) || state.Repository.PrincipalID != s.principal || state.RepositoryID != "" {
			return ErrScope
		}
		checkpoint.Origin = region.OCIRIssuanceOrigin{GrantSHA256: s.scope.GrantDigest(), Generation: s.scope.Generation(), FoundationOperation: s.original.OperationID, Epoch: s.original.Epoch, ExpiresAt: state.CreateExpiresAt}
	} else {
		checkpoint.Origin = previous.Origin
		if !state.CreateExpiresAt.Equal(previous.Origin.ExpiresAt) || checkpoint.Namespace != previous.Namespace || checkpoint.CompartmentID != previous.CompartmentID || checkpoint.Name != previous.Name || checkpoint.PrincipalID != previous.PrincipalID || checkpoint.Owner != previous.Owner || checkpoint.OperationID != previous.OperationID || previous.RepositoryID != "" && checkpoint.RepositoryID != previous.RepositoryID {
			return ErrScope
		}
		if previous.RepositoryID == "" && checkpoint.RepositoryID != "" {
			if !time.Now().Before(previous.Origin.ExpiresAt) {
				return ErrScope
			}
		}
	}
	if !exists {
		entry.Origin = checkpoint.Origin
		entry.Revision = 1
		entry.State = region.OCIRIssuanceState{ScopeHash: strings.TrimPrefix(issuerKey, "ocir-issuer."), Generation: s.scope.Generation(), GrantDigest: s.scope.GrantDigest(), OperationID: uuid.New().String(), Stage: "identity"}
	}
	if checkpoint.RepositoryID != "" && entry.State.RepositoryID == "" {
		entry.State.RepositoryID = checkpoint.RepositoryID
		entry.Revision++
		if entry.Revision == 0 {
			return ErrScope
		}
	}
	entry.Repository = &checkpoint
	record.OCIRIssuances = maps.Clone(record.OCIRIssuances)
	if record.OCIRIssuances == nil {
		record.OCIRIssuances = map[string]region.OCIRIssuanceEntry{}
	}
	record.OCIRIssuances[issuerKey] = entry
	ctx = ociclient.WithAuthority(ctx, s.guard)
	ctx = ociclient.WithWireAttempt(ctx, func(*http.Request) (func(*http.Response, error, bool) error, error) {
		return func(*http.Response, error, bool) error { return nil }, nil
	})
	if _, err := s.store.CompareAndSwap(ctx, record, etag); err != nil {
		return err
	}
	return s.guard(ctx)
}
