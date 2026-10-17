package rootsecret

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type managedMaterialKeySnapshot struct {
	controller controllerReaderSnapshot
	reference  bootstrap.SecretReference
	enrollment []byte
	public     ed25519.PublicKey
}

// ManagedMaterialControllerKey retains the fixed accepted response key only in
// root memory for the managed-material semantic backend. It grants no admission.
type ManagedMaterialControllerKey struct {
	mu       sync.Mutex
	key      ed25519.PrivateKey
	snapshot managedMaterialKeySnapshot
	original context.Context
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
}

// OpenManagedMaterialControllerKey derives its source from installed accepted
// authority. No caller can select a secret, version, public pin or private key.
func OpenManagedMaterialControllerKey(ctx context.Context) (*ManagedMaterialControllerKey, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil {
		return nil, ErrDelivery
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return nil, ErrDelivery
	}
	snapshot, err := loadManagedMaterialKeySnapshot()
	if err != nil {
		return nil, ErrDelivery
	}
	if expiry := snapshot.controller.expires; !expiry.IsZero() && expiry.Before(deadline) {
		deadline = expiry
	}
	readCtx, cancelRead := context.WithDeadline(ctx, deadline)
	defer cancelRead()
	readCtx, cancelTimeout := context.WithTimeout(readCtx, 30*time.Second)
	defer cancelTimeout()
	guard := func() error { return guardManagedMaterialKeySnapshot(readCtx, snapshot, deadline) }
	region, err := snapshot.controller.acceptedRegion()
	if err != nil || guard() != nil {
		return nil, ErrDelivery
	}
	factory, err := ociclient.InstancePrincipal(region)
	if err != nil || guard() != nil {
		return nil, ErrDelivery
	}
	client, err := vaultsecret.SecretsClient(factory)
	if err != nil || guard() != nil {
		return nil, ErrDelivery
	}
	client.HTTPClient = credentialDispatcher{next: client.HTTPClient, guard: guard}
	value, providerExpiry, err := readExact(readCtx, &client, snapshot.reference)
	defer clear(value)
	if err != nil || guard() != nil {
		return nil, ErrDelivery
	}
	if !providerExpiry.IsZero() && providerExpiry.Before(deadline) {
		deadline = providerExpiry
	}
	encoded := bytes.TrimSpace(value)
	if len(encoded) != base64.StdEncoding.EncodedLen(ed25519.PrivateKeySize) {
		return nil, ErrDelivery
	}
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	count, err := base64.StdEncoding.Strict().Decode(key, encoded)
	if err != nil || count != ed25519.PrivateKeySize {
		clear(key)
		return nil, ErrDelivery
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	matches := bytes.Equal(key, derived) && bytes.Equal(derived.Public().(ed25519.PublicKey), snapshot.public)
	clear(derived)
	if !matches || guardManagedMaterialKeySnapshot(ctx, snapshot, deadline) != nil {
		clear(key)
		return nil, ErrDelivery
	}
	lease, cancel := context.WithDeadline(ctx, deadline)
	source := &ManagedMaterialControllerKey{key: key, snapshot: snapshot, original: ctx, ctx: lease, cancel: cancel, deadline: deadline}
	if err := source.Guard(ctx); err != nil {
		source.Close()
		return nil, ErrDelivery
	}
	return source, nil
}

// Key returns a guarded clone only to the root managed-material backend. The
// backend must clear its clone and guard the source before and after each effect.
func (source *ManagedMaterialControllerKey) Key() (ed25519.PrivateKey, error) {
	if source == nil {
		return nil, ErrDelivery
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.guard(source.ctx) != nil {
		return nil, ErrDelivery
	}
	key := bytes.Clone(source.key)
	if source.original.Err() != nil || source.ctx.Err() != nil || !time.Now().Before(source.deadline) {
		clear(key)
		return nil, ErrDelivery
	}
	return key, nil
}

// Guard synchronously rejects expiry, closure or accepted source drift.
func (source *ManagedMaterialControllerKey) Guard(ctx context.Context) error {
	if source == nil {
		return ErrDelivery
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.guard(ctx)
}

func (source *ManagedMaterialControllerKey) guard(ctx context.Context) error {
	if source.original == nil || source.original.Err() != nil || source.ctx == nil || source.ctx.Err() != nil ||
		ctx == nil || len(source.key) != ed25519.PrivateKeySize {
		return ErrDelivery
	}
	deadline := source.deadline
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if guardManagedMaterialKeySnapshot(ctx, source.snapshot, deadline) != nil || source.original.Err() != nil || source.ctx.Err() != nil {
		return ErrDelivery
	}
	return nil
}

// Deadline is the immutable earliest original caller, signed source or provider expiry.
func (source *ManagedMaterialControllerKey) Deadline() time.Time {
	if source == nil {
		return time.Time{}
	}
	return source.deadline
}

// Close cancels the source and clears its retained private key.
func (source *ManagedMaterialControllerKey) Close() {
	if source == nil {
		return
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.cancel != nil {
		source.cancel()
	}
	clear(source.key)
	source.key = nil
}

func guardManagedMaterialKeySnapshot(ctx context.Context, snapshot managedMaterialKeySnapshot, deadline time.Time) error {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return ErrDelivery
	}
	current, err := loadManagedMaterialKeySnapshot()
	if err != nil || !reflect.DeepEqual(snapshot, current) || ctx.Err() != nil || !time.Now().Before(deadline) {
		return ErrDelivery
	}
	return nil
}

func loadManagedMaterialKeySnapshot() (managedMaterialKeySnapshot, error) {
	var snapshot managedMaterialKeySnapshot
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return snapshot, ErrDelivery
		}
	}
	controller, err := loadControllerReaderSnapshot()
	if err != nil {
		return snapshot, ErrDelivery
	}
	var config struct {
		Controller struct {
			ResponseKeyFile string `json:"response_key_file"`
		} `json:"controller"`
	}
	if json.Unmarshal(controller.config, &config) != nil {
		return snapshot, ErrDelivery
	}
	name := controller.accepted.Slot + "-response.key"
	reference, ok := controller.refs[name]
	if !ok || reference.Purpose != bootstrap.SecretController || reference.Slot != controller.accepted.Slot || reference.TargetFile != name ||
		config.Controller.ResponseKeyFile != filepath.Join(bootstrap.MaterialDirectory, name) {
		return snapshot, ErrDelivery
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(controller.accepted)
	if err != nil {
		return snapshot, ErrDelivery
	}
	bundle, err := hostenroll.ParsePublicBundle(launch.HostEnrollment)
	if err != nil {
		return snapshot, ErrDelivery
	}
	public, err := bundle.ResponsePublicKey()
	if err != nil {
		return snapshot, ErrDelivery
	}
	return managedMaterialKeySnapshot{controller: controller, reference: reference, enrollment: launch.HostEnrollment, public: public}, nil
}
