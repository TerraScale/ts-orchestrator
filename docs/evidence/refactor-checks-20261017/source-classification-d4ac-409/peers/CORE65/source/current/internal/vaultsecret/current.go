package vaultsecret

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// Current holds a value in memory. Formatting and JSON expose metadata only.
type Current struct {
	ID        string    `json:"id"`
	Version   int64     `json:"version"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	value     string
}

func (s Current) Value() string    { return s.value }
func (s Current) String() string   { return fmt.Sprintf("Vault secret %s version %d", s.ID, s.Version) }
func (s Current) GoString() string { return s.String() }

// ReadCurrent returns the CURRENT version, never LATEST or PENDING.
func ReadCurrent(ctx context.Context, client BundleClient, ref Ref) (Current, error) {
	if ref.region() == "" || len(ref.Name) > 255 || !nameRE.MatchString(ref.Name) {
		return Current{}, errors.New("Vault current read requires a regional Vault and a secret name")
	}
	bundle, err := readBundle(ctx, client, ref.Vault, ref.Name)
	if err != nil {
		return Current{}, err
	}
	if bundle.SecretId == nil || !secretOCIDRE.MatchString(*bundle.SecretId) ||
		strings.Split(*bundle.SecretId, ".")[3] != ref.region() ||
		bundle.VersionNumber == nil || *bundle.VersionNumber < 1 ||
		bundle.TimeOfExpiry != nil && !time.Now().Before(bundle.TimeOfExpiry.Time) ||
		bundle.TimeOfDeletion != nil && !time.Now().Before(bundle.TimeOfDeletion.Time) {
		return Current{}, fmt.Errorf("Vault secret %s returned invalid or expired version metadata", ref.Name)
	}
	value, err := decodeBundle(bundle.SecretBundle, ref.Name)
	if err != nil {
		return Current{}, err
	}
	expires := time.Time{}
	for _, deadline := range []*common.SDKTime{bundle.TimeOfExpiry, bundle.TimeOfDeletion} {
		if deadline != nil && (expires.IsZero() || deadline.Time.Before(expires)) {
			expires = deadline.Time
		}
	}
	return Current{ID: *bundle.SecretId, Version: *bundle.VersionNumber, ExpiresAt: expires, value: value}, nil
}

// ResolveCurrent reads a complete set before the consumer can publish it.
func ResolveCurrent(ctx context.Context, refs map[string]Ref, client func(string) (BundleClient, error)) (map[string]Current, error) {
	if err := safeEnv(); err != nil {
		return nil, err
	}
	if len(refs) == 0 || len(refs) > MaxRefs {
		return nil, fmt.Errorf("Vault delivery requires 1 to %d references", MaxRefs)
	}
	values, clients, total := map[string]Current{}, map[string]BundleClient{}, 0
	for key, ref := range refs {
		if !envKeyRE.MatchString(key) || ref.region() == "" {
			return nil, errors.New("Vault delivery has an invalid key or regional Vault")
		}
		bundles := clients[ref.region()]
		if bundles == nil {
			var err error
			bundles, err = client(ref.region())
			if err != nil {
				return nil, fmt.Errorf("Vault client for %s is unavailable", ref.region())
			}
			clients[ref.region()] = bundles
		}
		value, err := ReadCurrent(ctx, bundles, ref)
		if err != nil {
			return nil, err
		}
		if !FileKey(key) && strings.ContainsRune(value.value, 0) {
			return nil, fmt.Errorf("Vault secret %s does not fit an environment variable", ref.Name)
		}
		if total += len(key) + len(value.value); total > maxResolved {
			return nil, fmt.Errorf("Vault secrets exceed %d bytes together", maxResolved)
		}
		values[key] = value
	}
	return values, nil
}

// ReadCurrentRefs authenticates with the regional host's instance principal.
func ReadCurrentRefs(ctx context.Context, refs map[string]Ref) (map[string]Current, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return ResolveCurrent(ctx, refs, func(region string) (BundleClient, error) {
		factory, err := ociclient.InstancePrincipal(region)
		if err != nil {
			return nil, err
		}
		return SecretsClient(factory)
	})
}

// Watch applies the first complete snapshot before polling CURRENT versions.
// Later failures retain the last successful snapshot and retry on the next
// poll. Consumers reopen file deliveries or atomically replace their in-memory
// configuration in apply; they never need to redeploy to see a new version.
func Watch(ctx context.Context, refs map[string]Ref, interval time.Duration,
	apply func(map[string]Current) error, failed func(error),
) error {
	return watch(ctx, refs, interval, ReadCurrentRefs, apply, failed)
}

func watch(ctx context.Context, refs map[string]Ref, interval time.Duration,
	read func(context.Context, map[string]Ref) (map[string]Current, error),
	apply func(map[string]Current) error, failed func(error),
) error {
	if interval <= 0 || apply == nil {
		return errors.New("Vault watch requires a positive interval and a consumer")
	}
	refs = maps.Clone(refs)
	var installed map[string]Current
	refresh := func() error {
		readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		next, err := read(readCtx, refs)
		if err != nil {
			return err
		}
		// OCI can briefly return an older CURRENT after a successful write.
		// Rollback publishes old content as a new version, never an old stage.
		for key, value := range next {
			if previous, ok := installed[key]; ok && previous.ID == value.ID && value.Version < previous.Version {
				return errors.New("Vault CURRENT moved backwards; retaining the last applied snapshot")
			}
		}
		if maps.EqualFunc(installed, next, func(a, b Current) bool { return a.ID == b.ID && a.Version == b.Version }) {
			return nil
		}
		if err := apply(maps.Clone(next)); err != nil {
			return errors.New("apply Vault secret snapshot failed")
		}
		installed = next
		return nil
	}
	if err := refresh(); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := refresh(); err != nil && failed != nil {
				failed(err)
			}
		}
	}
}
