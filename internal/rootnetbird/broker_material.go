package rootnetbird

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

// managerReaderState is installed only after exact CURRENT readback and IAM.
// Its original source, user, version and deadline never follow a replacement.
type managerReaderState struct {
	cell, user, source string
	deadline           time.Time
	guard              func(context.Context) error
}

// ReconcileManagerReader belongs to the exclusive root lifecycle, never IPC.
// sourceGuard retains APP's original exclusive root startup authority, ready
// node, source and credentials; it is never a public runtime-lease bypass.
func (b *Backend) ReconcileManagerReader(ctx context.Context, sourceGuard func(context.Context) error) error {
	if b == nil || b.factory == nil || os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || sourceGuard == nil {
		return rootoci.ErrUnauthorized
	}
	originalDeadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(originalDeadline) {
		return rootoci.ErrUnauthorized
	}
	b.mu.RLock()
	s, previous := b.sources, b.managerReader
	b.mu.RUnlock()
	if s == nil {
		return rootoci.ErrUnavailable
	}
	if previous != nil {
		return previous.guard(ctx)
	}
	original := ctx
	credentialCtx := s.Credentials.Context()
	if credentialCtx == nil {
		return rootoci.ErrUnauthorized
	}
	credentialDeadline, ok := credentialCtx.Deadline()
	if !ok {
		return rootoci.ErrUnauthorized
	}
	deadline := earlier(originalDeadline, credentialDeadline)
	ctx, cancelCredential := context.WithDeadline(ctx, deadline)
	stopCredential := context.AfterFunc(credentialCtx, cancelCredential)
	defer func() { stopCredential(); cancelCredential() }()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	baseGuard := func(check context.Context) error {
		if check == nil || check.Err() != nil || original.Err() != nil || !time.Now().Before(originalDeadline) || sourceGuard(check) != nil || s.Credentials.Guard(check) != nil {
			return rootoci.ErrUnauthorized
		}
		return check.Err()
	}
	if err := baseGuard(ctx); err != nil {
		return err
	}
	runtime, err := s.Authority.ReadRuntimeAuthority(ctx, s.Accepted, time.Now().UTC())
	if err != nil {
		return rootoci.ErrUnauthorized
	}
	deadline = earlier(deadline, runtime.ExpiresAt())
	ctx, cancelRuntime := context.WithDeadline(ctx, deadline)
	defer cancelRuntime()
	identity := runtime.Identity()
	if identity.Cell != s.Accepted.Cell || identity.OCIRegion != b.factory.Region() {
		return rootoci.ErrUnauthorized
	}
	source, err := rootsecret.LoadNetBirdBrokerSourceForOperation(ctx, original, b.factory, identity.Cell, identity.Slot)
	if err != nil {
		return rootoci.ErrUnauthorized
	}
	deadline = earlier(deadline, source.ExpiresAt())
	ctx, cancelSource := context.WithDeadline(ctx, deadline)
	defer cancelSource()
	manifest := source.Startup().Manifest()
	if manifest.DeploymentID != identity.DeploymentID || manifest.ClusterID != identity.ClusterID || manifest.Environment != identity.Environment || manifest.Slot != identity.Slot ||
		source.Startup().Digest() != s.Accepted.ManifestSHA256 || source.Startup().AnchorDigest() != s.Accepted.AnchorSHA256 {
		return rootoci.ErrUnauthorized
	}
	recipient, err := region.VerifyNetBirdManagerRecipientForOperation(ctx, original, b.factory, source.Resolver(), source.Source())
	if err != nil {
		return rootoci.ErrUnauthorized
	}
	deadline = earlier(deadline, recipient.ExpiresAt())
	ctx, cancelRecipient := context.WithDeadline(ctx, deadline)
	defer cancelRecipient()
	publication := source
	guard := func(check context.Context) error {
		if check == nil {
			return rootoci.ErrUnauthorized
		}
		check, stop := context.WithDeadline(check, deadline)
		stopOriginal := context.AfterFunc(original, stop)
		stopCredentials := context.AfterFunc(credentialCtx, stop)
		defer func() { stopOriginal(); stopCredentials(); stop() }()
		check = ociclient.WithRequestGuard(check, baseGuard)
		if baseGuard(check) != nil || !time.Now().Before(deadline) || source.Guard(check) != nil || recipient.Check(check) != nil {
			return rootoci.ErrUnauthorized
		}
		if publication.Startup().Digest() != source.Startup().Digest() && publication.Guard(check) != nil {
			return rootoci.ErrUnauthorized
		}
		current, err := s.Authority.ReadRuntimeAuthority(check, s.Accepted, time.Now().UTC())
		if err != nil || current.Identity() != identity || current.Anchor().Digest() != runtime.Anchor().Digest() || !current.ExpiresAt().Equal(runtime.ExpiresAt()) {
			return rootoci.ErrUnauthorized
		}
		return baseGuard(check)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(b.factory.Provider())
	if err != nil {
		return rootoci.ErrUnavailable
	}
	management.SetRegion(b.factory.Region())
	b.factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(b.factory)
	if err != nil {
		return rootoci.ErrUnavailable
	}
	target := source.Source().Template().VaultTarget()
	ref := rootsecret.NetBirdBrokerRef(source)
	ctx = ociclient.WithRequestGuard(ctx, guard)
	stored, err := vaultsecret.Ensure(ctx, &management, vaultsecret.Target{CompartmentID: target.CompartmentOCID, VaultID: target.VaultOCID, KeyID: target.KMSKeyOCID}, ref.Name, "Original dedicated NetBird manager broker reader", func(create context.Context) (string, error) {
		if err := guard(create); err != nil {
			return "", err
		}
		files := map[string][]byte{}
		defer func() {
			for _, wire := range files {
				clear(wire)
			}
		}()
		read := func(name string) ([]byte, error) {
			if err := guard(create); err != nil {
				return nil, err
			}
			wire, err := readBrokerIssuerFile(name)
			if err != nil {
				return nil, err
			}
			files[name] = wire
			return wire, nil
		}
		issuer, err := bootstrapmaterial.LoadStartupControllerIssuer(create, source.Startup(), read, time.Now().UTC())
		if err != nil {
			return "", rootoci.ErrUnauthorized
		}
		defer issuer.Wipe()
		credentials, err := issuer.IssueNetBirdReadCredentials(deadline)
		if err != nil {
			return "", rootoci.ErrUnauthorized
		}
		defer clear(credentials)
		raw, err := jwt.ParseDecoratedJWT(credentials)
		if err != nil {
			return "", rootoci.ErrUnauthorized
		}
		claim, err := jwt.DecodeUserClaims(raw)
		if err != nil {
			return "", rootoci.ErrUnauthorized
		}
		cert, key, err := issuer.IssueNetBirdReadTLS(recipient.PrivateIP(), time.Unix(claim.Expires, 0))
		if err != nil {
			return "", rootoci.ErrUnauthorized
		}
		defer clear(key)
		material, err := rootsecret.NewNetBirdBrokerMaterial(source, recipient, credentials, cert, key, files["ca.pem"], files["operator.jwt"], files["cell.jwt"])
		if err != nil {
			return "", rootoci.ErrUnauthorized
		}
		defer clear(material.Credentials)
		defer clear(material.Key)
		wire, err := material.Encode()
		if err != nil {
			return "", errors.New("NetBird broker delivery exceeds its fixed 16 KiB bound or is invalid")
		}
		defer clear(wire)
		if err := guard(create); err != nil {
			return "", err
		}
		return string(wire), nil
	})
	if err != nil {
		return err
	}
	if guard(ctx) != nil {
		return rootoci.ErrUnauthorized
	}
	current, err := vaultsecret.ReadCurrent(ctx, &bundles, ref)
	if err != nil || current.ID != stored.ID {
		return rootoci.ErrUnauthorized
	}
	if !current.ExpiresAt.IsZero() {
		deadline = earlier(deadline, current.ExpiresAt)
	}
	ctx, cancelCurrent := context.WithDeadline(ctx, deadline)
	defer cancelCurrent()
	if guard(ctx) != nil {
		return rootoci.ErrUnauthorized
	}
	material, err := rootsecret.DecodeNetBirdBrokerMaterial([]byte(current.Value()))
	if err != nil {
		return rootoci.ErrUnauthorized
	}
	defer clear(material.Credentials)
	defer clear(material.Key)
	deadline = earlier(deadline, material.ExpiresAt)
	ctx, cancelMaterial := context.WithDeadline(ctx, deadline)
	defer cancelMaterial()
	if material.StartupSlot != source.Startup().Manifest().Slot {
		publication, err = source.ForStartupSlot(ctx, material.StartupSlot)
		if err != nil {
			return rootoci.ErrUnauthorized
		}
	}
	_, user, err := rootsecret.CheckNetBirdBrokerMaterial(material, publication, recipient, time.Now().UTC())
	if err != nil {
		return rootoci.ErrUnauthorized
	}
	policyErr := region.VerifyNetBirdBrokerReader(ctx, b.factory, source.Resolver(), source.Source(), recipient)
	if errors.Is(policyErr, region.ErrNetBirdBrokerPolicyAbsent) {
		home, err := region.NewRuntimeHomeIAMAuthority(ctx, s.Authority, s.Accepted, source.Resolver())
		if err != nil {
			return rootoci.ErrUnauthorized
		}
		ensureErr := home.EnsureNetBirdBrokerReader(ctx, source.Source(), recipient)
		// A concurrent admitted controller may have completed the original policy.
		policyErr = region.VerifyNetBirdBrokerReader(ctx, b.factory, source.Resolver(), source.Source(), recipient)
		if policyErr != nil {
			return errors.Join(ensureErr, policyErr)
		}
	}
	if policyErr != nil || guard(ctx) != nil {
		return errors.Join(rootoci.ErrUnauthorized, policyErr)
	}
	contentDigest := digest([]byte(current.Value()))
	secretID, secretVersion, secretExpiry := current.ID, current.Version, current.ExpiresAt
	state := &managerReaderState{cell: material.Cell, user: user, source: material.SourceSHA256, deadline: material.ExpiresAt}
	state.guard = func(check context.Context) error {
		if check == nil {
			return rootoci.ErrUnauthorized
		}
		check, stopDeadline := context.WithDeadline(check, deadline)
		stopOriginal := context.AfterFunc(original, stopDeadline)
		stopCredentials := context.AfterFunc(credentialCtx, stopDeadline)
		defer func() { stopOriginal(); stopCredentials(); stopDeadline() }()
		check, stop := context.WithTimeout(check, 30*time.Second)
		defer stop()
		if guard(check) != nil || !time.Now().Before(deadline) {
			return rootoci.ErrUnauthorized
		}
		observed, err := vaultsecret.ReadCurrent(ociclient.WithRequestGuard(check, guard), &bundles, ref)
		if err != nil || observed.ID != secretID || observed.Version != secretVersion || !observed.ExpiresAt.Equal(secretExpiry) || digest([]byte(observed.Value())) != contentDigest {
			return rootoci.ErrUnauthorized
		}
		return guard(check)
	}
	if state.guard(ctx) != nil {
		return rootoci.ErrUnauthorized
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.managerReader != nil {
		return rootoci.ErrUnauthorized
	}
	b.managerReader = state
	return nil
}

func (b *Backend) checkManagerReadOpen(ctx context.Context, proof rootoci.NetBirdReadOpen) error {
	if b == nil || ctx == nil || os.Geteuid() != 0 {
		return rootoci.ErrUnauthorized
	}
	b.mu.RLock()
	state := b.managerReader
	b.mu.RUnlock()
	if state == nil || proof.Schema != 1 || !entityid.Valid(proof.Nonce) || proof.Cell != state.cell || proof.User != state.user || proof.SourceSHA256 != state.source ||
		!proof.ExpiresAt.Equal(state.deadline) || !time.Now().Before(state.deadline) || state.guard(ctx) != nil {
		return rootoci.ErrUnauthorized
	}
	public, err := nkeys.FromPublicKey(state.user)
	if err != nil || public.Verify(rootsecret.NetBirdReadOpenSigningBytes(proof), proof.Signature) != nil {
		return rootoci.ErrUnauthorized
	}
	return state.guard(ctx)
}

func readBrokerIssuerFile(name string) ([]byte, error) {
	if !strings.Contains("|ca.pem|operator.jwt|cell.jwt|controller-tls-issuer-cert.pem|controller-tls-issuer-key.pem|controller-account-signer.seed|", "|"+name+"|") || strings.ContainsAny(name, "/\\") {
		return nil, rootoci.ErrUnauthorized
	}
	directory, err := unix.Open(bootstrap.MaterialDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, rootoci.ErrUnavailable
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, rootoci.ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0o077 != 0 || stat.Size <= 0 || stat.Size > bootstrap.MaxSecretBytes {
		return nil, rootoci.ErrUnauthorized
	}
	wire, err := io.ReadAll(io.LimitReader(file, bootstrap.MaxSecretBytes+1))
	if err != nil || len(wire) != int(stat.Size) {
		clear(wire)
		return nil, rootoci.ErrUnauthorized
	}
	return wire, nil
}
