package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"golang.org/x/sys/unix"
)

const credentialChildTimeout = 15 * time.Second

var ErrLiveCredentials = errors.New("live controller credentials are invalid")

// LiveCredentials checks the accepted material inventory at the fixed service
// directory. The root first-install process validates through the same binary
// under the dedicated service UID; restarts validate in the service process.
type LiveCredentials struct {
	Config                 natscell.Config
	ServiceUID             uint32
	ServiceGID             uint32
	ResponseKeyFile        string
	BrokerTicketKeyFile    string
	HostNATSIssuerSeedFile string
	HostTLSIssuerKeyFile   string
	HostTLSIssuerCertFile  string
	// TerraBaseCACertFile and TerraBaseCAKeyFile are the optional C# TerraBase
	// member CA; set both or neither.
	TerraBaseCACertFile    string
	TerraBaseCAKeyFile     string
	ValidateControllerKeys func() error
	directory              string
	allowUnsafeAncestors   bool
	runChild               func(context.Context, []byte, uint32, uint32) error
	// ControllerConfig is the loaded controller config's exact bytes, which an
	// adopted v1 generation pins; accepted restart checks them.
	ControllerConfig []byte
}

func NewLiveCredentialChecker(cfg natscell.Config, serviceUID, serviceGID uint32,
	responseKeyFile, brokerTicketKeyFile, hostNATSIssuerSeedFile, hostTLSIssuerKeyFile, hostTLSIssuerCertFile string,
	validateControllerKeys func() error,
) (LiveCredentials, error) {
	if serviceUID == 0 || serviceGID == 0 || cfg.Lab || cfg.Embedded == nil ||
		responseKeyFile == "" || brokerTicketKeyFile == "" || hostNATSIssuerSeedFile == "" ||
		hostTLSIssuerKeyFile == "" || hostTLSIssuerCertFile == "" || validateControllerKeys == nil {
		return LiveCredentials{}, ErrLiveCredentials
	}
	return LiveCredentials{Config: cfg, ServiceUID: serviceUID, ServiceGID: serviceGID,
		ResponseKeyFile: responseKeyFile, BrokerTicketKeyFile: brokerTicketKeyFile,
		HostNATSIssuerSeedFile: hostNATSIssuerSeedFile, HostTLSIssuerKeyFile: hostTLSIssuerKeyFile,
		HostTLSIssuerCertFile:  hostTLSIssuerCertFile,
		ValidateControllerKeys: validateControllerKeys, directory: MaterialDirectory}, nil
}

func (check LiveCredentials) VerifyLiveCredentials(ctx context.Context, expected MaterialPins, accepted AcceptedIdentity) error {
	acceptance, err := accepted.AcceptanceSHA256()
	if err != nil || expected.acceptance != acceptance || !expected.matchesAccepted(accepted) {
		return ErrLiveCredentials
	}
	return check.verifyLiveCredentials(ctx, expected, accepted.Slot, accepted.SeedSlot, accepted.MaterialReferences)
}

// VerifyInitialLiveCredentials is limited to current, independently verified first formation.
func (check LiveCredentials) VerifyInitialLiveCredentials(ctx context.Context, expected MaterialPins, manifest bootstrap.StartupAuthority) error {
	payload := manifest.Manifest()
	if !sameMaterials(expectedMaterials(payload, payload.Slot), expected.Digests) {
		return ErrLiveCredentials
	}
	expected.references = slotReferences(payload, payload.Slot)
	return check.verifyLiveCredentials(ctx, expected, payload.Slot, payload.SeedSlot, payload.Secrets)
}

func (check LiveCredentials) verifyLiveCredentials(ctx context.Context, expected MaterialPins, slot, seedSlot string, references []bootstrap.SecretReference) error {
	if check.ServiceUID == 0 || check.ServiceGID == 0 || check.Config.Lab || check.Config.Embedded == nil ||
		check.ValidateControllerKeys == nil ||
		len(expected.Digests) == 0 {
		return ErrLiveCredentials
	}
	if err := check.verifyPaths(expected, slot, seedSlot, references); err != nil {
		return err
	}
	if err := check.verifyInventory(expected); err != nil {
		return err
	}
	if os.Geteuid() == int(check.ServiceUID) && os.Getegid() == int(check.ServiceGID) {
		if err := natscell.ValidateProductionCredentials(check.Config); err != nil {
			return err
		}
		return check.ValidateControllerKeys()
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w: credential verifier is neither root nor the service account", ErrLiveCredentials)
	}
	wire, err := protocol.EncodeJSON(CredentialChildRequest{
		Config: check.Config, UID: check.ServiceUID, GID: check.ServiceGID,
		ResponseKeyFile: check.ResponseKeyFile, BrokerTicketKeyFile: check.BrokerTicketKeyFile,
	})
	if err != nil {
		return fmt.Errorf("encode service credential preflight: %w", err)
	}
	run := check.runChild
	if run == nil {
		run = runCredentialChild
	}
	childCtx, cancel := context.WithTimeout(ctx, credentialChildTimeout)
	defer cancel()
	if err := run(childCtx, wire, check.ServiceUID, check.ServiceGID); err != nil {
		return fmt.Errorf("%w: service-account credential preflight: %v", ErrLiveCredentials, err)
	}
	return check.verifyInventory(expected)
}

func (check LiveCredentials) verifyPaths(expected MaterialPins, slot, seedSlot string, references []bootstrap.SecretReference) error {
	if slot == "" || seedSlot == "" {
		return ErrLiveCredentials
	}
	e := check.Config.Embedded
	paths := []string{
		check.Config.CredentialsFile,
		check.Config.TLS.CAFile, check.Config.TLS.CertFile, check.Config.TLS.KeyFile,
		e.TLS.CAFile, e.TLS.CertFile, e.TLS.KeyFile,
		e.RouteTLS.CAFile, e.RouteTLS.CertFile, e.RouteTLS.KeyFile,
		e.OperatorJWTFile, e.SystemJWTFile, e.CellJWTFile, e.SystemCredentialsFile,
		e.TicketPublicKeyFile,
	}
	if e.RoutePasswordFile != "" {
		paths = append(paths, e.RoutePasswordFile)
	}
	// The optional scoped membership user is signed material like every
	// other credential: when configured it must be pinned, and when signed
	// it must be configured.
	if e.MembershipCredentialsFile != "" {
		paths = append(paths, e.MembershipCredentialsFile)
	}
	paths = append(paths, check.ResponseKeyFile, check.BrokerTicketKeyFile,
		check.HostNATSIssuerSeedFile, check.HostTLSIssuerKeyFile, check.HostTLSIssuerCertFile)
	if check.HostNATSIssuerSeedFile != filepath.Join(check.directory, "host-nats-issuer.seed") ||
		check.HostTLSIssuerKeyFile != filepath.Join(check.directory, "host-tls-issuer-key.pem") ||
		check.HostTLSIssuerCertFile != filepath.Join(check.directory, "host-tls-issuer-cert.pem") {
		return fmt.Errorf("%w: host issuer paths differ from fixed roles", ErrLiveCredentials)
	}
	// The member CA follows the membership rule: pinned when configured, and
	// the inventory loop below requires it configured when signed.
	if check.TerraBaseCACertFile != "" || check.TerraBaseCAKeyFile != "" {
		if check.TerraBaseCACertFile != filepath.Join(check.directory, "terrabase-member-ca.pem") ||
			check.TerraBaseCAKeyFile != filepath.Join(check.directory, "terrabase-member-ca.key") {
			return fmt.Errorf("%w: TerraBase member CA paths differ from fixed roles", ErrLiveCredentials)
		}
		paths = append(paths, check.TerraBaseCACertFile, check.TerraBaseCAKeyFile)
	}
	// Interregion and link files must belong to the accepted baseline or adopted generation.
	for _, path := range append(e.InterRegion.Files(), e.Link.Files()...) {
		if !expected.interRegion(filepath.Base(path)) {
			return fmt.Errorf("%w: interregion or link credential path is not pinned by the adopted generation", ErrLiveCredentials)
		}
		paths = append(paths, path)
	}
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		name := filepath.Base(path)
		if path == "" || path != filepath.Join(check.directory, name) || !expected.known(name) {
			return fmt.Errorf("%w: configured credential path is not pinned by signed material", ErrLiveCredentials)
		}
		seen[name] = true
	}
	if slot == seedSlot {
		purposes := make(map[bootstrap.SecretPurpose]bool, 2)
		for _, reference := range references {
			if reference.Purpose != bootstrap.SecretSeedFounder &&
				reference.Purpose != bootstrap.SecretSeedLedgerSigner {
				continue
			}
			name := reference.TargetFile
			if reference.Slot != seedSlot || name == "" ||
				filepath.Base(name) != name || expected.Digests[name] == "" ||
				expected.Digests[name] != reference.SHA256 || seen[name] || purposes[reference.Purpose] {
				return fmt.Errorf("%w: seed signer is not pinned to its signed role and slot", ErrLiveCredentials)
			}
			seen[name] = true
			purposes[reference.Purpose] = true
		}
		if len(purposes) != 0 && (!purposes[bootstrap.SecretSeedFounder] || !purposes[bootstrap.SecretSeedLedgerSigner]) {
			return fmt.Errorf("%w: signed seed signer roles are incomplete", ErrLiveCredentials)
		}
	}
	// A generation's own files have their role in the generation: the chain,
	// and the controller issuers the renewal loop reads by fixed name.
	for name := range expected.Digests {
		if !seen[name] && (!generationOwnFile(name)) {
			return fmt.Errorf("%w: signed credential material has no configured role", ErrLiveCredentials)
		}
	}
	for name := range expected.Issued {
		if !seen[name] {
			return fmt.Errorf("%w: issued credential material has no configured role", ErrLiveCredentials)
		}
	}
	return nil
}

func (check LiveCredentials) verifyInitialPaths(expected MaterialPins, manifest bootstrap.Manifest) error {
	expected.references = slotReferences(manifest, manifest.Slot)
	return check.verifyPaths(expected, manifest.Slot, manifest.SeedSlot, manifest.Secrets)
}

func generationOwnFile(name string) bool {
	return name == MaterialGenerationsFile ||
		bootstrap.MaterialGenerationFiles()[name] == bootstrap.SecretControllerIssuer
}

func (check LiveCredentials) verifyInventory(expected MaterialPins) error {
	dir, err := openMaterialDirectory(check.directory, check.ServiceUID, check.ServiceGID, 0o700, check.allowUnsafeAncestors)
	if err != nil {
		return fmt.Errorf("%w: open fixed credential directory: %v", ErrLiveCredentials, err)
	}
	defer unix.Close(dir)
	copyFD, err := unix.Dup(dir)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(copyFD), check.directory)
	entries, err := file.ReadDir(-1)
	_ = file.Close()
	if err != nil || len(entries) != expected.size() {
		return fmt.Errorf("%w: installed credential inventory differs", ErrLiveCredentials)
	}
	for _, entry := range entries {
		if !expected.known(entry.Name()) {
			return fmt.Errorf("%w: unpinned credential file", ErrLiveCredentials)
		}
		var content []byte
		var err error
		if want := expected.Digests[entry.Name()]; want != "" {
			content, err = readMaterial(dir, entry.Name(), check.ServiceUID, check.ServiceGID, want, bootstrap.MaxSecretBytes)
		} else {
			// Issued files were checked by rule in VerifyRestart.
			content, err = readUnpinned(dir, entry.Name(), check.ServiceUID, check.ServiceGID, bootstrap.MaxSecretBytes)
		}
		if err != nil {
			return fmt.Errorf("%w: installed credential %s: %v", ErrLiveCredentials, entry.Name(), err)
		}
		clear(content)
	}
	return nil
}

// CredentialChildRequest is the bounded service-user preflight request passed
// over stdin to the same executable. It carries file paths, never secrets.
type CredentialChildRequest struct {
	Config              natscell.Config `json:"config"`
	UID                 uint32          `json:"uid"`
	GID                 uint32          `json:"gid"`
	ResponseKeyFile     string          `json:"responseKeyFile"`
	BrokerTicketKeyFile string          `json:"brokerTicketKeyFile"`
}

func runCredentialChild(ctx context.Context, wire []byte, uid, gid uint32) error {
	command := exec.CommandContext(ctx, "/proc/self/exe", "bootstrap-credential-check")
	command.Stdin = bytes.NewReader(wire)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uid, Gid: gid, Groups: []uint32{},
	}}
	if err := command.Run(); err != nil {
		return fmt.Errorf("service credential child exited unsuccessfully: %w", err)
	}
	return nil
}

// RunCredentialValidationChild is the hidden, read-only same-binary command.
// The parent supplies only configuration and expected service identity; no
// secret bytes or cloud authority are passed through stdin.
func RunCredentialValidationChild(input io.Reader, validateControllerKeys func(CredentialChildRequest) error) error {
	const maximum = 1 << 20
	wire, err := io.ReadAll(io.LimitReader(input, maximum+1))
	if err != nil || len(wire) == 0 || len(wire) > maximum {
		return ErrLiveCredentials
	}
	var request CredentialChildRequest
	if err := protocol.DecodeStrict(wire, &request, maximum); err != nil ||
		request.UID == 0 || request.GID == 0 ||
		request.ResponseKeyFile == "" || request.BrokerTicketKeyFile == "" || validateControllerKeys == nil ||
		os.Geteuid() != int(request.UID) || os.Getegid() != int(request.GID) {
		return ErrLiveCredentials
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return ErrLiveCredentials
	}
	if err := natscell.ValidateProductionCredentials(request.Config); err != nil {
		return err
	}
	return validateControllerKeys(request)
}

var _ LiveCredentialChecker = LiveCredentials{}
