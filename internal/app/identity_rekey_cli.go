package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	selfupdatecli "github.com/TerraScale/ts-orchestrator/internal/selfupdate/cli"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

const identityRekeyUsage = "Usage: ts-orch identity-rekey <stage|install|precommit|authorize-resume> --inputs DIRECTORY\n       ts-orch identity-rekey <abort|recover-inputs> --inputs DIRECTORY --journal-sha256 SHA256\n       ts-orch identity-rekey cleanup\n\nInputs: root:root 0700 directory containing identity-rekey.json, material-generations.json, receipt.json, delegation.json, controller.json, its three sidecars, the four launch files (all root:root 0600), and terrascale-orchestrator (root-owned executable).\nStage, install and authorize-resume read connection.json. Precommit and authorize-resume additionally read root-signing.key (PKCS#8 PEM), both root:root 0600. It authenticates and prepares before sampling the final floor, signing, staging and publishing one barrier. Stage is for the peers of that winning reset. Recover-inputs republishes the exact verified durable journal for the same proposal after interrupted finalization. Install requires the exact durable journal, authenticated shared commitment and a stopped controller. Authorize-resume root-signs only an independently observed out-of-window held transaction. Cleanup requires shared completion.\n"

func runIdentityRekey(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, identityRekeyUsage)
		return err
	}
	command := args[0]
	if command != "stage" && command != "install" && command != "precommit" && command != "abort" && command != "recover-inputs" && command != "cleanup" && command != "authorize-resume" {
		return fmt.Errorf("unknown identity-rekey command %q", command)
	}
	if command == "cleanup" {
		if len(args) != 1 {
			return errors.New("identity-rekey cleanup accepts no arguments")
		}
		return CleanupIdentityRekey(ctx)
	}
	flags := flag.NewFlagSet("identity-rekey "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("inputs", "", "root-owned reviewed public inputs directory")
	expectedSHA256 := flags.String("journal-sha256", "", "exact durable journal digest to recover or archive")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *directory == "" || flags.NArg() != 0 {
		return errors.New("identity-rekey " + command + " requires only --inputs DIRECTORY")
	}
	requiresDigest := command == "abort" || command == "recover-inputs"
	if requiresDigest && *expectedSHA256 == "" || !requiresDigest && *expectedSHA256 != "" {
		return errors.New("only identity-rekey abort and recover-inputs require --journal-sha256")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return errors.New("identity-rekey requires root:root on the verified controller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := openIdentityRekeyInputs(*directory)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	inputs, err := readIdentityRekeyInputs(dir, *directory, 0, 0)
	if err != nil {
		return err
	}
	if command == "recover-inputs" {
		final, _, err := bootstrapstart.ReadStagedIdentityRekeyEvidence(*expectedSHA256)
		if err != nil {
			return err
		}
		return recoverFinalIdentityRekeyInput(dir, inputs.journal, final)
	}
	if command == "abort" {
		wire, err := protocol.EncodeJSON(inputs.journal)
		if err != nil || controllerSHA256(wire) != *expectedSHA256 {
			return bootstrapstart.ErrIdentityRekeyJournal
		}
		_, verified, err := bootstrapstart.ReadStagedIdentityRekeyEvidence(*expectedSHA256)
		if err != nil {
			return err
		}
		connection, err := readIdentityRekeyConnection(dir, verified.Accepted(), inputs.journal.Replicas)
		if err != nil {
			return err
		}
		runtime, err := natscell.Start(ctx, connection.NATS)
		if err != nil {
			return err
		}
		defer runtime.Close()
		return AbortIdentityRekey(ctx, *expectedSHA256, inputs.files, runtime.JetStream())
	}
	if command == "install" || command == "authorize-resume" {
		return resumeIdentityRekeyInputs(ctx, dir, inputs, command, output)
	}
	now := time.Now().Round(0).UTC()
	verified, roots, err := bootstrapstart.VerifyIdentityRekeyInstall(inputs.journal, now)
	if err != nil {
		return err
	}
	if err := selfupdatecli.VerifyIdentityRekeyCandidate(ctx, verified.Accepted(), roots, inputs.candidate,
		inputs.receipt, inputs.delegation, now); err != nil {
		return err
	}
	if command == "stage" {
		connection, err := readIdentityRekeyConnection(dir, verified.Accepted(), inputs.journal.Replicas)
		if err != nil {
			return err
		}
		runtime, err := natscell.Start(ctx, connection.NATS)
		if err != nil {
			return err
		}
		defer runtime.Close()
		return StageIdentityRekey(ctx, inputs.journal, inputs.files, inputs.chain, runtime.JetStream())
	}
	if command == "precommit" {
		return precommitIdentityRekeyInputs(ctx, dir, inputs, verified.Accepted(), output)
	}
	return errors.New("unhandled identity rekey command")
}

// IdentityRekeyConnection is fresh operator input, never an installed old config.
type IdentityRekeyConnection struct {
	Version int             `json:"version"`
	NATS    natscell.Config `json:"nats"`
}

func (connection IdentityRekeyConnection) Validate(accepted bootstrapstart.AcceptedIdentity, replicas int) error {
	cfg := connection.NATS
	if connection.Version != 1 || accepted.Validate() != nil || cfg.Embedded != nil ||
		cfg.Cell != strings.ToLower(accepted.Cell) || cfg.Instance != accepted.Slot || cfg.Replicas != replicas ||
		cfg.ClientRole != "controller" || cfg.URL == "" || cfg.CredentialsFile == "" || cfg.NKeySeedFile != "" ||
		cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" || cfg.TLS.CAFile == "" {
		return errors.New("identity rekey requires an explicit v1 production external controller connection matching the reviewed target and quorum")
	}
	return nil
}

func readIdentityRekeyConnection(dir int, accepted bootstrapstart.AcceptedIdentity, replicas int) (IdentityRekeyConnection, error) {
	wire, err := readExactControllerFile(dir, "connection.json", 0, 0, 0o600, 64<<10)
	if err != nil {
		return IdentityRekeyConnection{}, err
	}
	var connection IdentityRekeyConnection
	if err := protocol.DecodeStrict(wire, &connection, 64<<10); err != nil {
		return IdentityRekeyConnection{}, err
	}
	canonical, err := protocol.EncodeJSON(connection)
	if err != nil || !bytes.Equal(wire, canonical) {
		return IdentityRekeyConnection{}, errors.New("identity rekey connection must be canonical v1 JSON")
	}
	if err := connection.Validate(accepted, replicas); err != nil {
		return IdentityRekeyConnection{}, err
	}
	return connection, nil
}

func precommitIdentityRekeyInputs(ctx context.Context, dir int, inputs identityRekeyInputs, accepted bootstrapstart.AcceptedIdentity, output io.Writer) error {
	connection, err := readIdentityRekeyConnection(dir, accepted, inputs.journal.Replicas)
	if err != nil {
		return err
	}
	key, err := readIdentityRekeyRootKey(dir)
	if err != nil {
		return err
	}
	defer clear(key)
	runtime, err := natscell.Start(ctx, connection.NATS)
	if err != nil {
		return err
	}
	defer runtime.Close()
	final, sequence, commitErr := StageAndPrecommitIdentityRekey(ctx, inputs.journal, inputs.files, inputs.chain, runtime.JetStream(), key)
	// The fixed journal survives an unknown outcome; this copy makes the same
	// finalized public inputs directly consumable by the subsequent installer.
	finalWire, encodeErr := protocol.EncodeJSON(final)
	original, _ := protocol.EncodeJSON(inputs.journal)
	var writeErr error
	if encodeErr == nil && !bytes.Equal(original, finalWire) {
		writeErr = writeFinalIdentityRekeyInput(dir, finalWire)
	}
	if err := errors.Join(commitErr, encodeErr, writeErr); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "identity rekey held barrier operation=%s cell=%s sequence=%d\n", accepted.OperationID, connection.NATS.Cell, sequence)
	return err
}

func writeFinalIdentityRekeyInput(dir int, wire []byte) error {
	temporary := ".identity-rekey.final." + rand.Text() + ".json"
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return err
	}
	if count, err := file.Write(wire); err != nil || count != len(wire) {
		return errors.Join(err, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := unix.Renameat(dir, temporary, dir, "identity-rekey.json"); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

func recoverFinalIdentityRekeyInput(dir int, proposal, final bootstrapstart.IdentityRekeyJournal) error {
	wire, err := protocol.EncodeJSON(final)
	if err != nil {
		return err
	}
	// Finalization changes only the signed lease floor and acceptance time.
	final.AcceptedWire, final.ResetWire = proposal.AcceptedWire, proposal.ResetWire
	normalized, err := protocol.EncodeJSON(final)
	original, originalErr := protocol.EncodeJSON(proposal)
	if err != nil || originalErr != nil || !bytes.Equal(normalized, original) {
		return errors.Join(bootstrapstart.ErrIdentityRekeyJournal, err, originalErr)
	}
	return writeFinalIdentityRekeyInput(dir, wire)
}

type identityRekeyInputs struct {
	journal    bootstrapstart.IdentityRekeyJournal
	files      map[string][]byte
	chain      []byte
	receipt    []byte
	delegation []byte
	candidate  string
}

func readIdentityRekeyInputs(dir int, directory string, uid, gid uint32) (identityRekeyInputs, error) {
	var inputs identityRekeyInputs
	read := func(name string, limit int) ([]byte, error) {
		wire, err := readExactControllerFile(dir, name, uid, gid, 0o600, limit)
		if err != nil {
			return nil, fmt.Errorf("read identity rekey input %s: %w", name, err)
		}
		return wire, nil
	}
	wire, err := read("identity-rekey.json", bootstrapstart.MaxIdentityRekeyJournalBytes)
	if err != nil {
		return inputs, err
	}
	if err := protocol.DecodeStrict(wire, &inputs.journal, bootstrapstart.MaxIdentityRekeyJournalBytes); err != nil {
		return inputs, err
	}
	canonical, err := protocol.EncodeJSON(inputs.journal)
	if err != nil || inputs.journal.Version != 1 || !bytes.Equal(wire, canonical) {
		return inputs, bootstrapstart.ErrIdentityRekeyJournal
	}
	inputs.chain, err = read(bootstrapstart.MaterialGenerationsFile, bootstrapstart.MaxIdentityRekeyJournalBytes)
	if err != nil {
		return inputs, err
	}
	if len(inputs.journal.Values) < 3 || !bytes.Equal(inputs.chain, inputs.journal.Values[2]) {
		return inputs, errors.New("identity rekey input chain differs from its signed reset")
	}
	inputs.receipt, err = read("receipt.json", trust.MaxEnvelopeBytes)
	if err != nil {
		return inputs, err
	}
	inputs.delegation, err = read("delegation.json", trust.MaxEnvelopeBytes)
	if err != nil {
		return inputs, err
	}
	inputs.files = make(map[string][]byte, 8)
	names := append([]string{controllerConfigFilename}, bootstrap.ControllerConfigFileNames[:]...)
	names = append(names, identityRekeyLaunchFiles[:]...)
	for _, name := range names {
		inputs.files[name], err = read(name, bootstrap.MaxControllerConfigBytes)
		if err != nil {
			return inputs, err
		}
	}
	inputs.candidate = filepath.Join(directory, selfupdate.BinaryName)
	return inputs, nil
}

func openIdentityRekeyInputs(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, errors.New("identity rekey inputs require a clean absolute directory")
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		next, err := unix.Openat(dir, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if err != nil {
			return -1, err
		}
		dir = next
		var stat unix.Stat_t
		if unix.Fstat(dir, &stat) != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o022 != 0 {
			unix.Close(dir)
			return -1, errors.New("identity rekey inputs ancestor is not exclusively root-owned")
		}
	}
	var stat unix.Stat_t
	if unix.Fstat(dir, &stat) != nil || stat.Mode&0o7777 != 0o700 {
		unix.Close(dir)
		return -1, errors.New("identity rekey inputs directory requires mode 0700")
	}
	return dir, nil
}

func readIdentityRekeyRootKey(dir int) (ed25519.PrivateKey, error) {
	wire, err := readExactControllerFile(dir, "root-signing.key", 0, 0, 0o600, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("identity rekey signing key must be PKCS#8 Ed25519 PEM")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, trust.ErrUntrustedKey
	}
	return key, nil
}

func resumeIdentityRekeyInputs(ctx context.Context, dir int, inputs identityRekeyInputs, command string, output io.Writer) error {
	wire, err := protocol.EncodeJSON(inputs.journal)
	if err != nil {
		return err
	}
	_, evidence, err := bootstrapstart.ReadStagedIdentityRekeyEvidence(controllerSHA256(wire))
	if err != nil {
		return err
	}
	connection, err := readIdentityRekeyConnection(dir, evidence.Accepted(), inputs.journal.Replicas)
	if err != nil {
		return err
	}
	runtime, err := natscell.Start(ctx, connection.NATS)
	if err != nil {
		return err
	}
	defer runtime.Close()
	roots, err := bootstrapstart.LoadTrustInputs(evidence.Accepted())
	if err != nil {
		return err
	}
	envelope, err := evidence.ResetEnvelope()
	if err != nil {
		return err
	}
	if command == "authorize-resume" {
		clock := controllerClockCheck(controllerBrokerClockProbe())
		key, err := readIdentityRekeyRootKey(dir)
		if err != nil {
			return err
		}
		defer clear(key)
		if err := authorizeIdentityRekeyRecovery(ctx, runtime.JetStream(), envelope, roots.Roots.Current, evidence.ResetTarget(), key, clock); err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "identity rekey exact held transaction reauthorized operation=%s\n", evidence.Accepted().OperationID)
		return err
	}
	verified, roots, err := bootstrapstart.VerifyCommittedIdentityRekeyInstall(ctx, inputs.journal, runtime.JetStream(), time.Now().Round(0).UTC())
	if err != nil {
		return err
	}
	if err := selfupdatecli.VerifyCommittedIdentityRekeyCandidate(ctx, verified, roots, inputs.candidate, inputs.receipt, inputs.delegation, time.Now().UTC()); err != nil {
		return err
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	material, err := bootstrapstart.NewMaterialStore(nil, uid, gid)
	if err != nil {
		return err
	}
	if err := material.VerifyIdentityRekeyMaterialPredecessors(verified, roots, time.Now().UTC()); err != nil {
		return err
	}
	if err := selfupdatecli.InstallIdentityRekeyBinary(ctx, inputs.journal, inputs.candidate, inputs.receipt, inputs.delegation, time.Now().UTC(), runtime.JetStream()); err != nil {
		return err
	}
	return InstallIdentityRekey(ctx, inputs.journal, inputs.files, inputs.chain, runtime.JetStream())
}

func authorizeIdentityRekeyRecovery(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope, roots trust.Keyring,
	target authority.IdentityResetTarget, key ed25519.PrivateKey, clock func() error,
) error {
	if clock == nil {
		return errors.New("identity rekey recovery requires a healthy controller clock")
	}
	if err := clock(); err != nil {
		return err
	}
	recovery, err := authority.SignIdentityResetRecovery(ctx, js, envelope, roots, target, key, time.Now().Round(0).UTC())
	if err != nil {
		return err
	}
	if err := clock(); err != nil {
		return err
	}
	return authority.CommitIdentityResetRecovery(ctx, js, envelope, recovery, roots, target, time.Now().Round(0).UTC())
}
