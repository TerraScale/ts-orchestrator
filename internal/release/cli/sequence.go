package cli

import (
	"errors"
	"flag"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// signSequenceMigration is the offline-root review of the signer identity,
// canonical store and retained regional floors or explicit fresh-role purpose.
func (c command) signSequenceMigration(args []string) error {
	flags := flag.NewFlagSet("sign-sequence-migration", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidate := flags.String("candidate", "", "canonical migration JSON with reviewed regional floors or explicit fresh-role baseline")
	keyPath := flags.String("signing-key", "", "offline root Ed25519 private key")
	output := flags.String("out", "", "new signed migration envelope")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidate == "" || *keyPath == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("sign-sequence-migration requires --candidate, --signing-key and --out")
	}
	migration, err := readCanonicalPayload[release.SequenceMigration](*candidate)
	if err != nil {
		return err
	}
	if err := migration.Validate(); err != nil {
		return err
	}
	key, err := readOfflineRootPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	envelope, err := release.SignSequenceMigration(migration, time.Now().UTC(), key)
	if err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	return c.writeNew(*output, wire, 0644)
}

// allocateSequence reserves an order independently of content qualification;
// producers can then qualify the exact final manifest before artifact signing.
func (c command) allocateSequence(args []string) error {
	flags := flag.NewFlagSet("allocate-sequence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	identityPath := flags.String("identity", "", "canonical release content identity JSON")
	migrationPath := flags.String("migration", "", "root-signed migration authorizing this signer and allocator")
	rootPath := flags.String("root-key", "", "trusted root public key")
	keyPath := flags.String("signing-key", "", "release signer Ed25519 private key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *identityPath == "" || *migrationPath == "" || *rootPath == "" || *keyPath == "" || flags.NArg() != 0 {
		return errors.New("allocate-sequence requires --identity, --migration, --root-key and --signing-key")
	}
	identity, err := readCanonicalPayload[release.SequenceIdentity](*identityPath)
	if err != nil {
		return err
	}
	envelope, err := readEnvelope(*migrationPath)
	if err != nil {
		return err
	}
	public, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		return err
	}
	migration, err := release.VerifySequenceMigrationHistorical(envelope, roots, identity.Role, identity.Environment)
	if err != nil {
		return err
	}
	client, err := operatorObjectStorage(migration.Region)
	if err != nil {
		return err
	}
	location := release.SequenceLocation{Client: client, Namespace: migration.Namespace, Bucket: migration.Bucket}
	if err := location.ImportMigration(c.ctx, envelope, roots, identity.Role, identity.Environment, time.Now().UTC()); err != nil {
		return err
	}
	key, err := readDelegatedPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	sequence, err := location.Allocate(c.ctx, identity, roots, key)
	if err != nil {
		return err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return err
	}
	return c.printJSON(struct {
		Sequence        uint64 `json:"release_sequence"`
		MigrationSHA256 string `json:"sequence_migration_sha256"`
	}{sequence, fingerprint})
}
