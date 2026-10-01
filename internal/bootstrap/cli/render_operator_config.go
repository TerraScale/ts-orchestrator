package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const operatorInstallDirectory = "/var/lib/terrascale-operator"

func (c command) renderOperatorConfigAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("render-operator-config", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recordPath := flags.String("material-record", "", "reviewed public material inventory")
	recordSHA := flags.String("material-record-sha256", "", "reviewed public inventory SHA-256")
	materialDirectory := flags.String("material-directory", "", "complete owner-only offline material source")
	grantPath := flags.String("operator-grant", "", "reviewed canonical operator grant JSON")
	grantSHA := flags.String("operator-grant-sha256", "", "reviewed operator grant SHA-256")
	signingKeyPath := flags.String("operator-signing-key", "", "reviewed owner-only Ed25519 signing key PEM")
	signingKeySHA := flags.String("operator-signing-key-sha256", "", "reviewed signing key SHA-256")
	outputPath := flags.String("out", "", "new owner-only operator role JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || os.Geteuid() != 0 || *outputPath == "" || !filepath.IsAbs(*outputPath) ||
		*materialDirectory == "" || !filepath.IsAbs(*materialDirectory) {
		return errors.New("render-operator-config requires root, reviewed absolute material source, key, and new output")
	}
	recordWire, err := readPinnedControllerFile(*recordPath, *recordSHA, 1<<20)
	if err != nil {
		return err
	}
	var record bootstrapmaterial.Record
	if err := protocol.DecodeStrict(recordWire, &record, 1<<20); err != nil {
		return err
	}
	live, err := bootstrapmaterial.Load(*materialDirectory)
	if err != nil || !reflect.DeepEqual(live, record) {
		return errors.New("owner-only material source differs from reviewed public record")
	}
	if err := natscell.ValidateBrokerOperatorCredentials(filepath.Join(*materialDirectory, "operator.creds"),
		record.Config.Cell); err != nil {
		return err
	}
	grantWire, err := readPinnedControllerFile(*grantPath, *grantSHA, 4<<10)
	if err != nil {
		return err
	}
	var grant app.TrustedSignerConfig
	if err := protocol.DecodeStrict(grantWire, &grant, 4<<10); err != nil {
		return err
	}
	canonicalGrant, err := protocol.EncodeJSON(grant)
	if err != nil || !slices.Equal(canonicalGrant, grantWire) {
		return errors.New("operator grant must use canonical app JSON")
	}
	if _, err := readPinnedControllerFile(*signingKeyPath, *signingKeySHA, maxKeyFileBytes); err != nil {
		return err
	}
	private, err := readRootPrivateKey(*signingKeyPath)
	if err != nil {
		return err
	}
	defer clear(private)
	public, err := base64.StdEncoding.Strict().DecodeString(grant.PublicKey)
	if err != nil || !slices.Equal(public, private.Public().(ed25519.PublicKey)) {
		return errors.New("reviewed operator signing key differs from grant public key")
	}
	cfg, err := operatorConfigFromRecord(record, grant, now)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(cfg)
	if err != nil || len(wire) == 0 || len(wire) > 16<<10 {
		return errors.New("rendered operator config exceeds size bound")
	}
	if err := c.writeNew(*outputPath, wire, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "rendered operator config actor=%s sha256=%s\n", grant.Actor, controllerConfigDigest(wire))
	return nil
}

func operatorConfigFromRecord(record bootstrapmaterial.Record, grant app.TrustedSignerConfig,
	now time.Time,
) (app.Config, error) {
	prefix, prefixErr := netip.ParsePrefix(record.Config.SubnetCIDR)
	controllerPublic, controllerErr := base64.StdEncoding.Strict().DecodeString(record.Public.ControllerResponsePublicKey)
	ticketPublic, ticketErr := base64.StdEncoding.Strict().DecodeString(record.Public.TicketSignerPublicKey)
	if record.SchemaVersion != 1 || record.Config.Validate() != nil || len(record.Config.Slots) != 3 ||
		record.Config.Environment != "canary" && record.Config.Environment != "production" ||
		record.Config.DeploymentID == "" || !now.Before(record.ExpiresAt) ||
		prefixErr != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix ||
		controllerErr != nil || len(controllerPublic) != ed25519.PublicKeySize ||
		ticketErr != nil || len(ticketPublic) != ed25519.PublicKeySize ||
		grant.Actor == "" || !slices.Contains(grant.Environments, record.Config.Environment) {
		return app.Config{}, errors.New("reviewed operator material or grant does not match the deployment")
	}
	if err := app.ValidateTrustedSignerGrant(grant); err != nil {
		return app.Config{}, fmt.Errorf("reviewed operator grant is invalid: %w", err)
	}
	required := []string{"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem", "ca.pem", "ticket.pub"}
	for _, name := range required {
		if !slices.ContainsFunc(record.Files, func(file bootstrapmaterial.File) bool { return file.Name == name }) {
			return app.Config{}, fmt.Errorf("reviewed operator material lacks %s", name)
		}
	}
	urls := make([]string, 0, len(record.Config.Slots))
	for index, slot := range record.Config.Slots {
		address, err := netip.ParseAddr(slot.PrivateIP)
		if slot.Name != fmt.Sprintf("controller-%c", 'a'+index) || err != nil || !address.Is4() ||
			!prefix.Contains(address) || address.String() != slot.PrivateIP {
			return app.Config{}, errors.New("reviewed operator controller endpoint is invalid")
		}
		urls = append(urls, "tls://"+slot.PrivateIP+":4222")
	}
	path := func(name string) string { return filepath.Join(operatorInstallDirectory, name) }
	return app.Config{
		NATS: natscell.Config{Cell: record.Config.Cell, Instance: "operator-" + grant.Actor,
			Replicas: len(record.Config.Slots), ClientRole: "operator", URL: strings.Join(urls, ","),
			CredentialsFile: path("operator.creds"), TLS: natscell.TLSFiles{CAFile: path("ca.pem"),
				CertFile: path("operator-tls-cert.pem"), KeyFile: path("operator-tls-key.pem")}},
		Controller: app.ControllerConfig{TrustedSigners: []app.TrustedSignerConfig{grant}},
		Operator: app.OperatorConfig{Actor: grant.Actor, SigningKeyFile: path("operator-signing.key"),
			ControllerPublicKey:       record.Public.ControllerResponsePublicKey,
			BrokerTicketPublicKeyFile: path("ticket.pub")},
	}, nil
}
