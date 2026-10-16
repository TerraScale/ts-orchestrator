package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	hostInstallRoot        = "/var/lib/terrascale-orchestrator-host/install"
	hostStateRoot          = "/var/lib/terrascale-orchestrator-host/state"
	hostManagedRuntimeRoot = "/srv/ts-managed"
	hostWorkloadUID        = 2000
	hostWorkloadGID        = 2000
)

// renderHostEnrollmentPublicAt emits the exact public enrollment inputs baked
// into a regional host image. The live, owner-only material source is the source
// of the controller CA and authority keys, and the output cannot overwrite a
// previously reviewed bundle.
func (c command) renderHostEnrollmentPublicAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("render-host-enrollment-public", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recordPath := flags.String("material-record", "", "reviewed public material inventory")
	recordSHA := flags.String("material-record-sha256", "", "reviewed inventory SHA-256")
	materialDirectory := flags.String("material-directory", "", "complete owner-only material source")
	outputPath := flags.String("out", "", "new public host enrollment bundle JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || os.Geteuid() != 0 || !filepath.IsAbs(*materialDirectory) ||
		!filepath.IsAbs(*outputPath) || pathInside(*materialDirectory, *outputPath) {
		return errors.New("render-host-enrollment-public requires root, reviewed absolute material source, and new output")
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
	if err := bootstrapmaterial.ValidateLive(*materialDirectory, live); err != nil {
		return err
	}
	caWire, err := c.readBoundedRegular(filepath.Join(*materialDirectory, "ca.pem"), 64<<10)
	if err != nil {
		return err
	}
	bundle, err := hostEnrollmentPublicFromRecord(live, caWire, now)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(bundle)
	if err != nil || len(wire) == 0 || len(wire) > hostenroll.MaxPublicBundleBytes {
		return errors.New("host enrollment public bundle exceeds size bound")
	}
	if _, err := hostenroll.ParsePublicBundle(wire); err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "rendered host enrollment public bundle sha256=%s output=%s\n", controllerConfigDigest(wire), *outputPath)
	return nil
}

func hostEnrollmentPublicFromRecord(record bootstrapmaterial.Record, caWire []byte, now time.Time) (hostenroll.PublicBundle, error) {
	if record.SchemaVersion != 1 || record.Config.Validate() != nil || len(record.Config.Slots) != 3 ||
		record.ExpiresAt.Sub(record.IssuedAt) != time.Duration(record.Config.ValidityHours)*time.Hour ||
		now.IsZero() || now.Add(24*time.Hour).After(record.ExpiresAt) {
		return hostenroll.PublicBundle{}, errors.New("reviewed regional material does not have a valid identity or image build window")
	}
	var caDigest string
	for _, file := range record.Files {
		if file.Name == "ca.pem" {
			if caDigest != "" || file.Purpose != bootstrap.SecretRegionalShared || file.Slot != "" || file.MaxBytes != int64(len(caWire)) {
				return hostenroll.PublicBundle{}, errors.New("reviewed regional CA file is invalid")
			}
			caDigest = file.SHA256
		}
	}
	if caDigest == "" || !matchesSHA256(caWire, caDigest) {
		return hostenroll.PublicBundle{}, errors.New("regional CA differs from reviewed material")
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: record.Config.Cell,
		Region: strings.ToUpper(record.Config.Cell), Environment: record.Config.Environment,
		CAPEM: string(caWire), ControllerResponsePublicKey: record.Public.ControllerResponsePublicKey,
		CellAccountNKey: record.Public.CellAccountNKey,
		InstallRoot:     hostInstallRoot, StateRoot: hostStateRoot, ManagedRuntimeRoot: hostManagedRuntimeRoot,
		WorkloadUID: hostWorkloadUID, WorkloadGID: hostWorkloadGID}
	for index, slot := range record.Config.Slots {
		if slot.Name != fmt.Sprintf("controller-%c", 'a'+index) {
			return hostenroll.PublicBundle{}, errors.New("reviewed controller slots are not in canonical order")
		}
		bundle.ControllerEndpoints = append(bundle.ControllerEndpoints, slot.PrivateIP+":8443")
		bundle.NATSURLs = append(bundle.NATSURLs, "tls://"+slot.PrivateIP+":4222")
	}
	if err := bundle.Validate(); err != nil {
		return hostenroll.PublicBundle{}, err
	}
	return bundle, nil
}
