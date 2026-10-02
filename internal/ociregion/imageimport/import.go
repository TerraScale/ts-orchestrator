// Package imageimport imports qualified ARM64 images and enforces their A1 launch contract.
package imageimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const A1Shape = "VM.Standard.A1.Flex"

func Capabilities() map[string]any {
	result := map[string]any{}
	for key, value := range map[string]string{"Compute.Firmware": "UEFI_64", "Compute.LaunchMode": "PARAVIRTUALIZED", "Network.AttachmentType": "PARAVIRTUALIZED", "Storage.BootVolumeType": "PARAVIRTUALIZED", "Storage.RemoteDataVolumeType": "PARAVIRTUALIZED"} {
		result[key] = map[string]any{"descriptor-type": "enumstring", "source": "IMAGE", "values": []any{value}, "default-value": value}
	}
	for _, key := range []string{"Storage.ConsistentVolumeNaming", "Storage.ParaVirtualization.EncryptionInTransit"} {
		result[key] = map[string]any{"descriptor-type": "boolean", "source": "IMAGE", "default-value": true}
	}
	return result
}

type Options struct{ QCOW2, SHA256, Region, Compartment, Namespace, Bucket, DisplayName, Out string }

// Importer isolates external effects while preserving native admission and lifecycle checks.
type Importer struct {
	Client                            command.Client
	Pause                             func(context.Context, time.Duration) error
	PollInterval, AvailabilityTimeout time.Duration
}

func Run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("oci-region import-image", flag.ContinueOnError)
	fs.SetOutput(out)
	var o Options
	fs.StringVar(&o.QCOW2, "qcow2", "", "qualified QCOW2 file")
	fs.StringVar(&o.SHA256, "sha256", "", "expected QCOW2 SHA-256")
	fs.StringVar(&o.Region, "region", catalog.OCIRegion(catalog.Bootstrap), "OCI region")
	fs.StringVar(&o.Compartment, "compartment-id", "", "image compartment")
	fs.StringVar(&o.Namespace, "namespace", "", "object namespace")
	fs.StringVar(&o.Bucket, "bucket", "", "object bucket")
	fs.StringVar(&o.DisplayName, "display-name", "", "image display name")
	fs.StringVar(&o.Out, "out", "", "output record")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	_, err := (Importer{Client: command.CLI{Region: o.Region}}).Import(ctx, o, out)
	return err
}

func (i Importer) data(ctx context.Context, args ...string) (map[string]any, error) {
	r, err := i.Client.Call(ctx, args...)
	if err != nil {
		return nil, err
	}
	return command.Object(r["data"])
}
func (i Importer) rows(ctx context.Context, args ...string) ([]map[string]any, error) {
	r, err := i.Client.Call(ctx, args...)
	if err != nil {
		return nil, err
	}
	return command.Rows(r["data"])
}

func (i Importer) FindImage(ctx context.Context, compartment, name string) (map[string]any, error) {
	rows, err := i.rows(ctx, "compute", "image", "list", "--compartment-id", compartment, "--display-name", name, "--all")
	if err != nil {
		return nil, err
	}
	var live map[string]any
	for _, row := range rows {
		if slices.Contains([]string{"IMPORTING", "PROVISIONING", "AVAILABLE"}, fmt.Sprint(row["lifecycle-state"])) {
			if live != nil {
				return nil, fmt.Errorf("more than one live image is named %s", name)
			}
			live = row
		}
	}
	return live, nil
}

func (i Importer) WaitAvailable(ctx context.Context, id string) (map[string]any, error) {
	timeout := i.AvailabilityTimeout
	if timeout <= 0 {
		timeout = 45 * time.Minute
	}
	interval := i.PollInterval
	if interval <= 0 {
		interval = 20 * time.Second
	}
	pause := i.Pause
	if pause == nil {
		pause = command.Pause
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		row, err := i.data(ctx, "compute", "image", "get", "--image-id", id)
		if err != nil {
			return nil, err
		}
		switch row["lifecycle-state"] {
		case "AVAILABLE":
			return row, nil
		case "IMPORTING", "PROVISIONING":
		default:
			return nil, fmt.Errorf("image %s entered %v", id, row["lifecycle-state"])
		}
		if err := pause(ctx, interval); err != nil {
			return nil, fmt.Errorf("image %s did not become AVAILABLE: %w", id, err)
		}
	}
}

func (i Importer) EnsureCapabilities(ctx context.Context, compartment, id, name string) (map[string]any, error) {
	rows, err := i.rows(ctx, "compute", "image-capability-schema", "list", "--compartment-id", compartment, "--image-id", id, "--all")
	if err != nil {
		return nil, err
	}
	var schema map[string]any
	if len(rows) > 0 {
		schemaID, err := command.ID(rows[0])
		if err != nil {
			return nil, err
		}
		schema, err = i.data(ctx, "compute", "image-capability-schema", "get", "--image-capability-schema-id", schemaID)
		if err != nil {
			return nil, err
		}
	} else {
		globals, err := i.rows(ctx, "compute", "global-image-capability-schema", "list", "--all")
		if err != nil {
			return nil, err
		}
		if len(globals) == 0 {
			return nil, fmt.Errorf("OCI returned no global capability schema")
		}
		version, ok := globals[0]["current-version-name"].(string)
		if !ok || version == "" {
			return nil, fmt.Errorf("global schema has no version")
		}
		runes := []rune(name)
		if len(runes) > 255 {
			name = string(runes[:255])
		}
		schema, err = i.data(ctx, "compute", "image-capability-schema", "create", "--compartment-id", compartment, "--image-id", id, "--display-name", name, "--global-image-capability-schema-version-name", version, "--schema-data", command.JSON(Capabilities()))
		if err != nil {
			return nil, err
		}
	}
	data, err := command.Object(schema["schema-data"])
	if err != nil {
		return nil, err
	}
	for key, value := range Capabilities() {
		expected := value.(map[string]any)
		actual, _ := data[key].(map[string]any)
		if !reflect.DeepEqual(actual["default-value"], expected["default-value"]) || !reflect.DeepEqual(actual["values"], expected["values"]) {
			return nil, fmt.Errorf("image capability %s differs from the launch contract", key)
		}
	}
	return schema, nil
}

func a1Constraints(row map[string]any) bool {
	// OCI JSON numbers are float64; native command fakes also pass through this boundary.
	ocpu, _ := row["ocpu-constraints"].(map[string]any)
	memory, _ := row["memory-constraints"].(map[string]any)
	return command.JSON(ocpu) == `{"max":4,"min":1}` && command.JSON(memory) == `{"max-in-gbs":24,"min-in-gbs":6}`
}

func (i Importer) EnsureShapes(ctx context.Context, id string) ([]map[string]any, error) {
	rows, err := i.rows(ctx, "compute", "image-shape-compatibility-entry", "list", "--image-id", id, "--all")
	if err != nil {
		return nil, err
	}
	var a1 map[string]any
	for _, r := range rows {
		if r["shape"] == A1Shape {
			a1 = r
			break
		}
	}
	if a1 == nil || !a1Constraints(a1) {
		_, err = i.Client.Call(ctx, "compute", "image-shape-compatibility-entry", "add", "--image-id", id, "--shape-name", A1Shape, "--ocpu-constraints", `{"min":1,"max":4}`, "--memory-constraints", `{"minInGBs":6,"maxInGBs":24}`, "--force")
		if err != nil {
			return nil, err
		}
	}
	for _, r := range rows {
		shape, ok := r["shape"].(string)
		if !ok {
			return nil, fmt.Errorf("shape compatibility row lacks shape")
		}
		if shape != A1Shape && !strings.HasSuffix(shape, ".Generic") {
			if _, err := i.Client.Call(ctx, "compute", "image-shape-compatibility-entry", "remove", "--image-id", id, "--shape-name", shape, "--force"); err != nil {
				return nil, err
			}
		}
	}
	rows, err = i.rows(ctx, "compute", "image-shape-compatibility-entry", "list", "--image-id", id, "--all")
	if err != nil {
		return nil, err
	}
	found := false
	for _, r := range rows {
		shape, ok := r["shape"].(string)
		if !ok {
			return nil, fmt.Errorf("shape compatibility row lacks shape")
		}
		if shape == A1Shape {
			found = true
			if !a1Constraints(r) {
				return nil, fmt.Errorf("image A1 constraints differ from the launch contract")
			}
		}
		if shape != A1Shape && !strings.HasSuffix(shape, ".Generic") {
			return nil, fmt.Errorf("image shape compatibility is not A1-only")
		}
	}
	if !found {
		return nil, fmt.Errorf("image shape compatibility is not A1-only")
	}
	return rows, nil
}

func (i Importer) Import(ctx context.Context, o Options, out io.Writer) (map[string]any, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	for key, value := range map[string]string{"qcow2": o.QCOW2, "sha256": o.SHA256, "compartment-id": o.Compartment, "namespace": o.Namespace, "bucket": o.Bucket, "display-name": o.DisplayName, "out": o.Out} {
		if value == "" {
			return nil, fmt.Errorf("--%s is required", key)
		}
	}
	f, err := os.Open(o.QCOW2)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
		return nil, fmt.Errorf("QCOW2 bytes differ from the expected SHA-256")
	}
	objectName := "images/" + o.SHA256 + ".qcow2"
	image, err := i.FindImage(ctx, o.Compartment, o.DisplayName)
	if err != nil {
		return nil, err
	}
	if image == nil {
		if err := i.Client.Head(ctx, "os", "object", "head", "--namespace-name", o.Namespace, "--bucket-name", o.Bucket, "--name", objectName); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if _, err := fmt.Fprintf(out, "uploading %s\n", objectName); err != nil {
				return nil, err
			}
			if _, err := i.Client.Call(ctx, "os", "object", "put", "--namespace-name", o.Namespace, "--bucket-name", o.Bucket, "--name", objectName, "--file", o.QCOW2, "--metadata", command.JSON(map[string]string{"sha256": o.SHA256}), "--no-overwrite", "--parallel-upload-count", "8"); err != nil {
				return nil, err
			}
		}
		if _, err := fmt.Fprintln(out, "importing image"); err != nil {
			return nil, err
		}
		image, err = i.data(ctx, "compute", "image", "import", "from-object", "--compartment-id", o.Compartment, "--namespace", o.Namespace, "--bucket-name", o.Bucket, "--name", objectName, "--display-name", o.DisplayName, "--source-image-type", "QCOW2", "--launch-mode", "PARAVIRTUALIZED", "--operating-system", "Custom", "--operating-system-version", "Custom")
		if err != nil {
			return nil, err
		}
	}
	id, err := command.ID(image)
	if err != nil {
		return nil, err
	}
	image, err = i.WaitAvailable(ctx, id)
	if err != nil {
		return nil, err
	}
	schema, err := i.EnsureCapabilities(ctx, o.Compartment, id, o.DisplayName)
	if err != nil {
		return nil, err
	}
	schemaID, err := command.ID(schema)
	if err != nil {
		return nil, err
	}
	shapes, err := i.EnsureShapes(ctx, id)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(shapes))
	for _, r := range shapes {
		names = append(names, r["shape"].(string))
	}
	slices.Sort(names)
	record := map[string]any{"schema": "terrascale.oci.image-import.v1", "image_id": id, "display_name": o.DisplayName, "qcow2_sha256": o.SHA256, "object": o.Namespace + "/" + o.Bucket + "/" + objectName, "billable_size_gb": image["billable-size-in-gbs"], "capability_schema_id": schemaID, "shapes": names}
	b, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(o.Out, append(b, '\n'), 0644); err != nil {
		return nil, err
	}
	_, err = fmt.Fprintln(out, string(b))
	return record, err
}
