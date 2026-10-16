// Package imageimport imports qualified ARM64 images and enforces their A1 launch contract.
//
// The importer runs inside the single binary through the OCI Go SDK: the
// QCOW2 is uploaded with the Object Storage upload manager, imported with
// Compute CreateImage, and the import work request is polled with backoff.
// One invocation may import the same verified bytes into several catalog
// regions in parallel.
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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const A1Shape = "VM.Standard.A1.Flex"

// Capability is one image capability descriptor of the A1 launch contract.
type Capability struct {
	// Boolean selects a boolean descriptor; otherwise the descriptor is an
	// enumstring with Values and Default.
	Boolean     bool
	BoolDefault bool
	Values      []string
	Default     string
}

func (c Capability) equal(other Capability) bool {
	return c.Boolean == other.Boolean && c.BoolDefault == other.BoolDefault &&
		c.Default == other.Default && slices.Equal(c.Values, other.Values)
}

// Capabilities is the image capability schema every TerraScale image must carry.
func Capabilities() map[string]Capability {
	result := map[string]Capability{}
	for key, value := range map[string]string{"Compute.Firmware": "UEFI_64", "Compute.LaunchMode": "PARAVIRTUALIZED", "Network.AttachmentType": "PARAVIRTUALIZED", "Storage.BootVolumeType": "PARAVIRTUALIZED", "Storage.RemoteDataVolumeType": "PARAVIRTUALIZED"} {
		result[key] = Capability{Values: []string{value}, Default: value}
	}
	for _, key := range []string{"Storage.ConsistentVolumeNaming", "Storage.ParaVirtualization.EncryptionInTransit"} {
		result[key] = Capability{Boolean: true, BoolDefault: true}
	}
	return result
}

// Range is an inclusive integer constraint.
type Range struct{ Min, Max int }

// ShapeEntry is one image shape compatibility entry.
type ShapeEntry struct {
	Shape    string
	OCPU     *Range
	MemoryGB *Range
}

// A node may run with as little as 4 GB: gru-1's nodes run the colocated
// controller, TerraBase member and ts-auth in 1 OCPU / 4 GB (TS-627).
var (
	a1OCPU   = Range{Min: 1, Max: 4}
	a1Memory = Range{Min: 4, Max: 24}
)

func a1Constraints(entry ShapeEntry) bool {
	return entry.OCPU != nil && *entry.OCPU == a1OCPU && entry.MemoryGB != nil && *entry.MemoryGB == a1Memory
}

// Image is the normalized Compute image state the importer reads.
type Image struct {
	ID             string
	LifecycleState string
	BillableSizeGB *int64
	// SHA256 is the imported QCOW2 digest from the image's SHA256Tag.
	SHA256 string
}

// SHA256Tag is the freeform tag that names an imported image's QCOW2
// SHA-256, so a later import under the same display name can tell its own
// image from another one.
const SHA256Tag = "terrascale-qcow2-sha256"

// CapabilitySchema is a created or existing image capability schema.
type CapabilitySchema struct {
	ID   string
	Data map[string]Capability
}

// WorkRequestStatus is a normalized core work request status.
type WorkRequestStatus string

const (
	WorkRequestAccepted   WorkRequestStatus = "ACCEPTED"
	WorkRequestInProgress WorkRequestStatus = "IN_PROGRESS"
	WorkRequestSucceeded  WorkRequestStatus = "SUCCEEDED"
	WorkRequestFailed     WorkRequestStatus = "FAILED"
	WorkRequestCanceling  WorkRequestStatus = "CANCELING"
	WorkRequestCanceled   WorkRequestStatus = "CANCELED"
)

// ImportRequest creates one image from an Object Storage QCOW2.
type ImportRequest struct {
	Compartment, Namespace, Bucket, Object, DisplayName, SHA256 string
}

// UploadRequest uploads one local file without overwriting an existing object.
type UploadRequest struct {
	Namespace, Bucket, Object, Path string
	// SHA256 is the expected digest of the file. The client hashes exactly
	// the bytes it sends and never commits an object whose bytes differ.
	SHA256      string
	Metadata    map[string]string
	PartSize    int64
	Parallelism int
}

// API is the narrow, typed OCI seam for one region. Fakes exercise admission,
// resume, and lifecycle behavior without cloud access.
type API interface {
	ListImages(ctx context.Context, compartment, displayName string) ([]Image, error)
	GetImage(ctx context.Context, id string) (Image, error)
	// HeadObject reports whether the object exists and returns its metadata.
	HeadObject(ctx context.Context, namespace, bucket, object string) (bool, map[string]string, error)
	UploadObject(ctx context.Context, request UploadRequest) error
	// ImportImage returns the new image and its work request ID.
	ImportImage(ctx context.Context, request ImportRequest) (Image, string, error)
	GetWorkRequest(ctx context.Context, id string) (WorkRequestStatus, error)
	ListCapabilitySchemas(ctx context.Context, compartment, imageID string) ([]string, error)
	GetCapabilitySchema(ctx context.Context, id string) (CapabilitySchema, error)
	GlobalCapabilitySchemaVersion(ctx context.Context) (string, error)
	CreateCapabilitySchema(ctx context.Context, compartment, imageID, displayName, version string, data map[string]Capability) (CapabilitySchema, error)
	ListShapes(ctx context.Context, imageID string) ([]ShapeEntry, error)
	AddShape(ctx context.Context, imageID string, entry ShapeEntry) error
	RemoveShape(ctx context.Context, imageID, shape string) error
}

// Options are the operator inputs. Regions lists catalog OCI regions; the
// QCOW2 is uploaded to the same bucket name in each region and imported there.
type Options struct {
	QCOW2, SHA256, Compartment, Namespace, Bucket, DisplayName, Out string
	Regions                                                         []string
	PartSizeMiB, UploadParallelism                                  int
}

const (
	defaultPartSizeMiB       = 128
	defaultUploadParallelism = 8
	maxPartSizeMiB           = 5 << 10
	maxUploadParallelism     = 64
)

// Importer imports into one region through API. Pause and the poll bounds are
// injectable so lifecycle tests run without sleeping.
type Importer struct {
	Client API
	Pause  func(context.Context, time.Duration) error
	// PollInterval is the first work request poll delay; it doubles up to
	// MaxPollInterval.
	PollInterval, MaxPollInterval, AvailabilityTimeout time.Duration
}

type regionList []string

func (r *regionList) String() string { return strings.Join(*r, ",") }
func (r *regionList) Set(value string) error {
	for part := range strings.SplitSeq(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*r = append(*r, part)
		}
	}
	return nil
}

// ClientFactory builds the API for one OCI region.
type ClientFactory func(region string) (API, error)

func Run(ctx context.Context, args []string, out io.Writer) error {
	return RunWith(ctx, args, out, NewSDKClient)
}

// RunWith parses the operator command and imports into every requested
// region through clients built by factory.
func RunWith(ctx context.Context, args []string, out io.Writer, factory ClientFactory) error {
	return RunImporters(ctx, args, out, func(region string) (Importer, error) {
		client, err := factory(region)
		if err != nil {
			return Importer{}, err
		}
		return Importer{Client: client}, nil
	})
}

// ImporterFactory builds the Importer for one OCI region, including its
// client and poll bounds.
type ImporterFactory func(region string) (Importer, error)

// RunImporters parses the operator command and imports into every requested
// region through the importers it builds.
func RunImporters(ctx context.Context, args []string, out io.Writer, importers ImporterFactory) error {
	fs := flag.NewFlagSet("oci-region import-image", flag.ContinueOnError)
	fs.SetOutput(out)
	var o Options
	var regions regionList
	fs.StringVar(&o.QCOW2, "qcow2", "", "qualified QCOW2 file")
	fs.StringVar(&o.SHA256, "sha256", "", "expected QCOW2 SHA-256")
	fs.Var(&regions, "region", "catalog OCI region; repeatable or comma-separated (default "+catalog.OCIRegion(catalog.Bootstrap)+")")
	fs.StringVar(&o.Compartment, "compartment-id", "", "image compartment")
	fs.StringVar(&o.Namespace, "namespace", "", "object namespace")
	fs.StringVar(&o.Bucket, "bucket", "", "object bucket (same name in every region)")
	fs.StringVar(&o.DisplayName, "display-name", "", "image display name")
	fs.StringVar(&o.Out, "out", "", "output record")
	fs.IntVar(&o.PartSizeMiB, "part-size-mib", defaultPartSizeMiB, "multipart upload part size in MiB")
	fs.IntVar(&o.UploadParallelism, "upload-parallelism", defaultUploadParallelism, "concurrent multipart upload parts")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	o.Regions = regions
	if len(o.Regions) == 0 {
		o.Regions = []string{catalog.OCIRegion(catalog.Bootstrap)}
	}
	_, err := ImportRegions(ctx, o, out, importers)
	return err
}

func (i Importer) pause(ctx context.Context, delay time.Duration) error {
	if i.Pause != nil {
		return i.Pause(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var liveImageStates = []string{"IMPORTING", "PROVISIONING", "AVAILABLE"}

func (i Importer) FindImage(ctx context.Context, compartment, name string) (*Image, error) {
	images, err := i.Client.ListImages(ctx, compartment, name)
	if err != nil {
		return nil, err
	}
	var live *Image
	for _, image := range images {
		if slices.Contains(liveImageStates, image.LifecycleState) {
			if live != nil {
				return nil, fmt.Errorf("more than one live image is named %s", name)
			}
			live = &image
		}
	}
	return live, nil
}

// WaitAvailable waits for the import work request, when known, and then for
// the image to report AVAILABLE. Polls start at PollInterval (5s) and double
// up to MaxPollInterval so short imports finish quickly without hammering OCI
// during long ones.
func (i Importer) WaitAvailable(ctx context.Context, id, workRequest string) (Image, error) {
	timeout := i.AvailabilityTimeout
	if timeout <= 0 {
		timeout = 45 * time.Minute
	}
	interval := i.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ceiling := i.MaxPollInterval
	if ceiling <= 0 {
		ceiling = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if workRequest != "" {
			status, err := i.Client.GetWorkRequest(ctx, workRequest)
			if err != nil {
				return Image{}, err
			}
			switch status {
			case WorkRequestSucceeded:
				workRequest = ""
			case WorkRequestAccepted, WorkRequestInProgress:
			default:
				return Image{}, fmt.Errorf("image %s import work request %s ended %s", id, workRequest, status)
			}
		}
		if workRequest == "" {
			image, err := i.Client.GetImage(ctx, id)
			if err != nil {
				return Image{}, err
			}
			switch image.LifecycleState {
			case "AVAILABLE":
				return image, nil
			case "IMPORTING", "PROVISIONING":
			default:
				return Image{}, fmt.Errorf("image %s entered %v", id, image.LifecycleState)
			}
		}
		if err := i.pause(ctx, interval); err != nil {
			return Image{}, fmt.Errorf("image %s did not become AVAILABLE: %w", id, err)
		}
		interval = min(interval*2, ceiling)
	}
}

func (i Importer) EnsureCapabilities(ctx context.Context, compartment, id, name string) (CapabilitySchema, error) {
	ids, err := i.Client.ListCapabilitySchemas(ctx, compartment, id)
	if err != nil {
		return CapabilitySchema{}, err
	}
	var schema CapabilitySchema
	if len(ids) > 0 {
		if ids[0] == "" {
			return CapabilitySchema{}, errors.New("OCI capability schema has no id")
		}
		schema, err = i.Client.GetCapabilitySchema(ctx, ids[0])
		if err != nil {
			return CapabilitySchema{}, err
		}
	} else {
		version, err := i.Client.GlobalCapabilitySchemaVersion(ctx)
		if err != nil {
			return CapabilitySchema{}, err
		}
		if version == "" {
			return CapabilitySchema{}, errors.New("global schema has no version")
		}
		runes := []rune(name)
		if len(runes) > 255 {
			name = string(runes[:255])
		}
		schema, err = i.Client.CreateCapabilitySchema(ctx, compartment, id, name, version, Capabilities())
		if err != nil {
			return CapabilitySchema{}, err
		}
	}
	if schema.ID == "" {
		return CapabilitySchema{}, errors.New("OCI capability schema has no id")
	}
	for key, expected := range Capabilities() {
		actual, ok := schema.Data[key]
		if !ok || !actual.equal(expected) {
			return CapabilitySchema{}, fmt.Errorf("image capability %s differs from the launch contract", key)
		}
	}
	return schema, nil
}

func (i Importer) EnsureShapes(ctx context.Context, id string) ([]ShapeEntry, error) {
	entries, err := i.Client.ListShapes(ctx, id)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(entries, func(entry ShapeEntry) bool { return entry.Shape == A1Shape })
	if index < 0 || !a1Constraints(entries[index]) {
		if err := i.Client.AddShape(ctx, id, ShapeEntry{Shape: A1Shape, OCPU: new(a1OCPU), MemoryGB: new(a1Memory)}); err != nil {
			return nil, err
		}
	}
	for _, entry := range entries {
		if entry.Shape == "" {
			return nil, errors.New("shape compatibility row lacks shape")
		}
		if entry.Shape != A1Shape && !strings.HasSuffix(entry.Shape, ".Generic") {
			if err := i.Client.RemoveShape(ctx, id, entry.Shape); err != nil {
				return nil, err
			}
		}
	}
	entries, err = i.Client.ListShapes(ctx, id)
	if err != nil {
		return nil, err
	}
	found := false
	for _, entry := range entries {
		if entry.Shape == "" {
			return nil, errors.New("shape compatibility row lacks shape")
		}
		if entry.Shape == A1Shape {
			found = true
			if !a1Constraints(entry) {
				return nil, errors.New("image A1 constraints differ from the launch contract")
			}
		}
		if entry.Shape != A1Shape && !strings.HasSuffix(entry.Shape, ".Generic") {
			return nil, errors.New("image shape compatibility is not A1-only")
		}
	}
	if !found {
		return nil, errors.New("image shape compatibility is not A1-only")
	}
	return entries, nil
}

func (o Options) validate() error {
	for key, value := range map[string]string{"qcow2": o.QCOW2, "sha256": o.SHA256, "compartment-id": o.Compartment, "namespace": o.Namespace, "bucket": o.Bucket, "display-name": o.DisplayName, "out": o.Out} {
		if value == "" {
			return fmt.Errorf("--%s is required", key)
		}
	}
	if len(o.Regions) == 0 {
		return errors.New("--region is required")
	}
	seen := map[string]bool{}
	for _, region := range o.Regions {
		if !catalog.IsOCIRegion(region) {
			return fmt.Errorf("--region %q is not a catalog OCI region", region)
		}
		if seen[region] {
			return fmt.Errorf("--region %q is repeated", region)
		}
		seen[region] = true
	}
	if o.PartSizeMiB < 0 || o.PartSizeMiB > maxPartSizeMiB || o.UploadParallelism < 0 || o.UploadParallelism > maxUploadParallelism {
		return errors.New("upload part size or parallelism is out of bounds")
	}
	return nil
}

func verifyDigest(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("QCOW2 bytes differ from the expected SHA-256")
	}
	return nil
}

// ImportRegions verifies the QCOW2 digest once, before any cloud effect, then
// imports into every region concurrently. A single region writes the
// terrascale.oci.image-import.v1 record unchanged; several regions write a
// terrascale.oci.image-import-set.v1 record keyed by region.
func ImportRegions(ctx context.Context, o Options, out io.Writer, importer func(region string) (Importer, error)) (map[string]any, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := o.validate(); err != nil {
		return nil, err
	}
	if err := verifyDigest(o.QCOW2, o.SHA256); err != nil {
		return nil, err
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		records = make(map[string]map[string]any, len(o.Regions))
		errs    = make([]error, len(o.Regions))
	)
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprintf(out, format, args...)
	}
	for index, region := range o.Regions {
		wg.Go(func() {
			regional, err := importer(region)
			if err != nil {
				errs[index] = fmt.Errorf("%s: %w", region, err)
				return
			}
			record, err := regional.importVerified(ctx, o, func(format string, args ...any) {
				if len(o.Regions) > 1 {
					format = region + ": " + format
				}
				logf(format, args...)
			})
			if err != nil {
				errs[index] = fmt.Errorf("%s: %w", region, err)
				return
			}
			mu.Lock()
			records[region] = record
			mu.Unlock()
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	result := records[o.Regions[0]]
	if len(o.Regions) > 1 {
		regions := make(map[string]any, len(records))
		for region, record := range records {
			regions[region] = record
		}
		result = map[string]any{"schema": "terrascale.oci.image-import-set.v1", "qcow2_sha256": o.SHA256, "display_name": o.DisplayName, "regions": regions}
	}
	b, err := json.Marshal(result, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(o.Out, append(b, '\n'), 0644); err != nil {
		return nil, err
	}
	_, err = fmt.Fprintln(out, string(b))
	return result, err
}

// Import imports into this importer's single region.
func (i Importer) Import(ctx context.Context, o Options, out io.Writer) (map[string]any, error) {
	if len(o.Regions) == 0 {
		o.Regions = []string{catalog.OCIRegion(catalog.Bootstrap)}
	}
	if len(o.Regions) != 1 {
		return nil, errors.New("Importer.Import serves exactly one region; use ImportRegions")
	}
	return ImportRegions(ctx, o, out, func(string) (Importer, error) { return i, nil })
}

func (i Importer) importVerified(ctx context.Context, o Options, logf func(string, ...any)) (map[string]any, error) {
	objectName := "images/" + o.SHA256 + ".qcow2"
	image, err := i.FindImage(ctx, o.Compartment, o.DisplayName)
	if err != nil {
		return nil, err
	}
	// Display names are static (gru-1-arm64), so a live image of this name
	// may hold another QCOW2. Resume only the import of these exact bytes.
	if image != nil && image.SHA256 != o.SHA256 {
		return nil, fmt.Errorf("live image %s is named %s but holds QCOW2 %q, not %s; retire it before importing",
			image.ID, o.DisplayName, image.SHA256, o.SHA256)
	}
	workRequest := ""
	if image == nil {
		exists, metadata, err := i.Client.HeadObject(ctx, o.Namespace, o.Bucket, objectName)
		if err != nil {
			return nil, err
		}
		if exists && metadata["sha256"] != "" && metadata["sha256"] != o.SHA256 {
			return nil, fmt.Errorf("object %s carries a different sha256 metadata value", objectName)
		}
		if !exists {
			logf("uploading %s\n", objectName)
			partSize := o.PartSizeMiB
			if partSize == 0 {
				partSize = defaultPartSizeMiB
			}
			parallelism := o.UploadParallelism
			if parallelism == 0 {
				parallelism = defaultUploadParallelism
			}
			if err := i.Client.UploadObject(ctx, UploadRequest{Namespace: o.Namespace, Bucket: o.Bucket, Object: objectName,
				Path: o.QCOW2, SHA256: o.SHA256, Metadata: map[string]string{"sha256": o.SHA256},
				PartSize: int64(partSize) << 20, Parallelism: parallelism}); err != nil {
				return nil, err
			}
		}
		logf("importing image\n")
		created, request, err := i.Client.ImportImage(ctx, ImportRequest{Compartment: o.Compartment, Namespace: o.Namespace,
			Bucket: o.Bucket, Object: objectName, DisplayName: o.DisplayName, SHA256: o.SHA256})
		if err != nil {
			return nil, err
		}
		image, workRequest = &created, request
	}
	if image.ID == "" {
		return nil, errors.New("OCI image has no id")
	}
	id := image.ID
	available, err := i.WaitAvailable(ctx, id, workRequest)
	if err != nil {
		return nil, err
	}
	schema, err := i.EnsureCapabilities(ctx, o.Compartment, id, o.DisplayName)
	if err != nil {
		return nil, err
	}
	shapes, err := i.EnsureShapes(ctx, id)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(shapes))
	for _, entry := range shapes {
		names = append(names, entry.Shape)
	}
	slices.Sort(names)
	var billable any
	if available.BillableSizeGB != nil {
		billable = *available.BillableSizeGB
	}
	return map[string]any{"schema": "terrascale.oci.image-import.v1", "image_id": id, "display_name": o.DisplayName,
		"qcow2_sha256": o.SHA256, "compartment_id": o.Compartment, "object": o.Namespace + "/" + o.Bucket + "/" + objectName,
		"billable_size_gb": billable, "capability_schema_id": schema.ID, "shapes": names}, nil
}
