package imageimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOCI is a typed, in-memory region. Each method records its name so tests
// can assert the exact provider call sequence.
type fakeOCI struct {
	mu            sync.Mutex
	calls         []string
	images        []Image
	image         Image
	objectExists  bool
	objectMeta    map[string]string
	uploads       []UploadRequest
	workRequests  []WorkRequestStatus
	schemas       []string
	schema        CapabilitySchema
	shapeReads    int
	shapes        func(read int) []ShapeEntry
	imageStates   []string
	failOn        string
	importRequest ImportRequest
}

func (f *fakeOCI) record(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	if name == f.failOn {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (f *fakeOCI) ListImages(context.Context, string, string) ([]Image, error) {
	return f.images, f.record("list images")
}
func (f *fakeOCI) GetImage(context.Context, string) (Image, error) {
	if err := f.record("get image"); err != nil {
		return Image{}, err
	}
	image := f.image
	if len(f.imageStates) > 0 {
		image.LifecycleState, f.imageStates = f.imageStates[0], f.imageStates[1:]
	}
	return image, nil
}
func (f *fakeOCI) HeadObject(context.Context, string, string, string) (bool, map[string]string, error) {
	return f.objectExists, f.objectMeta, f.record("head object")
}
func (f *fakeOCI) UploadObject(_ context.Context, request UploadRequest) error {
	f.uploads = append(f.uploads, request)
	return f.record("upload object")
}
func (f *fakeOCI) ImportImage(_ context.Context, request ImportRequest) (Image, string, error) {
	f.importRequest = request
	return Image{ID: f.image.ID, LifecycleState: "IMPORTING", SHA256: request.SHA256}, "work", f.record("import image")
}
func (f *fakeOCI) GetWorkRequest(context.Context, string) (WorkRequestStatus, error) {
	if err := f.record("get work request"); err != nil {
		return "", err
	}
	status := WorkRequestSucceeded
	if len(f.workRequests) > 0 {
		status, f.workRequests = f.workRequests[0], f.workRequests[1:]
	}
	return status, nil
}
func (f *fakeOCI) ListCapabilitySchemas(context.Context, string, string) ([]string, error) {
	return f.schemas, f.record("list capability schemas")
}
func (f *fakeOCI) GetCapabilitySchema(context.Context, string) (CapabilitySchema, error) {
	return f.schema, f.record("get capability schema")
}
func (f *fakeOCI) GlobalCapabilitySchemaVersion(context.Context) (string, error) {
	return "version", f.record("global capability schema")
}
func (f *fakeOCI) CreateCapabilitySchema(_ context.Context, _, _, _, version string, data map[string]Capability) (CapabilitySchema, error) {
	if version != "version" {
		return CapabilitySchema{}, errors.New("wrong global version")
	}
	return CapabilitySchema{ID: "capabilities", Data: data}, f.record("create capability schema")
}
func (f *fakeOCI) ListShapes(context.Context, string) ([]ShapeEntry, error) {
	f.shapeReads++
	return f.shapes(f.shapeReads), f.record("list shapes")
}
func (f *fakeOCI) AddShape(_ context.Context, _ string, entry ShapeEntry) error {
	if entry.Shape != A1Shape || !a1Constraints(entry) {
		return errors.New("added a shape outside the launch contract")
	}
	return f.record("add shape")
}
func (f *fakeOCI) RemoveShape(context.Context, string, string) error { return f.record("remove shape") }

func a1() ShapeEntry {
	return ShapeEntry{Shape: A1Shape, OCPU: &Range{Min: 1, Max: 4}, MemoryGB: &Range{Min: 4, Max: 24}}
}

func noPause(context.Context, time.Duration) error { return nil }

func newFake(resume bool) *fakeOCI {
	f := &fakeOCI{image: Image{ID: "image", LifecycleState: "AVAILABLE", BillableSizeGB: new(int64(47))}}
	if resume {
		f.images = []Image{f.image, {ID: "old", LifecycleState: "DELETED"}}
	}
	f.shapes = func(read int) []ShapeEntry {
		if read == 1 {
			return []ShapeEntry{{Shape: "VM.Standard.E4.Flex"}}
		}
		return []ShapeEntry{a1(), {Shape: "VM.Standard.Generic"}}
	}
	return f
}

func qualified(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "image.qcow2")
	if err := os.WriteFile(source, []byte("qualified bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("qualified bytes"))
	return Options{QCOW2: source, SHA256: hex.EncodeToString(hash[:]), Compartment: "compartment", Namespace: "namespace",
		Bucket: "bucket", DisplayName: "qualified", Out: filepath.Join(root, "record.json")}
}

func TestImportAndResume(t *testing.T) {
	for _, resume := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "resume"}[resume], func(t *testing.T) {
			o := qualified(t)
			f := newFake(resume)
			if resume {
				f.images[0].SHA256 = o.SHA256
			}
			r, err := (Importer{Client: f, Pause: noPause}).Import(t.Context(), o, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if r["image_id"] != "image" || r["capability_schema_id"] != "capabilities" || r["billable_size_gb"] != int64(47) {
				t.Fatalf("record=%v", r)
			}
			b, err := os.ReadFile(o.Out)
			if err != nil {
				t.Fatal(err)
			}
			var written map[string]any
			if err := json.Unmarshal(b, &written); err != nil {
				t.Fatal(err)
			}
			if written["schema"] != "terrascale.oci.image-import.v1" || written["qcow2_sha256"] != o.SHA256 ||
				written["object"] != "namespace/bucket/images/"+o.SHA256+".qcow2" {
				t.Fatalf("record=%v", written)
			}
			want := []string{"list images"}
			if !resume {
				want = append(want, "head object", "upload object", "import image", "get work request")
			}
			want = append(want, "get image", "list capability schemas", "global capability schema", "create capability schema",
				"list shapes", "add shape", "remove shape", "list shapes")
			if !slices.Equal(f.calls, want) {
				t.Fatalf("calls=%v want=%v", f.calls, want)
			}
			if !resume {
				upload := f.uploads[0]
				if upload.PartSize != 128<<20 || upload.Parallelism != 8 || upload.Metadata["sha256"] != o.SHA256 ||
					upload.Object != "images/"+o.SHA256+".qcow2" {
					t.Fatalf("upload=%+v", upload)
				}
				if f.importRequest.Object != upload.Object || f.importRequest.DisplayName != "qualified" ||
					f.importRequest.SHA256 != o.SHA256 {
					t.Fatalf("import=%+v", f.importRequest)
				}
			}
		})
	}
}

// Image names are static, so a live image of the same name may hold an
// older QCOW2; importing other bytes must not adopt it.
func TestImportRefusesALiveImageOfTheNameWithOtherBytes(t *testing.T) {
	for _, digest := range []string{"", strings.Repeat("a", 64)} {
		o := qualified(t)
		f := newFake(true)
		f.images[0].SHA256 = digest
		if _, err := (Importer{Client: f, Pause: noPause}).Import(t.Context(), o, io.Discard); err == nil ||
			!strings.Contains(err.Error(), "retire it before importing") {
			t.Fatalf("adopted an image holding %q: %v", digest, err)
		}
		if !slices.Equal(f.calls, []string{"list images"}) {
			t.Fatalf("calls=%v", f.calls)
		}
	}
}

func TestExistingObjectSkipsUploadButMustMatchDigest(t *testing.T) {
	o := qualified(t)
	f := newFake(false)
	f.objectExists = true
	f.objectMeta = map[string]string{"sha256": o.SHA256}
	if _, err := (Importer{Client: f, Pause: noPause}).Import(t.Context(), o, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(f.uploads) != 0 {
		t.Fatal("re-uploaded an existing object")
	}
	f = newFake(false)
	f.objectExists = true
	f.objectMeta = map[string]string{"sha256": strings.Repeat("0", 64)}
	if _, err := (Importer{Client: f, Pause: noPause}).Import(t.Context(), o, io.Discard); err == nil || !strings.Contains(err.Error(), "different sha256") {
		t.Fatalf("error=%v", err)
	}
	if slices.Contains(f.calls, "import image") {
		t.Fatal("imported an object with mismatched digest metadata")
	}
}

func TestDigestRejectsBeforeCloudEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate")
	if err := os.WriteFile(path, []byte("tampered"), 0644); err != nil {
		t.Fatal(err)
	}
	f := newFake(false)
	_, err := (Importer{Client: f}).Import(t.Context(), Options{QCOW2: path, SHA256: strings.Repeat("0", 64), Compartment: "c", Namespace: "n", Bucket: "b", DisplayName: "d", Out: path + ".json"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("error=%v", err)
	}
	if len(f.calls) != 0 {
		t.Fatal(f.calls)
	}
}

func TestOptionsRejectUncataloguedOrRepeatedRegionsBeforeEffects(t *testing.T) {
	for _, regions := range [][]string{{"uk-london-1"}, {"sa-saopaulo-1", "sa-saopaulo-1"}, {"GRU"}} {
		o := qualified(t)
		o.Regions = regions
		called := false
		_, err := ImportRegions(t.Context(), o, io.Discard, func(string) (Importer, error) {
			called = true
			return Importer{Client: newFake(false)}, nil
		})
		if err == nil || called {
			t.Fatalf("regions %v accepted: %v", regions, err)
		}
	}
	o := qualified(t)
	o.Regions = []string{"sa-saopaulo-1"}
	o.PartSizeMiB = 1 << 20
	if _, err := ImportRegions(t.Context(), o, io.Discard, nil); err == nil {
		t.Fatal("accepted an unbounded part size")
	}
}

func TestImportRegionsInParallel(t *testing.T) {
	o := qualified(t)
	o.Regions = []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}
	var mu sync.Mutex
	fakes := map[string]*fakeOCI{}
	// Every region blocks in its first work request poll until all three have
	// reached it, so a serial importer would time out instead of passing.
	started := make(chan struct{}, len(o.Regions))
	release := make(chan struct{})
	go func() {
		for range o.Regions {
			<-started
		}
		close(release)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result, err := ImportRegions(ctx, o, io.Discard, func(region string) (Importer, error) {
		f := newFake(false)
		f.image.ID = "image-" + region
		f.workRequests = []WorkRequestStatus{WorkRequestInProgress, WorkRequestSucceeded}
		mu.Lock()
		fakes[region] = f
		mu.Unlock()
		var once sync.Once
		return Importer{Client: f, Pause: func(ctx context.Context, delay time.Duration) error {
			if delay != 5*time.Second {
				t.Errorf("first poll delay=%v", delay)
			}
			once.Do(func() { started <- struct{}{} })
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["schema"] != "terrascale.oci.image-import-set.v1" {
		t.Fatalf("result=%v", result)
	}
	regions := result["regions"].(map[string]any)
	for _, region := range o.Regions {
		record := regions[region].(map[string]any)
		if record["image_id"] != "image-"+region || len(fakes[region].uploads) != 1 {
			t.Fatalf("region %s record=%v", region, record)
		}
	}
}

func TestImportRegionsReportsEveryRegionalFailure(t *testing.T) {
	o := qualified(t)
	o.Regions = []string{"sa-saopaulo-1", "us-sanjose-1"}
	_, err := ImportRegions(t.Context(), o, io.Discard, func(region string) (Importer, error) {
		f := newFake(false)
		if region == "us-sanjose-1" {
			f.failOn = "upload object"
		}
		return Importer{Client: f, Pause: noPause}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "us-sanjose-1: injected upload object failure") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat(o.Out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("wrote a record for a partial import")
	}
}

func TestDuplicateImagesRejected(t *testing.T) {
	f := &fakeOCI{images: []Image{{LifecycleState: "AVAILABLE"}, {LifecycleState: "IMPORTING"}}}
	_, err := (Importer{Client: f}).FindImage(t.Context(), "c", "d")
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatal(err)
	}
}

func TestCapabilitiesAndFinalShapesFailClosed(t *testing.T) {
	t.Run("capabilities", func(t *testing.T) {
		caps := Capabilities()
		caps["Compute.Firmware"] = Capability{Values: []string{"BIOS"}, Default: "BIOS"}
		f := &fakeOCI{schemas: []string{"schema"}, schema: CapabilitySchema{ID: "schema", Data: caps}}
		_, err := (Importer{Client: f}).EnsureCapabilities(t.Context(), "c", "i", "n")
		if err == nil || !strings.Contains(err.Error(), "Compute.Firmware") {
			t.Fatal(err)
		}
	})
	t.Run("missing capability", func(t *testing.T) {
		caps := Capabilities()
		delete(caps, "Storage.ConsistentVolumeNaming")
		f := &fakeOCI{schemas: []string{"schema"}, schema: CapabilitySchema{ID: "schema", Data: caps}}
		if _, err := (Importer{Client: f}).EnsureCapabilities(t.Context(), "c", "i", "n"); err == nil {
			t.Fatal("accepted a schema missing a contract capability")
		}
	})
	for _, shape := range []string{"VM.Standard.E4.Flex", A1Shape} {
		t.Run(shape, func(t *testing.T) {
			f := &fakeOCI{shapes: func(read int) []ShapeEntry {
				if read == 1 {
					return []ShapeEntry{a1()}
				}
				if shape == A1Shape {
					broken := a1()
					broken.OCPU = &Range{Min: 1, Max: 99}
					return []ShapeEntry{broken}
				}
				return []ShapeEntry{a1(), {Shape: shape}}
			}}
			if _, err := (Importer{Client: f}).EnsureShapes(t.Context(), "i"); err == nil {
				t.Fatal("accepted incompatible final shape state")
			}
		})
	}
}

func TestAvailabilityBackoffCancellationAndTerminalFailure(t *testing.T) {
	t.Run("work request failed", func(t *testing.T) {
		f := &fakeOCI{workRequests: []WorkRequestStatus{WorkRequestFailed}}
		_, err := (Importer{Client: f, Pause: noPause}).WaitAvailable(t.Context(), "i", "work")
		if err == nil || !strings.Contains(err.Error(), "FAILED") || slices.Contains(f.calls, "get image") {
			t.Fatalf("err=%v calls=%v", err, f.calls)
		}
	})
	t.Run("image failed", func(t *testing.T) {
		f := &fakeOCI{image: Image{ID: "i", LifecycleState: "FAILED"}}
		if _, err := (Importer{Client: f, Pause: noPause}).WaitAvailable(t.Context(), "i", ""); err == nil {
			t.Fatal("accepted a failed image")
		}
	})
	t.Run("backoff doubles to its ceiling", func(t *testing.T) {
		f := &fakeOCI{workRequests: []WorkRequestStatus{WorkRequestAccepted, WorkRequestInProgress, WorkRequestInProgress,
			WorkRequestInProgress, WorkRequestInProgress, WorkRequestSucceeded}, image: Image{ID: "i", LifecycleState: "AVAILABLE"}}
		var delays []time.Duration
		_, err := (Importer{Client: f, MaxPollInterval: 30 * time.Second, Pause: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		}}).WaitAvailable(t.Context(), "i", "work")
		if err != nil {
			t.Fatal(err)
		}
		want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second}
		if !slices.Equal(delays, want) {
			t.Fatalf("delays=%v want %v", delays, want)
		}
	})
	t.Run("cancelled while importing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		f := &fakeOCI{image: Image{ID: "i", LifecycleState: "IMPORTING"}}
		_, err := (Importer{Client: f, Pause: func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }}).WaitAvailable(ctx, "i", "")
		if !errors.Is(err, context.Canceled) || len(f.calls) != 1 {
			t.Fatalf("err=%v calls=%v", err, f.calls)
		}
	})
}

func TestRunParsesRepeatableRegions(t *testing.T) {
	o := qualified(t)
	var mu sync.Mutex
	var regions []string
	err := RunWith(t.Context(), []string{"--qcow2", o.QCOW2, "--sha256", o.SHA256, "--region", "us-sanjose-1,eu-frankfurt-1",
		"--compartment-id", "c", "--namespace", "n", "--bucket", "b", "--display-name", "d", "--out", o.Out,
		"--part-size-mib", "64", "--upload-parallelism", "4"}, io.Discard, func(region string) (API, error) {
		mu.Lock()
		regions = append(regions, region)
		mu.Unlock()
		return &tunedFake{fakeOCI: newFake(false)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(regions)
	if !slices.Equal(regions, []string{"eu-frankfurt-1", "us-sanjose-1"}) {
		t.Fatalf("regions=%v", regions)
	}
}

// tunedFake asserts that the upload tuning flags reach the upload request.
type tunedFake struct{ *fakeOCI }

func (p *tunedFake) UploadObject(ctx context.Context, request UploadRequest) error {
	if request.PartSize != 64<<20 || request.Parallelism != 4 {
		return errors.New("upload tuning flags were not applied")
	}
	return p.fakeOCI.UploadObject(ctx, request)
}
