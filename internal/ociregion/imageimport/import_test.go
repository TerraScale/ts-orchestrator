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
	"testing"
	"time"
)

type fakeOCI struct {
	calls   [][]string
	call    func([]string) (map[string]any, error)
	headErr error
}

func (f *fakeOCI) Call(_ context.Context, args ...string) (map[string]any, error) {
	f.calls = append(f.calls, slices.Clone(args))
	return f.call(args)
}
func (f *fakeOCI) Head(_ context.Context, args ...string) error {
	f.calls = append(f.calls, slices.Clone(args))
	return f.headErr
}
func data(v any) map[string]any { return map[string]any{"data": v} }
func a1() map[string]any {
	return map[string]any{"shape": A1Shape, "ocpu-constraints": map[string]any{"min": 1, "max": 4}, "memory-constraints": map[string]any{"min-in-gbs": 6, "max-in-gbs": 24}}
}

func TestImportAndResume(t *testing.T) {
	for _, resume := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "resume"}[resume], func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "image.qcow2")
			if err := os.WriteFile(source, []byte("qualified bytes"), 0644); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256([]byte("qualified bytes"))
			o := Options{QCOW2: source, SHA256: hex.EncodeToString(hash[:]), Compartment: "compartment", Namespace: "namespace", Bucket: "bucket", DisplayName: "qualified", Out: filepath.Join(root, "record.json")}
			image := map[string]any{"id": "image", "lifecycle-state": "AVAILABLE", "billable-size-in-gbs": 47}
			shapeReads := 0
			f := &fakeOCI{headErr: errors.New("not found")}
			f.call = func(args []string) (map[string]any, error) {
				switch strings.Join(args[:3], " ") {
				case "compute image list":
					if resume {
						return data([]any{image}), nil
					}
					return data([]any{}), nil
				case "os object put", "compute image-shape-compatibility-entry add", "compute image-shape-compatibility-entry remove":
					return map[string]any{}, nil
				case "compute image import", "compute image get":
					return data(image), nil
				case "compute image-capability-schema list":
					return data([]any{}), nil
				case "compute global-image-capability-schema list":
					return data([]any{map[string]any{"current-version-name": "version"}}), nil
				case "compute image-capability-schema create":
					return data(map[string]any{"id": "capabilities", "schema-data": Capabilities()}), nil
				case "compute image-shape-compatibility-entry list":
					shapeReads++
					if shapeReads == 1 {
						return data([]any{map[string]any{"shape": "VM.Standard.E4.Flex"}}), nil
					}
					return data([]any{a1(), map[string]any{"shape": "VM.Standard.Generic"}}), nil
				default:
					t.Fatalf("unexpected call: %v", args)
					return nil, nil
				}
			}
			r, err := (Importer{Client: f}).Import(t.Context(), o, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if r["image_id"] != "image" || r["capability_schema_id"] != "capabilities" {
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
			if written["qcow2_sha256"] != o.SHA256 {
				t.Fatalf("record hash=%v", written)
			}
			want := []string{"compute image list"}
			if !resume {
				want = append(want, "os object head", "os object put", "compute image import")
			}
			want = append(want, "compute image get", "compute image-capability-schema list", "compute global-image-capability-schema list", "compute image-capability-schema create", "compute image-shape-compatibility-entry list", "compute image-shape-compatibility-entry add", "compute image-shape-compatibility-entry remove", "compute image-shape-compatibility-entry list")
			got := []string{}
			for _, args := range f.calls {
				got = append(got, strings.Join(args[:3], " "))
			}
			if !slices.Equal(got, want) {
				t.Fatalf("calls=%v want=%v", got, want)
			}
		})
	}
}

func TestDigestRejectsBeforeCloudEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate")
	if err := os.WriteFile(path, []byte("tampered"), 0644); err != nil {
		t.Fatal(err)
	}
	f := &fakeOCI{call: func([]string) (map[string]any, error) {
		t.Fatal("provider called before digest admission")
		return nil, nil
	}}
	_, err := (Importer{Client: f}).Import(t.Context(), Options{QCOW2: path, SHA256: strings.Repeat("0", 64), Compartment: "c", Namespace: "n", Bucket: "b", DisplayName: "d", Out: path + ".json"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("error=%v", err)
	}
	if len(f.calls) != 0 {
		t.Fatal(f.calls)
	}
}

func TestDuplicateImagesRejected(t *testing.T) {
	f := &fakeOCI{call: func([]string) (map[string]any, error) {
		return data([]any{map[string]any{"lifecycle-state": "AVAILABLE"}, map[string]any{"lifecycle-state": "IMPORTING"}}), nil
	}}
	_, err := (Importer{Client: f}).FindImage(t.Context(), "c", "d")
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatal(err)
	}
}

func TestCapabilitiesAndFinalShapesFailClosed(t *testing.T) {
	t.Run("capabilities", func(t *testing.T) {
		caps := Capabilities()
		caps["Compute.Firmware"].(map[string]any)["default-value"] = "BIOS"
		f := &fakeOCI{call: func(args []string) (map[string]any, error) {
			if args[2] == "list" {
				return data([]any{map[string]any{"id": "schema"}}), nil
			}
			return data(map[string]any{"schema-data": caps}), nil
		}}
		_, err := (Importer{Client: f}).EnsureCapabilities(t.Context(), "c", "i", "n")
		if err == nil || !strings.Contains(err.Error(), "Compute.Firmware") {
			t.Fatal(err)
		}
	})
	for _, shape := range []string{"VM.Standard.E4.Flex", A1Shape} {
		t.Run(shape, func(t *testing.T) {
			reads := 0
			f := &fakeOCI{call: func(args []string) (map[string]any, error) {
				if args[2] != "list" {
					return map[string]any{}, nil
				}
				reads++
				if reads == 1 {
					return data([]any{a1()}), nil
				}
				if shape == A1Shape {
					broken := a1()
					broken["ocpu-constraints"] = map[string]any{"min": 1, "max": 99}
					return data([]any{broken}), nil
				}
				return data([]any{a1(), map[string]any{"shape": shape}}), nil
			}}
			if _, err := (Importer{Client: f}).EnsureShapes(t.Context(), "i"); err == nil {
				t.Fatal("accepted incompatible final shape state")
			}
		})
	}
}

func TestAvailabilityCancellationAndTerminalFailure(t *testing.T) {
	for _, state := range []string{"FAILED", "IMPORTING"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f := &fakeOCI{call: func([]string) (map[string]any, error) { return data(map[string]any{"lifecycle-state": state}), nil }}
			_, err := (Importer{Client: f, Pause: func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }}).WaitAvailable(ctx, "i")
			if err == nil {
				t.Fatal("accepted unavailable image")
			}
			if state == "IMPORTING" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if len(f.calls) != 1 {
				t.Fatal(f.calls)
			}
		})
	}
}
