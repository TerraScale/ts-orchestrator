package stateful

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// volumesTestInvalidOperation reports whether err is one of the package
// invalid-operation errors.
func volumesTestInvalidOperation(err error) bool {
	var invalidOperation *InvalidOperationError
	return errors.As(err, &invalidOperation)
}

// volumesTestInvalidData reports whether err is one of the package
// invalid-data errors.
func volumesTestInvalidData(err error) bool {
	var invalidData *InvalidDataError
	return errors.As(err, &invalidData)
}

// volumesTestStore is the deterministic in-memory PersistentVolumeStore fake.
type volumesTestStore struct {
	bindings []VolumeBinding
	loadErr  error
	saveErr  error
}

func (s *volumesTestStore) Load() ([]VolumeBinding, error) {
	return s.bindings, s.loadErr
}

func (s *volumesTestStore) Save(bindings []VolumeBinding) error {
	s.bindings = append([]VolumeBinding(nil), bindings...)
	return s.saveErr
}

func TestCanonicalDataVolumeId(t *testing.T) {
	tests := []struct {
		name         string
		roleKind     string
		allocationId string
		expected     string
		expectParam  string
	}{
		{
			name:         "canonical name",
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			expected:     "terrascale-terrabase-terrascale-gru-terrabase-1-data",
		},
		{
			name:         "single character tokens",
			roleKind:     "v",
			allocationId: "a",
			expected:     "terrascale-v-a-data",
		},
		{
			name:         "uppercase role kind",
			roleKind:     "TerraBase",
			allocationId: "a1",
			expectParam:  "roleKind",
		},
		{
			name:         "empty allocation id",
			roleKind:     "terrabase",
			allocationId: "",
			expectParam:  "allocationId",
		},
		{
			name:         "underscore allocation id",
			roleKind:     "terrabase",
			allocationId: "a_1",
			expectParam:  "allocationId",
		},
		{
			name:         "composed name exceeds the token bound",
			roleKind:     strings.Repeat("a", 24),
			allocationId: strings.Repeat("b", 24),
			expectParam:  "value",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := CanonicalDataVolumeId(test.roleKind, test.allocationId)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid id")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %s", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("id: %v", err)
			}
			if id.String() != test.expected {
				t.Fatalf("id = %q, want %q", id.String(), test.expected)
			}
		})
	}
}

func TestPersistentVolumeCatalogBindDataVolume(t *testing.T) {
	catalog, err := NewPersistentVolumeCatalog(16)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	binding, err := catalog.BindDataVolume("terrabase", "terrabase-1", "/var/lib/terrabase")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if binding.ReadOnly {
		t.Fatal("a data volume binding must be writable")
	}
	if binding.VolumeId.String() != "terrascale-terrabase-terrabase-1-data" {
		t.Fatalf("volume id = %q", binding.VolumeId.String())
	}

	_, err = catalog.BindDataVolume("terrabase", "terrabase-1", "/var/lib/other")
	if !volumesTestInvalidOperation(err) {
		t.Fatalf("second data volume error = %v, want an invalid operation", err)
	}

	data, err := catalog.DataVolume("terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("data volume: %v", err)
	}
	if data.Destination != "/var/lib/terrabase" {
		t.Fatalf("destination = %q", data.Destination)
	}
}

func TestPersistentVolumeCatalogRejectsMalformedIds(t *testing.T) {
	tests := []struct {
		name         string
		roleKind     string
		allocationId string
		destination  string
		expectParam  string
	}{
		{
			name:         "uppercase role kind",
			roleKind:     "TerraBase",
			allocationId: "a1",
			destination:  "/var/lib/terrabase",
			expectParam:  "roleKind",
		},
		{
			name:         "leading dash allocation id",
			roleKind:     "terrabase",
			allocationId: "-a1",
			destination:  "/var/lib/terrabase",
			expectParam:  "allocationId",
		},
		{
			name:         "relative destination",
			roleKind:     "terrabase",
			allocationId: "a1",
			destination:  "var/lib/terrabase",
			expectParam:  "destination",
		},
		{
			name:         "traversal destination",
			roleKind:     "terrabase",
			allocationId: "a1",
			destination:  "/var/lib/../terrabase",
			expectParam:  "destination",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := NewPersistentVolumeCatalog(16)
			if err != nil {
				t.Fatalf("catalog: %v", err)
			}
			if _, err := catalog.BindDataVolume(
				test.roleKind, test.allocationId, test.destination); !errorsAsParam(err, test.expectParam) {
				t.Fatalf("bind data error %v does not reference param %s", err, test.expectParam)
			}
			volumeId, err := CanonicalDataVolumeId("terrabase", "terrabase-1")
			if err != nil {
				t.Fatalf("canonical id: %v", err)
			}
			if _, err := catalog.BindReadOnlyMount(
				volumeId, test.roleKind, test.allocationId,
				test.destination); !errorsAsParam(err, test.expectParam) {
				t.Fatalf("bind read-only error %v does not reference param %s", err, test.expectParam)
			}
			if test.expectParam != "destination" {
				if _, err := catalog.Bindings(test.roleKind, test.allocationId); !errorsAsParam(err, test.expectParam) {
					t.Fatalf("bindings error %v does not reference param %s", err, test.expectParam)
				}
				if _, err := catalog.DataVolume(test.roleKind, test.allocationId); !errorsAsParam(err, test.expectParam) {
					t.Fatalf("data volume error %v does not reference param %s", err, test.expectParam)
				}
			}
		})
	}
}

func TestPersistentVolumeCatalogBindReadOnlyMountRules(t *testing.T) {
	catalog, err := NewPersistentVolumeCatalog(16)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if _, err := catalog.BindDataVolume("terrabase", "terrabase-1", "/var/lib/terrabase"); err != nil {
		t.Fatalf("bind data: %v", err)
	}
	volumeId, err := CanonicalDataVolumeId("terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("canonical id: %v", err)
	}

	mount, err := catalog.BindReadOnlyMount(volumeId, "backup", "backup-1", "/var/lib/backup/data")
	if err != nil {
		t.Fatalf("bind read-only: %v", err)
	}
	if !mount.ReadOnly {
		t.Fatal("a read-only mount must be read-only")
	}

	tests := []struct {
		name         string
		volumeId     PersistentVolumeId
		roleKind     string
		allocationId string
		destination  string
	}{
		{
			name:         "same role kind as the data owner",
			volumeId:     volumeId,
			roleKind:     "terrabase",
			allocationId: "terrabase-2",
			destination:  "/var/lib/terrabase-2/data",
		},
		{
			name:         "the data owner itself",
			volumeId:     volumeId,
			roleKind:     "terrabase",
			allocationId: "terrabase-1",
			destination:  "/var/lib/terrabase-2/data",
		},
		{
			name:         "unknown volume",
			volumeId:     PersistentVolumeId{Value: "terrascale-terrabase-terrabase-9-data"},
			roleKind:     "backup",
			allocationId: "backup-2",
			destination:  "/var/lib/backup-2/data",
		},
		{
			name:         "duplicate mount for one replica",
			volumeId:     volumeId,
			roleKind:     "backup",
			allocationId: "backup-1",
			destination:  "/var/lib/backup/other",
		},
		{
			name:         "duplicate destination for one replica",
			volumeId:     volumeId,
			roleKind:     "backup",
			allocationId: "backup-1",
			destination:  "/var/lib/backup/data",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := catalog.BindReadOnlyMount(
				test.volumeId, test.roleKind, test.allocationId,
				test.destination); !volumesTestInvalidOperation(err) {
				t.Fatalf("error = %v, want an invalid operation", err)
			}
		})
	}
}

func TestPersistentVolumeCatalogEnforcesBindingBound(t *testing.T) {
	catalog, err := NewPersistentVolumeCatalog(1)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if _, err := catalog.BindDataVolume("terrabase", "terrabase-1", "/var/lib/terrabase"); err != nil {
		t.Fatalf("bind data: %v", err)
	}
	volumeId, err := CanonicalDataVolumeId("terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("canonical id: %v", err)
	}
	if _, err := catalog.BindReadOnlyMount(
		volumeId, "backup", "backup-1", "/var/lib/backup/data"); !errorsAsParam(err, "bindings") {
		t.Fatalf("error %v does not reference param bindings", err)
	}
	if _, err := NewPersistentVolumeCatalog(0); !errorsAsParam(err, "maximumBindings") {
		t.Fatalf("error %v does not reference param maximumBindings", err)
	}
}

func TestPersistentVolumeCatalogSnapshotOrderAndRoundTrip(t *testing.T) {
	catalog, err := NewPersistentVolumeCatalog(16)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if _, err := catalog.BindDataVolume("terrabase", "terrabase-2", "/var/lib/terrabase-2"); err != nil {
		t.Fatalf("bind data 2: %v", err)
	}
	if _, err := catalog.BindDataVolume("terrabase", "terrabase-1", "/var/lib/terrabase-1"); err != nil {
		t.Fatalf("bind data 1: %v", err)
	}
	if _, err := catalog.BindDataVolume("backup", "backup-1", "/var/lib/backup-1"); err != nil {
		t.Fatalf("bind data 3: %v", err)
	}
	terrabaseVolume, err := CanonicalDataVolumeId("terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("canonical id: %v", err)
	}
	if _, err := catalog.BindReadOnlyMount(
		terrabaseVolume, "backup", "backup-2", "/var/lib/backup-2/data"); err != nil {
		t.Fatalf("bind read-only: %v", err)
	}

	snapshot := catalog.Snapshot()
	expectedOrder := []string{
		"terrascale-backup-backup-1-data",
		"terrascale-terrabase-terrabase-1-data",
		"terrascale-terrabase-terrabase-1-data",
		"terrascale-terrabase-terrabase-2-data",
	}
	if len(snapshot) != len(expectedOrder) {
		t.Fatalf("snapshot length = %d, want %d", len(snapshot), len(expectedOrder))
	}
	for index, expected := range expectedOrder {
		if snapshot[index].VolumeId.String() != expected {
			t.Fatalf("snapshot[%d] volume = %q, want %q",
				index, snapshot[index].VolumeId.String(), expected)
		}
	}

	store := &volumesTestStore{}
	if err := catalog.Persist(store); err != nil {
		t.Fatalf("persist: %v", err)
	}
	restored, err := RestorePersistentVolumeCatalog(store, 16)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !reflect.DeepEqual(catalog.Snapshot(), restored.Snapshot()) {
		t.Fatal("restored snapshot differs from the persisted snapshot")
	}
	for _, key := range [][2]string{
		{"terrabase", "terrabase-1"},
		{"terrabase", "terrabase-2"},
		{"backup", "backup-1"},
		{"backup", "backup-2"},
	} {
		original, err := catalog.Bindings(key[0], key[1])
		if err != nil {
			t.Fatalf("bindings %v: %v", key, err)
		}
		roundTripped, err := restored.Bindings(key[0], key[1])
		if err != nil {
			t.Fatalf("restored bindings %v: %v", key, err)
		}
		if !reflect.DeepEqual(original, roundTripped) {
			t.Fatalf("restored bindings for %v differ from the original", key)
		}
	}
}

func TestPersistentVolumeCatalogRestoreRejectsCorruptSnapshots(t *testing.T) {
	terrabaseVolume, err := CanonicalDataVolumeId("terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("canonical id: %v", err)
	}

	tests := []struct {
		name        string
		bindings    []VolumeBinding
		maximum     int
		check       func(err error) bool
		description string
	}{
		{
			name: "writable volume with a foreign name",
			bindings: []VolumeBinding{{
				VolumeId:     PersistentVolumeId{Value: "foreign-volume"},
				RoleKind:     "terrabase",
				AllocationId: "terrabase-1",
				Destination:  "/var/lib/terrabase",
			}},
			maximum:     16,
			check:       volumesTestInvalidData,
			description: "an invalid-data error",
		},
		{
			name: "read-only mount without an owner",
			bindings: []VolumeBinding{{
				VolumeId:     terrabaseVolume,
				RoleKind:     "backup",
				AllocationId: "backup-1",
				Destination:  "/var/lib/backup/data",
				ReadOnly:     true,
			}},
			maximum:     16,
			check:       volumesTestInvalidOperation,
			description: "an invalid operation",
		},
		{
			name: "duplicate volume for one replica",
			bindings: []VolumeBinding{
				{
					VolumeId:     terrabaseVolume,
					RoleKind:     "terrabase",
					AllocationId: "terrabase-1",
					Destination:  "/var/lib/terrabase",
				},
				{
					VolumeId:     terrabaseVolume,
					RoleKind:     "terrabase",
					AllocationId: "terrabase-1",
					Destination:  "/var/lib/terrabase/clone",
					ReadOnly:     true,
				},
			},
			maximum:     16,
			check:       volumesTestInvalidData,
			description: "an invalid-data error",
		},
		{
			name: "two data volumes for one replica",
			bindings: []VolumeBinding{
				{
					VolumeId:     terrabaseVolume,
					RoleKind:     "terrabase",
					AllocationId: "terrabase-1",
					Destination:  "/var/lib/terrabase",
				},
				{
					VolumeId:     PersistentVolumeId{Value: "terrascale-terrabase-terrabase-1-aux"},
					RoleKind:     "terrabase",
					AllocationId: "terrabase-1",
					Destination:  "/var/lib/terrabase/aux",
				},
			},
			maximum:     16,
			check:       volumesTestInvalidData,
			description: "an invalid-data error for the foreign writable name",
		},
		{
			name: "snapshot exceeds the bound",
			bindings: []VolumeBinding{
				{
					VolumeId:     terrabaseVolume,
					RoleKind:     "terrabase",
					AllocationId: "terrabase-1",
					Destination:  "/var/lib/terrabase",
				},
			},
			maximum: 0,
			check: func(err error) bool {
				return errorsAsParam(err, "maximumBindings")
			},
			description: "a maximumBindings argument error",
		},
		{
			name: "malformed binding row",
			bindings: []VolumeBinding{{
				VolumeId:     PersistentVolumeId{Value: "terrascale-terrabase-terrabase-1-data"},
				RoleKind:     "terrabase",
				AllocationId: "terrabase-1",
				Destination:  "relative/path",
			}},
			maximum: 16,
			check: func(err error) bool {
				return errorsAsParam(err, "destination")
			},
			description: "a destination argument error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &volumesTestStore{bindings: test.bindings}
			_, err := RestorePersistentVolumeCatalog(store, test.maximum)
			if err == nil {
				t.Fatal("expected a restore error, got a valid catalog")
			}
			if !test.check(err) {
				t.Fatalf("error = %v, want %s", err, test.description)
			}
		})
	}
}

func TestPersistentVolumeCatalogStoreSeam(t *testing.T) {
	catalog, err := NewPersistentVolumeCatalog(16)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if _, err := catalog.BindDataVolume("terrabase", "terrabase-1", "/var/lib/terrabase"); err != nil {
		t.Fatalf("bind data: %v", err)
	}

	if err := catalog.Persist(nil); !errorsAsParam(err, "store") {
		t.Fatalf("persist(nil) error %v does not reference param store", err)
	}
	if _, err := RestorePersistentVolumeCatalog(nil, 16); !errorsAsParam(err, "store") {
		t.Fatalf("restore(nil) error %v does not reference param store", err)
	}

	failingLoad := &volumesTestStore{loadErr: errors.New("load unavailable")}
	if _, err := RestorePersistentVolumeCatalog(failingLoad, 16); err == nil {
		t.Fatal("expected the load error to propagate")
	}
	failingSave := &volumesTestStore{saveErr: errors.New("save unavailable")}
	if err := catalog.Persist(failingSave); err == nil {
		t.Fatal("expected the save error to propagate")
	}
}
