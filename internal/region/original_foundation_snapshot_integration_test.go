package region

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// originalFixtureSnapshot is the complete mutable state of one prebuilt
// original foundation fixture chain: every fixture layer's fields, the fake
// cloud with its object files, and the local anti-rollback floor. Subtests that
// only exercise a later stage restore it instead of rebuilding and re-running
// every earlier stage. Each restore writes fresh deep copies, so no mutable
// value is shared between subtests; the fixture keeps its keys, signed bundle,
// TLS servers and transport, which are never mutated.
type originalFixtureSnapshot struct {
	visited map[snapshotLayerKey]bool
	fields  []snapshotField
	cloud   *provisionCloud
	objects map[string][]byte
	floor   string
	floors  map[string][]byte
}

type snapshotLayerKey struct {
	address uintptr
	typ     reflect.Type
}

type snapshotField struct {
	target reflect.Value
	value  reflect.Value
}

// snapshotOriginalFixture records the state of fixture, a pointer to an
// original foundation SDK fixture whose prerequisite stages already ran.
func snapshotOriginalFixture(t *testing.T, fixture any) *originalFixtureSnapshot {
	t.Helper()
	s := &originalFixtureSnapshot{visited: map[snapshotLayerKey]bool{}}
	s.walk(reflect.ValueOf(fixture).Elem())
	if s.cloud == nil {
		t.Fatal("snapshot found no fake cloud")
	}
	s.cloud.mu.Lock()
	defer s.cloud.mu.Unlock()
	s.objects = readSnapshotDirectory(t, s.cloud.directory)
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	s.floor = filepath.Join(config, "terrascale-orchestrator", "foundation")
	s.floors = readSnapshotDirectory(t, s.floor)
	return s
}

// restore resets the fixture to the snapshot and binds the fake cloud's error
// reporting to the running subtest.
func (s *originalFixtureSnapshot) restore(t *testing.T) {
	t.Helper()
	for _, field := range s.fields {
		field.target.Set(deepCopySnapshotValue(field.value))
	}
	s.cloud.mu.Lock()
	defer s.cloud.mu.Unlock()
	s.cloud.test = t
	writeSnapshotDirectory(t, s.cloud.directory, s.objects)
	writeSnapshotDirectory(t, s.floor, s.floors)
}

var (
	snapshotCloudType = reflect.TypeFor[*provisionCloud]()
	snapshotTestType  = reflect.TypeFor[*testing.T]()
	snapshotMutexType = reflect.TypeFor[sync.Mutex]()
)

// walk records every field of a fixture layer. Fixture pointers (embedded or
// named, such as an admission fixture's reads layer) and the fake cloud are
// layers of the same chain and are walked in place, each once.
func (s *originalFixtureSnapshot) walk(layer reflect.Value) {
	// An embedded struct shares its parent's address, so the type is part of the key.
	key := snapshotLayerKey{layer.UnsafeAddr(), layer.Type()}
	if s.visited[key] {
		return
	}
	s.visited[key] = true
	for i := range layer.NumField() {
		field := settableSnapshotField(layer.Field(i))
		kind := layer.Type().Field(i)
		switch {
		case field.Type() == snapshotCloudType:
			if !field.IsNil() {
				if s.cloud == nil {
					s.cloud = field.Interface().(*provisionCloud)
				} else if s.cloud != field.Interface().(*provisionCloud) {
					panic("fixture chain has two fake clouds")
				}
				s.walk(field.Elem())
			}
		case snapshotFixtureLayer(field.Type()):
			if !field.IsNil() {
				s.walk(field.Elem())
			}
		case kind.Anonymous && field.Kind() == reflect.Struct:
			s.walk(field)
		case field.Type() == snapshotMutexType || field.Type() == snapshotTestType:
		default:
			s.fields = append(s.fields, snapshotField{target: field, value: deepCopySnapshotValue(field)})
		}
	}
}

var snapshotProviderType = reflect.TypeFor[*provisionProvider]()

func snapshotCopiesPointer(typ reflect.Type) bool {
	elem := typ.Elem()
	if typ == snapshotProviderType || snapshotFixtureLayer(typ) || typ == snapshotCloudType {
		return false
	}
	if elem.Name() == "" {
		return elem.Kind() != reflect.Struct
	}
	return strings.HasPrefix(elem.PkgPath(), "github.com/TerraScale/ts-orchestrator/") || elem.PkgPath() == ""
}

// snapshotFixtureLayer reports a pointer to one of this package's fixture types.
func snapshotFixtureLayer(typ reflect.Type) bool {
	return typ.Kind() == reflect.Pointer && typ.Elem().Kind() == reflect.Struct &&
		typ.Elem().PkgPath() == snapshotCloudType.Elem().PkgPath() && strings.HasSuffix(typ.Elem().Name(), "Fixture")
}

func settableSnapshotField(field reflect.Value) reflect.Value {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}

// deepCopySnapshotValue copies maps, slices, arrays, interfaces, structs and
// pointers to this module's data recursively, so a subtest that mutates a
// signed grant or journal value through a pointer cannot reach the next one.
// Pointers to other packages' values (keys, TLS servers, clients) and the
// provider, whose request counter the fake SDK clients share, stay shared.
func deepCopySnapshotValue(value reflect.Value) reflect.Value {
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() || !snapshotCopiesPointer(value.Type()) {
			return detachedSnapshotValue(value)
		}
		copied := reflect.New(value.Type().Elem())
		copied.Elem().Set(deepCopySnapshotValue(readableSnapshotValue(value).Elem()))
		return copied
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		copied := reflect.MakeMapWithSize(value.Type(), value.Len())
		for iter := value.MapRange(); iter.Next(); {
			copied.SetMapIndex(deepCopySnapshotValue(iter.Key()), deepCopySnapshotValue(iter.Value()))
		}
		return copied
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		copied := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for i := range value.Len() {
			copied.Index(i).Set(deepCopySnapshotValue(value.Index(i)))
		}
		return copied
	case reflect.Array:
		copied := reflect.New(value.Type()).Elem()
		for i := range value.Len() {
			copied.Index(i).Set(deepCopySnapshotValue(value.Index(i)))
		}
		return copied
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		copied := reflect.New(value.Type()).Elem()
		copied.Set(deepCopySnapshotValue(value.Elem()))
		return copied
	case reflect.Struct:
		source := reflect.New(value.Type()).Elem()
		source.Set(readableSnapshotValue(value))
		copied := reflect.New(value.Type()).Elem()
		for i := range value.NumField() {
			settableSnapshotField(copied.Field(i)).Set(deepCopySnapshotValue(settableSnapshotField(source.Field(i))))
		}
		return copied
	default:
		return detachedSnapshotValue(value)
	}
}

// detachedSnapshotValue copies a scalar, pointer or func into a value of its
// own; returning the field itself would alias the live fixture field.
func detachedSnapshotValue(value reflect.Value) reflect.Value {
	copied := reflect.New(value.Type()).Elem()
	copied.Set(readableSnapshotValue(value))
	return copied
}

// readableSnapshotValue strips the read-only flag that unexported fields carry.
func readableSnapshotValue(value reflect.Value) reflect.Value {
	if value.CanInterface() {
		return value
	}
	if !value.CanAddr() {
		panic("snapshot cannot read unaddressable unexported value of " + value.Type().String())
	}
	return settableSnapshotField(value)
}

func readSnapshotDirectory(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		// The trust floor directory appears with the first foundation read.
		return map[string][]byte{}
	}
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("snapshot directory %s has a subdirectory", directory)
		}
		wire, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = wire
	}
	return files
}

func writeSnapshotDirectory(t *testing.T, directory string, files map[string][]byte) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) && len(files) == 0 {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if _, ok := files[entry.Name()]; !ok {
			if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, wire := range files {
		if err := os.WriteFile(filepath.Join(directory, name), wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOriginalFixtureSnapshotRestoresEveryMutation(t *testing.T) {
	f := newOriginalCompartmentSDKFixture(t, "")
	state := snapshotOriginalFixture(t, f)
	requests, faulted, rows := f.cloud.requests, f.faulted, len(f.cloud.rows)
	f.cloud.requests++
	f.faulted = !faulted
	f.fault = "changed"
	f.cloud.rows["extra"] = map[string]any{"id": "extra"}
	f.gets["extra"]++
	f.cloud.writeObject("extra", []byte("extra"))
	state.restore(t)
	if f.cloud.requests != requests || f.faulted != faulted || f.fault != "" || len(f.cloud.rows) != rows || f.gets["extra"] != 0 {
		t.Fatal("restore left a mutated fixture field")
	}
	if _, err := os.Stat(f.cloud.objectPath("extra")); !os.IsNotExist(err) {
		t.Fatal("restore left an object written after the snapshot", err)
	}
	f.cloud.rows["extra"] = map[string]any{"id": "extra"}
	state.restore(t)
	if len(f.cloud.rows) != rows {
		t.Fatal("a restored map is shared with the snapshot")
	}
}
