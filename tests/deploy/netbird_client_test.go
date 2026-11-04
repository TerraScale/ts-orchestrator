package deploy_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

type netbirdArchive struct {
	URL          string `json:"url"`
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256"`
	BinarySHA256 string `json:"binary_sha256"`
}
type netbirdPin struct {
	Version  string `json:"version"`
	Archives struct {
		Arm64 netbirdArchive `json:"arm64"`
		AMD64 netbirdArchive `json:"amd64"`
	} `json:"archives"`
	Enrollment jsontext.Value `json:"enrollment_config"`
}
type netbirdFixture struct {
	t                            *testing.T
	root, archive, output, cache string
	binary                       []byte
	pin                          netbirdPin
}

func elf(architecture, body string) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	machine := uint16(183)
	if architecture == "amd64" {
		machine = 62
	}
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	return append(b, body...)
}
func newNetbird(t *testing.T) *netbirdFixture {
	t.Helper()
	dir := t.TempDir()
	f := &netbirdFixture{t: t, root: dir, archive: filepath.Join(dir, "upstream.tar.gz"), output: filepath.Join(dir, "result/netbird"), cache: filepath.Join(dir, "cache"), binary: elf("arm64", "test NetBird")}
	var inputs struct {
		Netbird netbirdPin `json:"netbird"`
	}
	if err := json.Unmarshal(read(t, filepath.Join(deployRoot(t), "deploy/image/image-inputs.json")), &inputs); err != nil {
		t.Fatal(err)
	}
	f.pin = inputs.Netbird
	f.makeArchive(tar.TypeReg, false)
	return f
}
func (f *netbirdFixture) makeArchive(kind byte, duplicate bool) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	add := func(name string, kind byte, data []byte, link string) {
		f.t.Helper()
		h := &tar.Header{Name: name, Typeflag: kind, Mode: 0644, Size: int64(len(data)), Linkname: link}
		if err := tw.WriteHeader(h); err != nil {
			f.t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			f.t.Fatal(err)
		}
	}
	add("../../escape", tar.TypeReg, []byte("evil"), "")
	data := f.binary
	link := ""
	if kind != tar.TypeReg {
		data = nil
		link = "../../escape"
	}
	add("netbird", kind, data, link)
	if duplicate {
		add("netbird", kind, f.binary, link)
	}
	if err := tw.Close(); err != nil {
		f.t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		f.t.Fatal(err)
	}
	write(f.t, f.archive, b.Bytes(), 0600)
	f.pin.Archives.Arm64.Bytes = int64(b.Len())
	f.pin.Archives.Arm64.SHA256 = digest(b.Bytes())
	f.pin.Archives.Arm64.BinarySHA256 = digest(f.binary)
}

type roundTripper func(*http.Request) (*http.Response, error)

func (r roundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return r(request) }
func (f *netbirdFixture) invoke(args map[string]any) map[string]any {
	f.t.Helper()
	calls := []any{}
	transport := roundTripper(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.String())
		if args["forbid_download"] == true {
			return nil, errors.New("unexpected download")
		}
		payload := read(f.t, args["payload"].(string))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(payload)), Header: make(http.Header)}, nil
	})
	var err error
	if args["operation"] == "fetch" {
		var pin client.Pin
		if err = json.Unmarshal(jsonBytes(f.t, args["pin"]), &pin); err != nil {
			f.t.Fatal(err)
		}
		cache, _ := args["cache"].(string)
		err = client.Fetch(f.t.Context(), pin, args["architecture"].(string), args["output"].(string), cache, &http.Client{Transport: transport})
	} else {
		var pin client.Archive
		if err = json.Unmarshal(jsonBytes(f.t, args["archive_pin"]), &pin); err != nil {
			f.t.Fatal(err)
		}
		err = client.Extract(args["archive"].(string), args["output"].(string), pin, args["architecture"].(string))
	}
	result := map[string]any{"calls": calls, "error": nil}
	if err != nil {
		result["error"] = map[string]any{"message": err.Error()}
	}
	return result
}
func (f *netbirdFixture) fetch(payload string, cache bool, forbid bool) map[string]any {
	args := map[string]any{"operation": "fetch", "pin": f.pin, "architecture": "arm64", "output": f.output, "payload": payload, "forbid_download": forbid}
	if cache {
		args["cache"] = f.cache
	}
	return f.invoke(args)
}
func noNetbirdError(t *testing.T, r map[string]any) { t.Helper(); equal(t, r["error"], nil) }

func TestNetbirdFetchChecksArchiveAndInstallsOnlyBinary(t *testing.T) {
	f := newNetbird(t)
	r := f.fetch(f.archive, true, false)
	noNetbirdError(t, r)
	equal(t, len(r["calls"].([]any)), 1)
	equal(t, read(t, f.output), f.binary)
	equal(t, mode(t, f.output), os.FileMode(0755))
	absent(t, filepath.Join(f.root, "escape"))
	equal(t, read(t, filepath.Join(f.cache, f.pin.Archives.Arm64.SHA256)), read(t, f.archive))
}

func validNetbirdConfig() map[string]any {
	return map[string]any{"management_url": "https://netbird.terrascale.tech", "management_ip": "10.250.10.155", "region": "sa-saopaulo-1", "setup_key_secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test"}
}
