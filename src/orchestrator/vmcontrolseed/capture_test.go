package vmcontrolseed

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func TestPreliminaryCaptureRequiresOptInAndStaysOnSource(t *testing.T) {
	guests := []Guest{{ID: "gru-one", Address: "10.77.0.10", MembershipPublicKey: membershipPublic(t)}, {ID: "gru-two", Address: "10.77.0.11", MembershipPublicKey: membershipPublic(t)}}
	ordinary, err := GenerateGRU("source-default", guests)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range ordinary {
			m.Clear()
		}
	}()
	for _, m := range ordinary {
		config, err := initialgrant.ParseConfig([]byte(m.Settings))
		if err != nil {
			t.Fatal(err)
		}
		if config.PreliminaryCapture != nil {
			t.Fatal("default acquired privileged capture capability")
		}
		if _, ok := m.Files[CapturePrivateKeyPath]; ok {
			t.Fatal("default received capture private key")
		}
	}
	declaration := PreliminaryCaptureDeclaration{MaxSnapshotBytes: 32 << 20, MaxTotalBytes: 128 << 20}
	materials, err := GenerateGRUWithPreliminaryCapture("source-capture", guests, declaration)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range materials {
			m.Clear()
		}
	}()
	seed := materials["gru-one"]
	config, err := initialgrant.ParseConfig([]byte(seed.Settings))
	if err != nil {
		t.Fatal(err)
	}
	capture := config.PreliminaryCapture
	if capture == nil || capture.RequestFile != CaptureRequestPath || capture.OutputDir != CaptureOutputPath {
		t.Fatal("explicit source worker scope missing")
	}
	participant, err := initialgrant.ParseConfig([]byte(materials["gru-two"].Settings))
	if err != nil {
		t.Fatal(err)
	}
	for _, secretPath := range []string{RegionalCaptureNKeyPath, GlobalCaptureNKeyPath, CapturePrivateKeyPath} {
		secret := seed.Files[secretPath]
		if len(secret) == 0 || bytes.Contains([]byte(seed.Settings), secret) || bytes.Contains([]byte(config.Broker.Configuration), secret) || bytes.Contains([]byte(materials["gru-two"].Settings), secret) {
			t.Fatal("source private capture credential missing or embedded in configuration")
		}
		for _, data := range materials["gru-two"].Files {
			if bytes.Equal(data, secret) {
				t.Fatal("participant received source capture private material")
			}
		}
	}
	for _, public := range []string{capture.Regional.PublicNKey, capture.Global.PublicNKey} {
		if bytes.Contains([]byte(materials["gru-two"].Settings), []byte(public)) {
			t.Fatal("participant configuration contains source capture account identity")
		}
	}
	if participant.PreliminaryCapture != nil || len(materials["gru-two"].Files) != 8 {
		t.Fatal("participant received source capability")
	}
	size, err := seed.DataDriveBytes()
	if err != nil {
		t.Fatal(err)
	}
	if size != config.Broker.StorageBudgetBytes+256<<20+declaration.MaxTotalBytes+declaration.MaxSnapshotBytes {
		t.Fatal("source drive omits staging or atomic-file reserve")
	}
	var broker struct {
		Accounts map[string]struct {
			Users []struct {
				NKey        string `json:"nkey"`
				Permissions struct {
					Publish struct {
						Allow []string `json:"allow"`
					} `json:"publish"`
					Subscribe struct {
						Allow []string `json:"allow"`
					} `json:"subscribe"`
				} `json:"permissions"`
			} `json:"users"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(config.Broker.Configuration), &broker); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		connection    initialgrant.Connection
		account, path string
		global        bool
	}{{capture.Regional, config.Regional.Account, RegionalCaptureNKeyPath, false}, {capture.Global, config.Global.Account, GlobalCaptureNKeyPath, true}} {
		if entry.connection.NKeySeedFile != entry.path || !IsFilePath(entry.path) {
			t.Fatal("source credential staging path absent")
		}
		pub, sub, err := initialcontrol.CapturePermissions("gru", config.Instance, entry.global)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, user := range broker.Accounts[entry.account].Users {
			if user.NKey == entry.connection.PublicNKey {
				found++
				if !reflect.DeepEqual(pub, user.Permissions.Publish.Allow) || !reflect.DeepEqual(sub, user.Permissions.Subscribe.Allow) {
					t.Fatal("broker permission scope differs from signed source profile")
				}
			}
		}
		if found != 1 {
			t.Fatal("source account privilege missing or duplicated")
		}
	}
	if bytes.Equal(seed.Files[RegionalCaptureNKeyPath], seed.Files[GlobalCaptureNKeyPath]) {
		t.Fatal("account capture identities reused")
	}
	for _, path := range []string{NKeyPath, GlobalNKeyPath, AuthorityNKeyPath, RegionalProvisionerNKeyPath, GlobalProvisionerNKeyPath} {
		if bytes.Equal(seed.Files[RegionalCaptureNKeyPath], seed.Files[path]) {
			t.Fatal("source capture reuses another role")
		}
	}
	changed := seed.Clone()
	defer changed.Clear()
	changed.Files[CaptureCertificatePath] = append([]byte(nil), seed.Files[CertificatePath]...)
	changed.Files[CapturePrivateKeyPath] = append([]byte(nil), seed.Files[PrivateKeyPath]...)
	c := config
	captureCopy := *c.PreliminaryCapture
	c.PreliminaryCapture = &captureCopy
	c.PreliminaryCapture.Regional.TLS.CertificateSHA256 = digest(changed.Files[CaptureCertificatePath])
	c.PreliminaryCapture.Global.TLS.CertificateSHA256 = c.PreliminaryCapture.Regional.TLS.CertificateSHA256
	raw, _ := json.Marshal(c)
	changed.Settings = string(raw)
	if err := changed.Validate(); err == nil {
		t.Fatal("capture role reused runtime TLS key")
	}
	copied := seed.Clone()
	private := [][]byte{copied.Files[CapturePrivateKeyPath], copied.Files[RegionalCaptureNKeyPath], copied.Files[GlobalCaptureNKeyPath]}
	copied.Clear()
	for _, data := range private {
		for _, value := range data {
			if value != 0 {
				t.Fatal("source capture credential survived clear")
			}
		}
	}
}

func TestPreliminaryCaptureCapacityRefusesPartialAndOverflowInputs(t *testing.T) {
	for _, declaration := range []PreliminaryCaptureDeclaration{{}, {MaxSnapshotBytes: 1024}, {MaxTotalBytes: 1024}, {MaxSnapshotBytes: 2048, MaxTotalBytes: 1024}, {MaxSnapshotBytes: math.MaxInt64, MaxTotalBytes: math.MaxInt64}, {MaxSnapshotBytes: 1024, MaxTotalBytes: math.MaxInt64}} {
		if err := declaration.Validate(); err == nil {
			t.Fatal("invalid capture capacity accepted")
		}
	}
}
