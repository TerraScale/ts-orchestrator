package vmcontrolseed

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
)

func TestPublicationIsExplicitSourceOnlySignedCapability(t *testing.T) {
	d := PreliminaryPublicationDeclaration{Identity: ociinstance.Config{Region: "sa-saopaulo-1"}}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "publication.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	declaration, err := LoadPreliminaryPublicationDeclaration(file)
	if err != nil {
		t.Fatal(err)
	}
	defer declaration.Clear()
	guests := []Guest{{ID: "gru-one", Address: "10.77.0.10", MembershipPublicKey: membershipPublic(t)}, {ID: "gru-two", Address: "10.77.0.11", MembershipPublicKey: membershipPublic(t)}}
	materials, err := GenerateGRUWithPreliminaryCapture("publication", guests, PreliminaryCaptureDeclaration{MaxSnapshotBytes: 32 << 20, MaxTotalBytes: 128 << 20, Publication: declaration})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range materials {
			m.Clear()
		}
	}()
	seed := materials["gru-one"]
	c, err := initialgrant.ParseConfig([]byte(seed.Settings))
	if err != nil {
		t.Fatal(err)
	}
	p := c.PreliminaryCapture.Publication
	if p == nil || p.RequestFile != PublicationRequestPath || p.StateDir != PublicationStatePath || p.Journal.NKeySeedFile != PublicationJournalNKeyPath || p.Identity.Region != d.Identity.Region || p.Identity.Qualification != nil {
		t.Fatal("signed publication scope differs")
	}
	var broker struct {
		Accounts map[string]struct {
			Users []struct {
				Nkey        string `json:"nkey"`
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
	if err := json.Unmarshal([]byte(c.Broker.Configuration), &broker); err != nil {
		t.Fatal(err)
	}
	pub, sub := initialcontrol.PublicationJournalPermissions()
	found := 0
	for account, config := range broker.Accounts {
		for _, user := range config.Users {
			if user.Nkey == p.Journal.PublicNKey {
				found++
				if account != RegionalAccount || !reflect.DeepEqual(pub, user.Permissions.Publish.Allow) || !reflect.DeepEqual(sub, user.Permissions.Subscribe.Allow) {
					t.Fatal("journal NKey scope is not exact source regional provider journal")
				}
			}
		}
	}
	if found != 1 {
		t.Fatal("publication journal identity absent or duplicated")
	}
	participant := materials["gru-two"]
	if bytes.Contains([]byte(participant.Settings), []byte(p.Journal.PublicNKey)) {
		t.Fatal("participant received publication scope")
	}
	for _, path := range []string{PublicationJournalNKeyPath, PublicationCertificatePath, PublicationPrivateKeyPath} {
		if _, ok := participant.Files[path]; ok {
			t.Fatal("participant received publication private sideband")
		}
		if len(seed.Files[path]) == 0 || !IsFilePath(path) {
			t.Fatal("source publication sideband missing")
		}
	}
	for _, path := range []string{PublicationJournalNKeyPath, PublicationPrivateKeyPath} {
		if bytes.Contains([]byte(seed.Settings), seed.Files[path]) {
			t.Fatal("private credential embedded in signed config")
		}
	}
	for _, path := range []string{NKeyPath, AuthorityNKeyPath, RegionalCaptureNKeyPath, GlobalCaptureNKeyPath, RegionalProvisionerNKeyPath} {
		if bytes.Equal(seed.Files[path], seed.Files[PublicationJournalNKeyPath]) {
			t.Fatal("provider journal reused credential")
		}
	}
	changed := seed.Clone()
	defer changed.Clear()
	changed.Files[PublicationJournalNKeyPath] = append([]byte(nil), seed.Files[RegionalCaptureNKeyPath]...)
	if err := changed.Validate(); err == nil {
		t.Fatal("journal private identity substitution accepted")
	}
	secret := seed.Files[PublicationPrivateKeyPath]
	seed.Clear()
	for _, v := range secret {
		if v != 0 {
			t.Fatal("publication key survived cleanup")
		}
	}
}

func TestPublicationDeclarationRejectsUnprotectedOrUnknownInput(t *testing.T) {
	raw := []byte(`{"identity":{"region":"sa-saopaulo-1"}}`)
	path := filepath.Join(t.TempDir(), "publication.json")
	for _, data := range [][]byte{append(append([]byte(nil), raw...), '\n'), bytes.Replace(raw, []byte(`"region":`), []byte(`"extra":true,"region":`), 1), bytes.Replace(raw, []byte(`"region":"sa-saopaulo-1"`), []byte(`"region":"sa-saopaulo-1","region":"sa-saopaulo-1"`), 1)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPreliminaryPublicationDeclaration(path); err == nil {
			t.Fatal("noncanonical publication declaration accepted")
		}
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPreliminaryPublicationDeclaration(path); err == nil {
		t.Fatal("unprotected publication input accepted")
	}
}
