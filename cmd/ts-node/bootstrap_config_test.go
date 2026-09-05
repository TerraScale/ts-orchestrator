package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapConfigurationRequiresProtectedPairedFiles(t *testing.T) {
	for _, fields := range []string{
		`"bootstrapBeforeNats":true,`,
		`"bootstrapGrantFile":"/etc/grant.json",`,
		`"bootstrapPublicKeyFile":"/etc/bootstrap.pem",`,
		`"bootstrapGrantFile":"relative","bootstrapPublicKeyFile":"/etc/bootstrap.pem",`,
	} {
		data := strings.Replace(minimalConfig, "{", "{"+fields, 1)
		if _, err := loadTsNodeConfiguration(writeConfig(t, data)); err == nil {
			t.Fatal("invalid bootstrap file pair admitted")
		}
	}
	data := strings.Replace(minimalConfig, "{", `{"bootstrapBeforeNats":true,"bootstrapGrantFile":"/etc/grant.json","bootstrapPublicKeyFile":"/etc/bootstrap.pem",`, 1)
	config, err := loadTsNodeConfiguration(writeConfig(t, data))
	if err != nil || config.BootstrapGrantFile != "/etc/grant.json" || !config.BootstrapBeforeNATS {
		t.Fatalf("valid file pair rejected: %v", err)
	}
	path := filepath.Join(t.TempDir(), "grant.json")
	if err = os.WriteFile(path, []byte("signed-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readBootstrapConfigFile(path, 64); err != nil {
		t.Fatal(err)
	}
	if _, err = readBootstrapConfigFile(path, 2); err == nil {
		t.Fatal("oversized grant read")
	}
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err = readBootstrapConfigFile(path, 64); err == nil {
		t.Fatal("writable bootstrap pin admitted")
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = readBootstrapConfigFile(link, 64); err == nil {
		t.Fatal("symlink bootstrap pin admitted")
	}
}
