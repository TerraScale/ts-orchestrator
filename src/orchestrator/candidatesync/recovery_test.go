package candidatesync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceRecoveryBeforeScopePublication(t *testing.T) {
	for _, test := range []struct {
		name         string
		file         string
		mode         os.FileMode
		wantRecovery bool
	}{
		{"empty", "", 0, true},
		{"interrupted-write", ".staging-" + strings.Repeat("a", 32), 0600, true},
		{"unknown-file", "foreign", 0600, false},
		{"invalid-temporary-name", ".staging-invalid", 0600, false},
		{"unsafe-temporary-permissions", ".staging-" + strings.Repeat("a", 32), 0644, false},
		{"partial-committed-scope", "scope.json", 0600, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			s, err := newStage(root, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			name := ".reference-" + strings.Repeat("b", 32)
			path := filepath.Join(root, name)
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if test.file != "" {
				if err := os.WriteFile(filepath.Join(path, test.file), []byte("partial"), test.mode); err != nil {
					t.Fatal(err)
				}
			}
			err = recoverReference(t.Context(), s, name, []byte("complete scope"))
			if (err == nil) != test.wantRecovery {
				t.Fatalf("recovery error = %v, want recovery %v", err, test.wantRecovery)
			}
			_, err = os.Stat(path)
			if test.wantRecovery {
				if !os.IsNotExist(err) {
					t.Fatalf("recovered directory remains: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unrecognized directory was not retained: %v", err)
			}
		})
	}
}
