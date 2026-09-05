//go:build unix

package globalclient

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestConnectRevalidatesDescriptorSnapshotAfterAdmission(t *testing.T) {
	for _, mode := range []string{"seed permissions", "seed symlink", "TLS symlink", "ancestor symlink", "seed FIFO", "TLS FIFO", "oversized seed"} {
		t.Run(mode, func(t *testing.T) {
			config, _ := clientFixture(t, tls.VersionTLS13)
			plan, err := Admit(config)
			if err != nil {
				t.Fatal(err)
			}
			seed := *config.Authentication.NKeyFile
			switch mode {
			case "seed permissions":
				err = os.Chmod(seed, 0644)
			case "seed symlink", "TLS symlink":
				path := seed
				if mode == "TLS symlink" {
					path = config.Tls.KeyFile
				}
				err = os.Rename(path, path+".real")
				if err == nil {
					err = os.Symlink(path+".real", path)
				}
			case "ancestor symlink":
				parent := filepath.Dir(seed)
				err = os.Rename(parent, parent+".real")
				if err == nil {
					err = os.Symlink(parent+".real", parent)
				}
			case "seed FIFO", "TLS FIFO":
				path := seed
				if mode == "TLS FIFO" {
					path = config.Tls.CaFile
				}
				err = os.Remove(path)
				if err == nil {
					err = unix.Mkfifo(path, 0600)
				}
			case "oversized seed":
				err = os.WriteFile(seed, make([]byte, 4097), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				connection, err := plan.Connect(context.Background())
				if connection != nil {
					connection.Close()
				}
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("unsafe replacement admitted")
				}
			case <-time.After(time.Second):
				t.Fatal("replacement file blocked connection admission")
			}
		})
	}
}
