package bootstrapstart

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"golang.org/x/sys/unix"
)

func TestPrivilegedBrokerMaterialKeepsRootCustodyAcrossWriters(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root and service ownership requires root")
	}
	for _, writer := range []string{"install", "stage", "replace"} {
		t.Run(writer, func(t *testing.T) {
			directory := t.TempDir()
			fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			store := MaterialStore{serviceUID: 65534, serviceGID: 65534}
			content := []byte("exact secret bytes")
			for _, name := range []string{"system.creds", "membership.creds", "controller-account-signer.seed", "controller-tls-issuer-key.pem", "controller-a.creds"} {
				switch writer {
				case "install":
					err = store.installMaterial(fd, name, content, digest(content), 128)
				case "stage":
					err = store.writeStaged(fd, name, content)
				case "replace":
					if err := os.WriteFile(filepath.Join(directory, name), []byte("old material"), 0o600); err != nil {
						t.Fatal(err)
					}
					err = store.replaceStaged(fd, name, content)
				}
				if err != nil {
					t.Fatal(err)
				}
				var stat unix.Stat_t
				if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					t.Fatal(err)
				}
				wantOwner := uint32(0)
				if name == "controller-a.creds" {
					wantOwner = 65534
				}
				if stat.Uid != wantOwner || stat.Gid != wantOwner || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 {
					t.Fatalf("%s custody: uid=%d gid=%d mode=%o links=%d", name, stat.Uid, stat.Gid, stat.Mode&0o7777, stat.Nlink)
				}
				if _, err := readMaterial(fd, name, 65534, 65534, digest(content), 128); err != nil {
					t.Fatalf("root exact inventory read %s: %v", name, err)
				}
				if _, err := readUnpinned(fd, name, 65534, 65534, 128); err != nil {
					t.Fatalf("root restore read %s: %v", name, err)
				}
			}
		})
	}
}

func TestBrokerCredentialExpiriesRequireExactPinsAndRootCustody(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root broker observation requires root")
	}
	install := newGenerationInstall(t)
	install.adopt(install.material, install.expected, install.rootKey)
	views, err := install.store().BrokerCredentialExpiries(t.Context(), install.accepted, install.roots)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.ParseDecoratedJWT(install.material.Files["system.creds"])
	if err != nil {
		t.Fatal(err)
	}
	user, err := jwt.DecodeUserClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Name != "nats system credentials" || views[0].Kind != "nats-jwt" ||
		!views[0].NotAfter.Equal(time.Unix(user.Expires, 0).UTC()) {
		t.Fatalf("public SYSTEM expiry = %+v", views)
	}
	if _, err := install.store().BrokerCredentialExpiries(t.Context(), install.accepted, newGenerationInstall(t).roots); err == nil {
		t.Fatal("accepted an adopted generation under foreign roots")
	}
	path := filepath.Join(install.dir, "system.creds")
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := install.store().BrokerCredentialExpiries(t.Context(), install.accepted, install.roots); err == nil {
		t.Fatal("accepted service-owned SYSTEM credentials")
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replaced credentials"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := install.store().BrokerCredentialExpiries(t.Context(), install.accepted, install.roots); err == nil {
		t.Fatal("accepted SYSTEM bytes differing from signed pins")
	}
}
