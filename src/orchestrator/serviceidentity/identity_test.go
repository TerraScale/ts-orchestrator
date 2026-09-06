package serviceidentity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapRefusesConflictingLocalIdentityWithoutAccountMutation(t *testing.T) {
	for _, name := range []string{Orchestrator, TerraBase} {
		for _, fault := range []string{"", "uid", "gid", "shell", "socket-group-members"} {
			t.Run(name+"/"+fault, func(t *testing.T) {
				uid, _ := UID(name)
				root := t.TempDir()
				write := func(name, contents string, mode os.FileMode) string {
					p := filepath.Join(root, name)
					if err := os.WriteFile(p, []byte(contents), mode); err != nil {
						t.Fatal(err)
					}
					return p
				}
				passwd := fmt.Sprintf("%s:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", name, uid, uid)
				group := fmt.Sprintf("%s:x:%d:\n%s:x:%d:\n", name, uid, SocketGroup, SocketGID)
				switch fault {
				case "uid":
					passwd = strings.Replace(passwd, fmt.Sprintf(":%d:", uid), ":999:", 1)
				case "gid":
					group = strings.Replace(group, fmt.Sprintf(":%d:", uid), ":999:", 1)
				case "shell":
					passwd = strings.Replace(passwd, "/usr/sbin/nologin", "/bin/sh", 1)
				case "socket-group-members":
					group = strings.TrimSuffix(group, "\n") + "foreign\n"
				}
				passwdFile := write("passwd", passwd, 0600)
				groupFile := write("group", group, 0600)
				getent := write("getent", fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\npasswd) file=%s;;\ngroup) file=%s;;\nesac\n/usr/bin/awk -F: -v key=\"$2\" '$1==key || $3==key {print; found=1;exit} END{if(!found)exit 2}' \"$file\"\n", passwdFile, groupFile), 0700)
				id := write("id", fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %d\n", uid), 0700)
				refuse := write("refuse", "#!/bin/sh\nexit 99\n", 0700)
				script := strings.NewReplacer("/etc/passwd", passwdFile, "/etc/group", groupFile, "/usr/bin/getent", getent, "/usr/bin/id", id, "/usr/sbin/useradd", refuse, "/usr/sbin/groupadd", refuse).Replace(Bootstrap(name))
				output, err := exec.CommandContext(t.Context(), "/bin/sh", "-eu", "-c", script).CombinedOutput()
				if (err == nil) != (fault == "") {
					t.Fatalf("fault %q: err=%v output=%s", fault, err, output)
				}
			})
		}
	}
}

func TestSocketGroupDoesNotExposePrivatePrimaryGroup(t *testing.T) {
	engine := strings.Join(UnitProperties(TerraBase), "\n")
	if engine != "SupplementaryGroups="+SocketGroup {
		t.Fatal(engine)
	}
	server := strings.Join(UnitProperties(Orchestrator), "\n")
	for _, required := range []string{"RuntimeDirectoryMode=0700", "RuntimeDirectoryPreserve=no", "ExecStartPre=/usr/bin/chgrp " + SocketGroup + " " + SocketDirectory, "ExecStartPre=/usr/bin/chmod 0710 " + SocketDirectory} {
		if !strings.Contains(server, required) {
			t.Fatal(server)
		}
	}
	if Bootstrap("foreign") != "" {
		t.Fatal("unknown identity provisioned")
	}
}
