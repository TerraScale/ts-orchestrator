package app

import (
	"bufio"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const installedManagerProcessCommand = "installed-manager-process-fixture"

// This test executable waits after exec so root can capture its real witness
// before creating any regional candidate or signed manager observation.
func runInstalledManagerProcessChild() error {
	uid, gid, err := controllerServiceIdentity()
	if err != nil || os.Geteuid() != int(uid) || os.Getegid() != int(gid) || uid == 0 || gid == 0 {
		return errors.New("installed manager fixture requires the real service account")
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		return err
	}
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 16), 16)
	if input.Scan() && input.Text() == "stop" {
		return nil
	}
	if err := input.Err(); err != nil {
		return err
	}
	return errors.New("installed manager fixture requires its supervisor stop")
}
