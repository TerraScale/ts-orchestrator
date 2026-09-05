package initialgrant

import "golang.org/x/sys/unix"

func renamePublishedProof(directory int, name string) error {
	return unix.Renameat2(directory, name, directory, "proof.json", unix.RENAME_NOREPLACE)
}
