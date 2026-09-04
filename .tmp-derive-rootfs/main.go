package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

func main() {
	preparer := vmimage.Ext4Preparer{
		DebugFSPath: "/nix/store/3llrnwchkvcxgnrr604fhkvcmrlbrk2q-e2fsprogs-1.47.4-bin/bin/debugfs",
		E2FSCKPath:  "/nix/store/3llrnwchkvcxgnrr604fhkvcmrlbrk2q-e2fsprogs-1.47.4-bin/bin/e2fsck",
	}
	for _, path := range os.Args[1:] {
		inspection, err := preparer.Prepare(context.Background(), path, "24.04.3")
		if err != nil {
			panic(err)
		}
		file, err := os.Open(path)
		if err != nil {
			panic(err)
		}
		digest := sha256.New()
		if _, err := io.Copy(digest, file); err != nil {
			panic(err)
		}
		if err := file.Close(); err != nil {
			panic(err)
		}
		fmt.Printf("%s %x %+v\n", path, digest.Sum(nil), inspection)
	}
}
