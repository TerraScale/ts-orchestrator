//go:build ignore

// nkeygen creates per-run NATS user identities for the Firecracker lab.
// It is test tooling and is never included in the orchestrator binary.
package main

import (
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/nats-io/nkeys"
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func main() {
	directory := flag.String("dir", "", "private output directory")
	flag.Parse()
	if *directory == "" || flag.NArg() == 0 {
		fail("usage: go run nkeygen.go --dir PRIVATE_DIR NAME...")
	}
	result := make(map[string]string, flag.NArg())
	for _, name := range flag.Args() {
		if !namePattern.MatchString(name) {
			fail("invalid identity name")
		}
		if _, exists := result[name]; exists {
			fail("duplicate identity name")
		}
		pair, err := nkeys.CreateUser()
		if err != nil {
			fail(err.Error())
		}
		public, err := pair.PublicKey()
		if err != nil {
			pair.Wipe()
			fail(err.Error())
		}
		seed, err := pair.Seed()
		if err != nil {
			pair.Wipe()
			fail(err.Error())
		}
		path := filepath.Join(*directory, name+".nk")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			clear(seed)
			pair.Wipe()
			fail(err.Error())
		}
		_, writeErr := file.Write(seed)
		closeErr := file.Close()
		clear(seed)
		pair.Wipe()
		if writeErr != nil || closeErr != nil {
			fail(fmt.Sprintf("write %s: %v %v", path, writeErr, closeErr))
		}
		persisted, err := os.ReadFile(path)
		if err != nil {
			fail(err.Error())
		}
		parsed, err := nkeys.ParseDecoratedUserNKey(persisted)
		if err != nil {
			clear(persisted)
			fail(fmt.Sprintf("persisted NKey is invalid: %v", err))
		}
		checkedPublic, err := parsed.PublicKey()
		parsed.Wipe()
		clear(persisted)
		if err != nil || checkedPublic != public {
			fail("persisted NKey differs from generated public key")
		}
		result[name] = public
	}
	data, err := json.Marshal(result)
	if err != nil {
		fail(err.Error())
	}
	fmt.Println(string(data))
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
