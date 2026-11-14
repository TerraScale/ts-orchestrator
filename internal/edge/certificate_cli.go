package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/acme/autocert"
)

func RunCertificateCLI(ctx context.Context, args []string, output io.Writer) error {
	if len(args) != 5 || args[0] != "repair" || args[1] != "--state" || (args[4] != "ecdsa" && args[4] != "rsa") {
		return errors.New("usage: ts-orch edge certificates repair --state <directory> <name> <ecdsa|rsa>")
	}
	state, name := args[2], args[3]
	if strings.ContainsAny(name, "/\\+") || name == "" || strings.ToLower(name) != name {
		return errors.New("edge: invalid certificate name")
	}
	key := name
	if args[4] == "rsa" {
		key += "+rsa"
	}
	conn, seed, err := mesh.EdgeCertificateClient(ctx, state)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer clear(seed)
	cache := &certificateCache{local: autocert.DirCache(filepath.Join(state, "edge-certs")), source: func() (*nats.Conn, []byte, error) { return conn, append([]byte(nil), seed...), nil }}
	defer cache.stopWatch()
	if err := cache.repair(ctx, key); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "repaired", name, args[4])
	return err
}
