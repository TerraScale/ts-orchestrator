package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nkeys"
)

func hostNATSUserPublicKey(config natscell.Config) (string, error) {
	path := config.CredentialsFile
	if path == "" {
		path = config.NKeySeedFile
	}
	if path == "" {
		return "", errors.New("host NATS credentials are required")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	defer clear(wire)
	if len(wire) == 0 || len(wire) > 64<<10 {
		return "", errors.New("host NATS credentials are missing or too large")
	}
	pair, err := nkeys.ParseDecoratedUserNKey(wire)
	if err != nil {
		return "", fmt.Errorf("parse host NATS user key: %w", err)
	}
	defer pair.Wipe()
	return pair.PublicKey()
}
