package app

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
)

func brokerTicketKeys(cfg Config) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if cfg.NATS.Embedded == nil || cfg.Controller.BrokerTicketKeyFile == "" || cfg.NATS.Embedded.TicketPublicKeyFile == "" {
		return nil, nil, errors.New("production broker ticket signing and pinned public keys are required")
	}
	private, err := readPrivateKey(cfg.Controller.BrokerTicketKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read broker ticket signing key: %w", err)
	}
	publicRaw, err := os.ReadFile(cfg.NATS.Embedded.TicketPublicKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read pinned broker ticket key: %w", err)
	}
	public, err := decodePublicKey(string(publicRaw))
	if err != nil || !bytes.Equal(public, private.Public().(ed25519.PublicKey)) {
		return nil, nil, errors.New("pinned broker ticket key does not match the private signer")
	}
	return private, public, nil
}
