package natscell

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/nats-io/nkeys"
)

// ClientMaterial names the credential files a client presents when it dials.
type ClientMaterial struct {
	CredentialsFile string
	TLS             TLSFiles
}

// clientMaterialSource resolves the files for each connect and reconnect. A
// reloaded set is accepted only when it keeps the pinned NATS user key, so a
// renewal can replace the JWT and certificate but never the identity. Any
// failure falls back to the files the process started with, which remain
// valid until their own expiry.
type clientMaterialSource struct {
	static ClientMaterial
	user   string
	reload func() (ClientMaterial, error)
	mu     sync.Mutex
	logged string
}

func newClientMaterialSource(cfg Config, user string) *clientMaterialSource {
	return &clientMaterialSource{static: ClientMaterial{CredentialsFile: cfg.CredentialsFile, TLS: cfg.TLS},
		user: user, reload: cfg.ReloadClientMaterial}
}

func (s *clientMaterialSource) current() ClientMaterial {
	if s == nil {
		return ClientMaterial{}
	}
	if s.reload == nil {
		return s.static
	}
	material, err := s.reload()
	if err == nil {
		err = s.validate(material)
	}
	if err != nil {
		s.note("NATS client material reload rejected; using startup credentials", err)
		return s.static
	}
	return material
}

func (s *clientMaterialSource) validate(material ClientMaterial) error {
	if s.static.CredentialsFile != "" {
		if material.CredentialsFile == "" {
			return errors.New("reloaded material has no credentials file")
		}
		data, err := readPrivateFile(material.CredentialsFile, 64<<10)
		if err != nil {
			return err
		}
		pair, err := nkeys.ParseDecoratedUserNKey(data)
		clear(data)
		if err != nil {
			return err
		}
		public, err := pair.PublicKey()
		pair.Wipe()
		if err != nil || public != s.user {
			return errors.New("reloaded credentials carry a different NATS user key")
		}
	}
	if s.static.TLS.complete() != material.TLS.complete() {
		return errors.New("reloaded material changes the TLS mode")
	}
	return nil
}

// note logs each distinct rejection once, keeping reconnect storms quiet.
func (s *clientMaterialSource) note(message string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.logged == err.Error() {
		return
	}
	s.logged = err.Error()
	slog.Warn(message, "error", err)
}

func (s *clientMaterialSource) tlsConfig() (*tls.Config, error) {
	material := s.current()
	config, err := loadTLS(material.TLS, false)
	if err != nil && material != s.static {
		s.note("reloaded NATS TLS material is unusable; using startup certificate", err)
		return loadTLS(s.static.TLS, false)
	}
	if err != nil {
		return nil, fmt.Errorf("NATS client TLS: %w", err)
	}
	return config, nil
}
