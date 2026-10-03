package natscell

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// ClientMaterial names the credential files a client presents when it dials.
type ClientMaterial struct {
	CredentialsFile string
	TLS             TLSFiles
}

// clientMaterialSource resolves the files for each connect and reconnect. A
// reloaded set is accepted only when it keeps the pinned NATS user key, so a
// renewal can replace the JWT and certificate but never the identity. A
// failure falls back to the last renewal that was accepted, re-checked, and
// only before the first accepted renewal to the files the process started
// with: after a renewal the startup material may already have expired.
type clientMaterialSource struct {
	static ClientMaterial
	user   string
	reload func() (ClientMaterial, error)
	mu     sync.Mutex
	logged string
	// good is the last accepted renewal and goodTLS the last renewed TLS
	// files that loaded; both are guarded by mu.
	good    *ClientMaterial
	goodTLS *TLSFiles
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
	if err == nil {
		s.mu.Lock()
		s.good = &material
		s.mu.Unlock()
		return material
	}
	s.mu.Lock()
	good := s.good
	s.mu.Unlock()
	if good != nil && s.validate(*good) == nil {
		s.note("NATS client material reload rejected; using the last accepted renewal", err)
		return *good
	}
	s.note("NATS client material reload rejected; using startup credentials", err)
	return s.static
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
		// A partly written file can keep its seed block intact while its JWT
		// is corrupt: reject it here so the startup files are used instead
		// of failing every handshake.
		token, err := nkeys.ParseDecoratedJWT(data)
		if err == nil {
			var claims *jwt.UserClaims
			if claims, err = jwt.DecodeUserClaims(token); err == nil && claims.Subject != s.user {
				err = errors.New("JWT names a different NATS user")
			}
		}
		if err != nil {
			clear(data)
			return fmt.Errorf("reloaded credentials JWT: %w", err)
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
	if err == nil && material != s.static {
		s.mu.Lock()
		s.goodTLS = &material.TLS
		s.mu.Unlock()
	}
	if err != nil && material != s.static {
		s.mu.Lock()
		good := s.goodTLS
		s.mu.Unlock()
		if good != nil && *good != material.TLS {
			if config, goodErr := loadTLS(*good, false); goodErr == nil {
				s.note("reloaded NATS TLS material is unusable; using the last renewed certificate", err)
				return config, nil
			}
		}
		s.note("reloaded NATS TLS material is unusable; using startup certificate", err)
		config, fallbackErr := loadTLS(s.static.TLS, false)
		if fallbackErr != nil {
			return nil, fmt.Errorf("NATS client TLS (reloaded material: %v): %w", err, fallbackErr)
		}
		return config, nil
	}
	if err != nil {
		return nil, fmt.Errorf("NATS client TLS: %w", err)
	}
	return config, nil
}
