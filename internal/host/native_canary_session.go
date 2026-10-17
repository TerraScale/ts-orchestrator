//go:build linux

package host

import (
	"context"
	"errors"
	"time"
)

// NativeCanarySession pins a real native host session independently of Swarm.
type NativeCanarySession struct{ current *ContainerGenerationSession }

func (r *Reader) AdmitNativeCanarySession(ctx context.Context, node string) (*NativeCanarySession, error) {
	current, err := r.AdmitContainerGenerationSession(ctx, node)
	if err != nil {
		return nil, err
	}
	return &NativeCanarySession{current: current}, nil
}

func (s *NativeCanarySession) Deadline() time.Time {
	if s == nil || s.current == nil {
		return time.Time{}
	}
	return s.current.Deadline()
}

func (s *NativeCanarySession) Registration() (Registration, error) {
	if s == nil || s.current == nil {
		return Registration{}, errors.New("native canary session is unavailable")
	}
	return s.current.Registration()
}

func (s *NativeCanarySession) Guard(ctx context.Context) error {
	if s == nil || s.current == nil {
		return errors.New("native canary session is unavailable")
	}
	return s.current.Guard(ctx)
}
