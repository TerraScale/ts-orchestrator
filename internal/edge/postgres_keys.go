package edge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
)

// postgresKeys retains at most one key per admitted connection. Each owner is
// distinct even if a restarted backend reuses a key; ambiguous keys fail closed.
type postgresKeys struct {
	mu    sync.Mutex
	keys  map[[8]byte]map[*postgresOwner]struct{}
	count int
}

type postgresOwner struct {
	port       int
	generation [16]byte
}

func (k *postgresKeys) add(key [8]byte, port int) (func(), error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.count == maxPostgresConns {
		return nil, errors.New("edge: postgres key capacity reached")
	}
	owner := &postgresOwner{port: port}
	rand.Read(owner.generation[:])
	if k.keys == nil {
		k.keys = make(map[[8]byte]map[*postgresOwner]struct{})
	}
	if k.keys[key] == nil {
		k.keys[key] = make(map[*postgresOwner]struct{})
	}
	k.keys[key][owner] = struct{}{}
	k.count++
	return sync.OnceFunc(func() {
		k.mu.Lock()
		defer k.mu.Unlock()
		delete(k.keys[key], owner)
		if len(k.keys[key]) == 0 {
			delete(k.keys, key)
		}
		k.count--
	}), nil
}

func (k *postgresKeys) port(key [8]byte) (int, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	owners := k.keys[key]
	if len(owners) == 1 {
		for owner := range owners {
			return owner.port, true
		}
	}
	return 0, false
}

func (k *postgresKeys) find(digest [32]byte) (id [16]byte, matches int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, owners := range k.keys {
		if sha256.Sum256(key[:]) == digest {
			matches += len(owners)
			for owner := range owners {
				id = owner.generation
			}
		}
	}
	return id, matches
}

func (k *postgresKeys) resolve(key [8]byte, id [16]byte) (int, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if owners := k.keys[key]; len(owners) == 1 {
		for owner := range owners {
			return owner.port, owner.generation == id
		}
	}
	return 0, false
}

// postgresStartup observes framing without retaining payloads. TeeReader invokes
// it before forwarding bytes, so the key is registered before a client can cancel.
// Only the fixed eight-byte BackendKeyData body is retained, never auth messages.
type postgresStartup struct {
	head [5]byte
	key  func([8]byte) error
	data [8]byte
	n    int
	left uint32
	done bool
}

func (s *postgresStartup) Write(p []byte) (int, error) {
	length := len(p)
	for len(p) > 0 && !s.done {
		if s.n < len(s.head) {
			n := copy(s.head[s.n:], p)
			s.n += n
			p = p[n:]
			if s.n < len(s.head) {
				continue
			}
			frame := binary.BigEndian.Uint32(s.head[1:])
			if frame < 4 || frame > 1<<20 {
				return 0, errors.New("edge: invalid postgres startup frame")
			}
			s.left = frame - 4
		}
		n := min(len(p), int(s.left))
		if s.head[0] == 'K' && s.left <= 8 && binary.BigEndian.Uint32(s.head[1:]) == 12 {
			copy(s.data[8-int(s.left):], p[:n])
		}
		s.left -= uint32(n)
		p = p[n:]
		if s.left == 0 {
			if s.head[0] == 'K' && binary.BigEndian.Uint32(s.head[1:]) == 12 {
				if err := s.key(s.data); err != nil {
					return 0, err
				}
				s.done = true
			}
			s.done = s.done || s.head[0] == 'Z'
			s.n = 0
		}
	}
	return length, nil
}
