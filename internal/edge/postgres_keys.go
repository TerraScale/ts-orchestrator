package edge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
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

type postgresActivity struct {
	pending       atomic.Int64
	idle          *time.Timer
	authenticated func()
}

func (a *postgresActivity) ready() {
	if a.authenticated != nil {
		a.authenticated()
		a.authenticated = nil
	}
	if a.pending.Add(-1) == 0 {
		a.idle.Reset(postgresIdleTimeout)
	}
}

type postgresObserver struct {
	head     [5]byte
	key      func([8]byte) error
	activity *postgresActivity
	data     [8]byte
	n        int
	left     uint32
	keyed    bool
}

func (s *postgresObserver) Write(p []byte) (int, error) {
	length := len(p)
	if length > 0 && s.activity.pending.Load() == 0 {
		s.activity.idle.Reset(postgresIdleTimeout)
	}
	for len(p) > 0 {
		if s.n < len(s.head) {
			n := copy(s.head[s.n:], p)
			s.n += n
			p = p[n:]
			if s.n < len(s.head) {
				continue
			}
			frame := binary.BigEndian.Uint32(s.head[1:])
			if frame < 4 || frame > 1<<31-1 {
				return 0, errors.New("edge: invalid postgres frame")
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
				if s.keyed {
					return 0, errors.New("edge: duplicate postgres backend key")
				}
				if err := s.key(s.data); err != nil {
					return 0, err
				}
				s.keyed = true
			}
			if s.head[0] == 'Z' {
				if binary.BigEndian.Uint32(s.head[1:]) != 5 {
					return 0, errors.New("edge: invalid postgres ready frame")
				}
				s.activity.ready()
			}
			s.n = 0
		}
	}
	return length, nil
}

type postgresInput struct {
	io.Reader
	activity *postgresActivity
	skip     uint32
	head     [5]byte
	n        int
	left     uint32
	extended bool
}

func (r *postgresInput) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n == 0 {
		return n, err
	}
	r.activity.idle.Stop()
	data := p[:n]
	skipped := min(int(r.skip), len(data))
	r.skip -= uint32(skipped)
	data = data[skipped:]
	for len(data) > 0 {
		if r.n < len(r.head) {
			copied := copy(r.head[r.n:], data)
			r.n += copied
			data = data[copied:]
			if r.n < len(r.head) {
				continue
			}
			length := binary.BigEndian.Uint32(r.head[1:])
			if length < 4 || length > 1<<31-1 {
				return 0, errors.New("edge: invalid postgres frontend frame")
			}
			r.left = length - 4
			switch r.head[0] {
			case 'Q', 'F':
				r.activity.pending.Add(1)
			case 'S':
				if !r.extended {
					r.activity.pending.Add(1)
				}
				r.extended = false
			case 'P', 'B', 'D', 'E', 'C', 'H':
				if !r.extended {
					r.activity.pending.Add(1)
					r.extended = true
				}
			}
		}
		consumed := min(len(data), int(r.left))
		r.left -= uint32(consumed)
		data = data[consumed:]
		if r.left == 0 {
			r.n = 0
		}
	}
	return n, err
}
