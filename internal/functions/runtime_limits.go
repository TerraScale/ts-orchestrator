package functions

import (
	"bytes"
	"fmt"
)

const maxModuleEntries = 4096

// validateModuleResources bounds decoder allocations before wazero validates the module.
func validateModuleResources(module []byte) error {
	r := moduleResourceReader{data: module}
	if !bytes.Equal(r.take(8), []byte{0, 'a', 's', 'm', 1, 0, 0, 0}) {
		return fmt.Errorf("%w: core module header", ErrInvalid)
	}
	seen := uint16(0)
	totalLocals := uint32(0)
	for len(r.data) != 0 && !r.failed {
		id := r.byte()
		s := moduleResourceReader{data: r.take(r.u32())}
		if id == 0 || id > 12 || seen&(1<<id) != 0 {
			// shortcut: custom and element sections are excluded until their nested allocations are bounded.
			return fmt.Errorf("%w: unsupported or repeated section %d", ErrInvalid, id)
		}
		seen |= 1 << id
		switch id {
		case 1: // Function types, with bounded parameter/result vectors.
			for range s.count(maxModuleEntries) {
				if s.byte() != 0x60 {
					s.failed = true
				}
				for range 2 {
					for range s.count(128) {
						s.valueType()
					}
				}
			}
		case 2: // Only function imports are admitted.
			for range s.count(64) {
				s.name()
				s.name()
				if s.byte() != 0 {
					s.failed = true
				}
				s.u32()
			}
		case 3:
			for range s.count(maxModuleEntries) {
				s.u32()
			}
		case 4:
			for range s.count(1) {
				kind := s.byte()
				if kind != 0x70 && kind != 0x6f {
					s.failed = true
				}
				s.limits(maxModuleEntries, true)
			}
		case 5:
			for range s.count(1) {
				s.limits(MaxMemoryPages, false)
			}
		case 6:
			for range s.count(maxModuleEntries) {
				s.valueType()
				if s.byte() > 1 {
					s.failed = true
				}
				s.constant()
			}
		case 7:
			for range s.count(maxModuleEntries) {
				s.name()
				s.byte()
				s.u32()
			}
		case 8:
			s.u32()
		case 12:
			if s.u32() > maxModuleEntries {
				s.failed = true
			}
		case 9:
			s.failed = true
		case 10:
			for range s.count(maxModuleEntries) {
				size := s.u32()
				if size > 64<<10 {
					s.failed = true
				}
				body := moduleResourceReader{data: s.take(size)}
				locals := uint32(0)
				for range body.count(maxModuleEntries) {
					n := body.u32()
					if n > maxModuleEntries-locals {
						body.failed = true
						break
					}
					locals += n
					body.valueType()
				}
				totalLocals += locals
				if body.failed || totalLocals > 65536 {
					s.failed = true
				}
				// Wazero validates the instruction stream after all declared allocation sizes are bounded.
			}
		case 11:
			for range s.count(maxModuleEntries) {
				flags := s.u32()
				if flags > 2 {
					s.failed = true
				}
				if flags == 2 && s.u32() != 0 {
					s.failed = true
				}
				if flags != 1 {
					s.constant()
				}
				s.take(s.u32())
			}
		}
		if s.failed || len(s.data) != 0 {
			return fmt.Errorf("%w: module section %d resource limit or encoding", ErrInvalid, id)
		}
	}
	if r.failed {
		return fmt.Errorf("%w: truncated module section", ErrInvalid)
	}
	return nil
}

type moduleResourceReader struct {
	data   []byte
	failed bool
}

func (r *moduleResourceReader) take(n uint32) []byte {
	if r.failed || uint64(n) > uint64(len(r.data)) {
		r.failed = true
		return nil
	}
	value := r.data[:n]
	r.data = r.data[n:]
	return value
}

func (r *moduleResourceReader) byte() byte {
	if value := r.take(1); len(value) != 0 {
		return value[0]
	}
	return 0
}

func (r *moduleResourceReader) u32() uint32 {
	var value uint32
	for i := range 5 {
		b := r.byte()
		if r.failed || (i == 4 && b > 15) {
			r.failed = true
			return 0
		}
		value |= uint32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return value
		}
	}
	return 0
}

func (r *moduleResourceReader) count(maximum uint32) uint32 {
	n := r.u32()
	if n > maximum || uint64(n) > uint64(len(r.data)) || r.failed {
		r.failed = true
		return 0
	}
	return n
}

func (r *moduleResourceReader) name() {
	n := r.u32()
	if n > 1024 {
		r.failed = true
	}
	r.take(n)
}

func (r *moduleResourceReader) valueType() {
	switch r.byte() {
	case 0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x70, 0x6f:
	default:
		r.failed = true
	}
}

func (r *moduleResourceReader) limits(maximum uint32, requireMax bool) {
	flags, minimum := r.u32(), r.u32()
	if flags > 1 || minimum > maximum || (requireMax && flags != 1) {
		r.failed = true
	}
	if flags == 1 {
		if max := r.u32(); max > maximum || max < minimum {
			r.failed = true
		}
	}
}

func (r *moduleResourceReader) constant() {
	switch r.byte() {
	case 0x41, 0x42: // Signed integer LEB128; wazero checks its width and value.
		for i := range 10 {
			if b := r.byte(); b&0x80 == 0 {
				break
			} else if i == 9 {
				r.failed = true
			}
		}
	case 0x43:
		r.take(4)
	case 0x44:
		r.take(8)
	case 0x23, 0xd2:
		r.u32()
	case 0xd0:
		r.valueType()
	default:
		r.failed = true
	}
	if r.byte() != 0x0b {
		r.failed = true
	}
}
