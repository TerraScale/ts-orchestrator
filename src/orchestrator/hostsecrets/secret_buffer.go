package hostsecrets

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
)

// SecretBuffer stores application-owned delivery buffers in locked nondumpable
// memory. Borrow Bytes only until Close; Close must follow all transport reads.
type SecretBuffer struct {
	page []byte
	size int
}

func NewSecretBuffer(size int) (*SecretBuffer, error) {
	if size <= 0 || size > 256<<10 {
		return nil, ErrIdentitySecret
	}
	page, e := unix.Mmap(-1, 0, (size+4095)&^4095, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if e != nil {
		return nil, ErrIdentitySecret
	}
	if unix.Mlock(page) != nil || unix.Madvise(page, unix.MADV_DONTDUMP) != nil {
		unix.Munlock(page)
		unix.Munmap(page)
		return nil, ErrIdentitySecret
	}
	return &SecretBuffer{page, size}, nil
}
func (b *SecretBuffer) Bytes() []byte {
	if b == nil || b.page == nil {
		return nil
	}
	return b.page[:b.size]
}
func (b *SecretBuffer) Close() {
	if b == nil || b.page == nil {
		return
	}
	clear(b.page)
	unix.Munlock(b.page)
	unix.Munmap(b.page)
	b.page = nil
}
func (*SecretBuffer) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[redacted secret buffer]")
}

// SecretRequestBody serializes Read with Close so the caller can close the body
// before unmapping its borrowed buffer, even after an early HTTP response.
func SecretRequestBody(body []byte) io.ReadCloser {
	return &lockedRequestBody{reader: bytes.NewReader(body)}
}
