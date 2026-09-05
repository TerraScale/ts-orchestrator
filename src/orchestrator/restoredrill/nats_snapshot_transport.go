package restoredrill

import (
	"errors"
	"strconv"
	"strings"

	"github.com/nats-io/nats.go"
)

const snapshotChunkBytes = 1 << 20

// The pinned server sends numbered full chunks with acknowledgement subjects,
// an optional short tail without a reply, then an empty completion message.
// Validate the reply before publishing anything to a server-supplied subject.
type snapshotTransfer struct {
	stream string
	nonce  string
	index  uint64
	tail   bool
	done   bool
}

func (s *snapshotTransfer) accept(message *nats.Msg) (bool, error) {
	bad := errors.New("restore drill: invalid snapshot chunk protocol")
	if message == nil || s.done {
		return false, bad
	}
	if len(message.Data) == 0 {
		if message.Reply != "" {
			return false, bad
		}
		if s.index == 0 {
			if len(message.Header) != 0 || !s.tail {
				return false, bad
			}
		} else if len(message.Header) != 1 || len(message.Header["Status"]) != 1 || message.Header.Get("Status") != "204" {
			return false, errors.New("restore drill: snapshot transfer did not complete successfully")
		}
		s.done = true
		return true, nil
	}
	if len(message.Header) != 0 || s.tail || len(message.Data) > snapshotChunkBytes {
		return false, bad
	}
	if len(message.Data) < snapshotChunkBytes {
		if message.Reply != "" {
			return false, bad
		}
		s.tail = true
		return false, nil
	}
	parts := strings.Split(message.Reply, ".")
	if len(parts) != 7 || parts[0] != "$JS" || parts[1] != "SNAPSHOT" || parts[2] != "ACK" || parts[3] != s.stream || !snapshotNonce(parts[4]) {
		return false, bad
	}
	size, sizeErr := strconv.ParseUint(parts[5], 10, 64)
	index, indexErr := strconv.ParseUint(parts[6], 10, 64)
	if sizeErr != nil || indexErr != nil || size != uint64(len(message.Data)) || strconv.FormatUint(size, 10) != parts[5] || index != s.index+1 || strconv.FormatUint(index, 10) != parts[6] || s.nonce != "" && s.nonce != parts[4] {
		return false, bad
	}
	s.nonce, s.index = parts[4], index
	return false, nil
}

func snapshotNonce(value string) bool {
	if len(value) != 22 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}
