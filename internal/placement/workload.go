package placement

import (
	"errors"
)

var (
	ErrInvalidWorkload      = errors.New("invalid workload placement request")
	ErrInsufficientCapacity = errors.New("insufficient workload placement capacity")
)

// Resources are integer CPU cores and bytes. Zero-valued host capacity is
// unknown capacity and therefore cannot satisfy a positive request.
type Resources struct {
	CPU         int   `json:"cpu"`
	MemoryBytes int64 `json:"memory_bytes"`
	DiskBytes   int64 `json:"disk_bytes"`
}

func validToken(value string) bool {
	if len(value) == 0 || len(value) > 63 || !isLowerAlphaNumeric(value[0]) || !isLowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for i := 1; i < len(value)-1; i++ {
		if !isLowerAlphaNumeric(value[i]) && value[i] != '-' {
			return false
		}
	}
	return true
}

func isLowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
