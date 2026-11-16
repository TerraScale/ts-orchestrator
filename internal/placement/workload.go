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
