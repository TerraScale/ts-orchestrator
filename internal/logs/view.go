package logs

import (
	"errors"
	"time"
)

// The summary's bounds. The minute ring answers "1h" and the hour ring "24h".
const (
	retention        = 24 * time.Hour
	minuteSlots      = 60
	hourSlots        = 24
	maxClassKeys     = 2048
	maxNodesPerClass = 64
	defaultLimit     = 50
	maxLimit         = 500
	maxServiceBytes  = 64
)

// Request is one query of the region's log summary.
type Request struct {
	Version  int    `json:"v"`
	Window   string `json:"window"`
	MinLevel string `json:"min_level"`
	Service  string `json:"service"`
	Limit    int    `json:"limit"`
}

// Reply answers a Request for one region.
type Reply struct {
	Version   int          `json:"v"`
	Region    string       `json:"region"`
	From      time.Time    `json:"from"`
	To        time.Time    `json:"to"`
	Totals    []Total      `json:"totals"`
	Classes   []ReplyClass `json:"classes"`
	Gaps      int          `json:"gaps"`
	Truncated bool         `json:"truncated"`
}

// Total is the records of one service and level in the window.
type Total struct {
	Service string `json:"service"`
	Level   string `json:"level"`
	Count   int    `json:"count"`
}

// ReplyClass is one class in the window, with the nodes that logged it.
type ReplyClass struct {
	Service   string    `json:"service"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	Nodes     []string  `json:"nodes"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Example   string    `json:"example"`
}

// Validate reports whether the query serves the request.
func (r Request) Validate() error {
	switch {
	case r.Version != 1:
		return errors.New("version must be 1")
	case r.Window != "1h" && r.Window != "24h":
		return errors.New("window must be 1h or 24h")
	case !validLevel(r.MinLevel):
		return errors.New("min_level must be DEBUG, INFO, WARN or ERROR")
	case r.Limit < 0 || r.Limit > maxLimit:
		return errors.New("limit must be from 0 to 500")
	case len(r.Service) > maxServiceBytes:
		return errors.New("service must be at most 64 bytes")
	}
	return nil
}
