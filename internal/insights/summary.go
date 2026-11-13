package insights

import (
	"fmt"
	"time"
)

// Summary is a deterministic plain-language account of a window.
type Summary struct {
	Window    time.Duration `json:"window"`
	Scope     string        `json:"scope"`
	Generated time.Time     `json:"generated"`
	// Text is one paragraph.
	Text string `json:"text"`
	// Sentences are Text's parts, for a list rendering.
	Sentences []string `json:"sentences"`
	Decisions int      `json:"decisions"`
	Opened    int      `json:"opened"`
	Resolved  int      `json:"resolved"`
	Open      Counts   `json:"open"`
	// Partial reports that the counts cover only part of the window or
	// scope.
	Partial bool `json:"partial,omitzero"`
}

// WindowPhrase renders a window as "hour", "24 hours" or "15 minutes".
func WindowPhrase(window time.Duration) string {
	switch {
	case window == time.Hour:
		return "hour"
	case window%time.Hour == 0:
		return fmt.Sprintf("%d hours", int(window.Hours()))
	case window%time.Minute == 0:
		return fmt.Sprintf("%d minutes", int(window.Minutes()))
	default:
		return window.String()
	}
}
