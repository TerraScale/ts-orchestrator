// Package errs defines validation errors shared by orchestrator packages.
package errs

// ArgumentError reports invalid caller input.
type ArgumentError struct {
	Param   string
	Message string
}

func (e *ArgumentError) Error() string { return e.Message }

// Argument is the concise call-site name for ArgumentError.
type Argument = ArgumentError

// ArgumentOutOfRangeError reports caller input outside its closed range.
type ArgumentOutOfRangeError struct {
	Param   string
	Message string
}

func (e *ArgumentOutOfRangeError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "value out of range: " + e.Param
}
