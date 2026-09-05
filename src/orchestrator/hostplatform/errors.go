// Package hostplatform reads host clock state and controls systemd units.
package hostplatform

// InvalidOperationError reports invalid host utility configuration.
type InvalidOperationError struct{ Message string }

func (e *InvalidOperationError) Error() string { return e.Message }

// InvalidDataError reports invalid host observations.
type InvalidDataError struct{ Message string }

func (e *InvalidDataError) Error() string { return e.Message }
