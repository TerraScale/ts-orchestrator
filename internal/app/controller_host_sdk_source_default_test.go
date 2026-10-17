//go:build !fixturetest

package app

import (
	"context"
	"io"
)

func runSDKFixtureControllerHostSource(context.Context, []string, io.Reader, io.Writer) (bool, error) {
	return false, nil
}
