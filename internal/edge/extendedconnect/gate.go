package extendedconnect

import "os"

var godebug, hasGodebug = os.LookupEnv("GODEBUG")

func init() { _ = os.Setenv("GODEBUG", godebug+",http2xconnect=1") }

func Restore() {
	if hasGodebug {
		_ = os.Setenv("GODEBUG", godebug)
		return
	}
	_ = os.Unsetenv("GODEBUG")
}
