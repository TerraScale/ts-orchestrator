package extendedconnect

import (
	"os"
	"strings"
)

var godebug, hasGodebug = os.LookupEnv("GODEBUG")

func init() {
	if strings.Contains(godebug, "http2xconnect=") {
		return
	}
	_ = os.Setenv("GODEBUG", strings.TrimPrefix(godebug+",http2xconnect=1", ","))
}

func Restore() {
	if hasGodebug {
		_ = os.Setenv("GODEBUG", godebug)
		return
	}
	_ = os.Unsetenv("GODEBUG")
}
