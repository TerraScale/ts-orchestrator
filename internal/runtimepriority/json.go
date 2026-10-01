package runtimepriority

import "encoding/json/v2"

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
