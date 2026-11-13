package observability

import (
	"io"
	"sync"
	"sync/atomic"
)

var nodeFeatures sync.Map

func SetNodeFeatureAvailable(feature string, available bool) {
	state, _ := nodeFeatures.LoadOrStore(feature, new(atomic.Bool))
	state.(*atomic.Bool).Store(available)
}

func WriteNodeFeatureMetrics(w io.Writer) {
	nodeFeatures.Range(func(feature, state any) bool {
		WriteGauge(w, Series("ts_orch_node_feature_available", "feature", feature.(string)), Bool(state.(*atomic.Bool).Load()))
		return true
	})
}
