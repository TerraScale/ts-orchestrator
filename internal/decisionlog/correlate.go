package decisionlog

import "sync"

// maxCorrelations bounds the process-wide correlation table.
const maxCorrelations = 4096

// correlations maps a caller-chosen key (for example "release:sha256:..." or
// "managed_update:<operation>") to the ID of the decision that started that
// chain in this process, so a later decision by another slice can name it as
// its parent without both slices sharing state.
var correlations = struct {
	sync.Mutex
	ids   map[string]string
	order []string
}{ids: map[string]string{}}

// Correlate remembers id as the decision for key. The table is bounded;
// the oldest keys are forgotten first.
func Correlate(key, id string) {
	if key == "" || id == "" {
		return
	}
	correlations.Lock()
	defer correlations.Unlock()
	if _, exists := correlations.ids[key]; !exists {
		correlations.order = append(correlations.order, key)
	}
	correlations.ids[key] = id
	for len(correlations.order) > maxCorrelations {
		delete(correlations.ids, correlations.order[0])
		correlations.order = correlations.order[1:]
	}
}

// Correlated returns the decision ID remembered for key, or "".
func Correlated(key string) string {
	correlations.Lock()
	defer correlations.Unlock()
	return correlations.ids[key]
}
