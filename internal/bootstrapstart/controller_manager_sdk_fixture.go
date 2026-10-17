//go:build fixturetest

package bootstrapstart

import (
	"net/http"
	"slices"
	"sync"
)

type controllerManagerSDKState struct {
	mu        sync.Mutex
	instances map[string]InstanceObservation
}

func (state *controllerManagerSDKState) lookup(request *http.Request) (InstanceObservation, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	for id, observed := range state.instances {
		if request.URL.Path == "/20160918/instances/"+id || request.URL.Path == "/20160918/vnics/"+observed.PrimaryVNICOCID ||
			request.URL.Path == "/20160918/subnets/"+observed.SubnetOCID || request.URL.Path == "/20160918/vnicAttachments" && request.URL.Query().Get("instanceId") == id {
			observed.NSGOCIDs = slices.Clone(observed.NSGOCIDs)
			return observed, true
		}
	}
	return InstanceObservation{}, false
}
