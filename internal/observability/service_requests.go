package observability

import (
	"sync"
	"sync/atomic"
)

type serviceRequestSeries map[string]*atomic.Uint64

var serviceRequests atomic.Pointer[serviceRequestSeries]
var serviceRequestRoutes sync.Mutex

func RecordServiceRequest(service string) {
	if counts := serviceRequests.Load(); counts != nil {
		if counter := (*counts)[service]; counter != nil {
			counter.Add(1)
		}
	}
}

func ServiceRequestCounts() map[string]uint64 {
	result := make(map[string]uint64)
	if counts := serviceRequests.Load(); counts != nil {
		for service, counter := range *counts {
			result[service] = counter.Load()
		}
	}
	return result
}

func SetServiceRequestRoutes(routes map[string]string) {
	serviceRequestRoutes.Lock()
	defer serviceRequestRoutes.Unlock()
	previous := serviceRequests.Load()
	counts := make(serviceRequestSeries, len(routes))
	for _, service := range routes {
		if previous != nil {
			counts[service] = (*previous)[service]
		}
		if counts[service] == nil {
			counts[service] = new(atomic.Uint64)
		}
	}
	serviceRequests.Store(&counts)
}
