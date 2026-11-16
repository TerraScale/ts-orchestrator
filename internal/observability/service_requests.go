package observability

import "sync"

var serviceRequests = struct {
	sync.Mutex
	counts map[string]uint64
}{counts: make(map[string]uint64)}

func RecordServiceRequest(service string) {
	serviceRequests.Lock()
	defer serviceRequests.Unlock()
	if _, exists := serviceRequests.counts[service]; exists {
		serviceRequests.counts[service]++
	}
}

func ServiceRequestCounts() map[string]uint64 {
	serviceRequests.Lock()
	defer serviceRequests.Unlock()
	result := make(map[string]uint64, len(serviceRequests.counts))
	for service, count := range serviceRequests.counts {
		result[service] = count
	}
	return result
}

func SetServiceRequestRoutes(routes map[string]string) {
	serviceRequests.Lock()
	defer serviceRequests.Unlock()
	counts := make(map[string]uint64, len(routes))
	for _, service := range routes {
		counts[service] = serviceRequests.counts[service]
	}
	serviceRequests.counts = counts
}
