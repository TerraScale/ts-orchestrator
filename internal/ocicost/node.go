package ocicost

// The SKUs one A1 node is billed under in OCI usage data.
const (
	skuA1OCPU           = "B93297" // Standard - A1, per OCPU hour
	skuA1Memory         = "B93298" // Standard - A1 - Memory, per GB hour
	skuBlockStorage     = "B91961" // Block Volume - Storage, per GB month
	skuBlockPerformance = "B91962" // Block Volume - Performance Units, per VPU per GB month
	hoursPerMonth       = 744
	bootVPUs            = 10 // a boot volume's balanced performance units per GB
)

// NodeMonthlyCents prices one node for a month from the region's unit
// prices: its OCPUs and memory every hour and its boot volume's storage and
// performance. known is false while a SKU the node uses has no usage in the
// region yet; Always Free usage prices at zero. The result is whole cents.
func NodeMonthlyCents(prices []Price, ocpus, memoryGB, bootGB float64) (uint64, bool) {
	unit := make(map[string]float64, len(prices))
	for _, price := range prices {
		unit[price.SKU] = price.PerUnit
	}
	ocpu, okOCPU := unit[skuA1OCPU]
	memory, okMemory := unit[skuA1Memory]
	storage, okStorage := unit[skuBlockStorage]
	performance, okPerformance := unit[skuBlockPerformance]
	if !okOCPU || !okMemory || !okStorage || !okPerformance {
		return 0, false
	}
	amount := ocpus*hoursPerMonth*ocpu + memoryGB*hoursPerMonth*memory +
		bootGB*storage + bootGB*bootVPUs*performance
	return cents(amount), true
}
