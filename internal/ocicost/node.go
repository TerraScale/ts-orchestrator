package ocicost

// OCI Usage API SKUs for compute and balanced boot volumes.
const (
	skuA1OCPU           = "B93297" // Standard - A1, per OCPU hour
	skuA1Memory         = "B93298" // Standard - A1 - Memory, per GB hour
	skuBlockStorage     = "B91961" // Block Volume - Storage, per GB month
	skuBlockPerformance = "B91962" // Block Volume - Performance Units, per VPU per GB month
	hoursPerMonth       = 744
	bootVPUs            = 10 // a boot volume's balanced performance units per GB
)

// NodeMonthlyCents prices one node for a month from the region's unit
// prices: its billing OCPUs and memory every hour and its boot volume's storage and
// performance. known is false while a SKU the node uses has no usage in the
// region yet, the shape is unknown, or an input is invalid. Guest schedulable
// CPUs must not be passed as OCPUs. Always Free usage prices at zero.
func NodeMonthlyCents(prices []Price, shape string, ocpus, memoryGB, bootGB float64) (uint64, bool) {
	// SKU identities: Oracle's public product catalog, checked 2026-10-16.
	// https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/
	var ocpuSKU, memorySKU string
	switch shape {
	case "VM.Standard.A1.Flex":
		ocpuSKU, memorySKU = skuA1OCPU, skuA1Memory
	case "VM.Standard.A2.Flex":
		ocpuSKU, memorySKU = "B109529", "B109530"
	case "VM.Standard.A4.Flex":
		ocpuSKU, memorySKU = "B112145", "B112146"
	case "VM.Standard.E3.Flex":
		ocpuSKU, memorySKU = "B92306", "B92307"
	case "VM.Standard.E4.Flex":
		ocpuSKU, memorySKU = "B93113", "B93114"
	case "VM.Standard.E5.Flex":
		ocpuSKU, memorySKU = "B97384", "B97385"
	case "VM.Standard.E6.Flex":
		ocpuSKU, memorySKU = "B111129", "B111130"
	case "VM.Standard3.Flex":
		ocpuSKU, memorySKU = "B94176", "B94177"
	default:
		return 0, false
	}
	if !(ocpus > 0 && memoryGB > 0 && bootGB > 0) {
		return 0, false
	}
	unit := make(map[string]float64, len(prices))
	for _, price := range prices {
		if _, duplicate := unit[price.SKU]; duplicate || !(price.PerUnit >= 0 && price.PerUnit <= maxUnitPrice) {
			return 0, false
		}
		unit[price.SKU] = price.PerUnit
	}
	ocpu, okOCPU := unit[ocpuSKU]
	memory, okMemory := unit[memorySKU]
	storage, okStorage := unit[skuBlockStorage]
	performance, okPerformance := unit[skuBlockPerformance]
	if !okOCPU || !okMemory || !okStorage || !okPerformance {
		return 0, false
	}
	amount := ocpus*hoursPerMonth*ocpu + memoryGB*hoursPerMonth*memory +
		bootGB*storage + bootGB*bootVPUs*performance
	if !(amount >= 0 && amount <= maxCents/100) {
		return 0, false
	}
	return cents(amount), true
}
