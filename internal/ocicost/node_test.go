package ocicost

import "testing"

// liveGRUPrices are the rate window's unit prices for an A1 node in GRU: the
// Always Free OCPU and memory, and the paid boot volume.
var liveGRUPrices = []Price{
	{SKU: skuA1OCPU, PerUnit: 0},
	{SKU: skuA1Memory, PerUnit: 0},
	{SKU: skuBlockStorage, PerUnit: 0.1335},
	{SKU: skuBlockPerformance, PerUnit: 0.0089},
}

func TestNodeMonthlyCents(t *testing.T) {
	paid := []Price{
		{SKU: skuA1OCPU, PerUnit: 0.0134},
		{SKU: skuA1Memory, PerUnit: 0.002},
		{SKU: skuBlockStorage, PerUnit: 0.1335},
		{SKU: skuBlockPerformance, PerUnit: 0.0089},
	}
	tests := []struct {
		name   string
		prices []Price
		want   uint64
		known  bool
	}{
		// Always Free compute leaves only the boot volume: 50 × 0.1335 + 50 × 10 × 0.0089 = 11.125.
		{name: "live GRU", prices: liveGRUPrices, want: 1113, known: true},
		// 4 × 744 × 0.0134 + 24 × 744 × 0.002 + 11.125 = 86.7154.
		{name: "paid A1", prices: paid, want: 8672, known: true},
		{name: "one SKU unseen", prices: liveGRUPrices[1:], want: 0, known: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cents, known := NodeMonthlyCents(tc.prices, "VM.Standard.A1.Flex", 4, 24, 50)
			if cents != tc.want || known != tc.known {
				t.Fatalf("NodeMonthlyCents() = %d, %v, want %d, %v", cents, known, tc.want, tc.known)
			}
		})
	}
}
