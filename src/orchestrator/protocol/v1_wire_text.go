package protocol

// v1UTF16CodeUnitCount preserves the length bounds of version-one protocol
// material. Unicode scalar values outside the basic multilingual plane occupy
// two code units in that contract.
func v1UTF16CodeUnitCount(value string) int {
	count := 0
	for _, character := range value {
		count++
		if character > 0xFFFF {
			count++
		}
	}
	return count
}
