package contracts

// UTF16CodeUnitCount counts UTF-16 code units: protocol length bounds are
// specified in code units, so scalar values outside the basic multilingual
// plane occupy two.
func UTF16CodeUnitCount(value string) int {
	count := 0
	for _, character := range value {
		count++
		if character > 0xFFFF {
			count++
		}
	}
	return count
}
