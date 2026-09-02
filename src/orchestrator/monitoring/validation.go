package monitoring

func monitoringCellTokenIsValid(cell string) bool {
	if len(cell) < 1 || len(cell) > 63 || cell[0] == '-' || cell[len(cell)-1] == '-' {
		return false
	}
	for index := 0; index < len(cell); index++ {
		character := cell[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}
