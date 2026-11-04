package cli

type failedBootstrapOutput struct {
	err error
}

func (output failedBootstrapOutput) Write(contents []byte) (int, error) {
	return 0, output.err
}
