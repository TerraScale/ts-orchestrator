package capacityinventory

// Reader reads actual regional resources through the shared authenticated SDK
// factory. Public tariffs require no cloud credentials or Usage API history.
type Reader struct {
	endpoint string
}
