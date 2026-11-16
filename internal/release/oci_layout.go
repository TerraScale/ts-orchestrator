package release

// ContainerImage retains the producer's immutable index and selected child.
// Image always names the executable child, never a platform index or a tag.
type ContainerImage struct {
	Image          string
	Index          []byte
	IndexSHA256    string
	ManifestSHA256 string
	Architecture   string
}
