package region

// WorkerBootstrapDerivationV1 authorizes one fixed public enrollment derivation,
// not copying metadata or privileges from a running controller.
const WorkerBootstrapDerivationV1 = "terrascale.worker.bootstrap.v1"

// WorkerProfile is explicit worker authority in the existing root-signed grant.
// Resource references remain logical until independently proven OCI readback.
type WorkerImageSource struct {
	OCIRegion           string `json:"ociRegion"`
	Namespace           string `json:"namespace"`
	Bucket              string `json:"bucket"`
	CurrentObject       string `json:"currentObject"`
	ImageDomain         string `json:"imageDomain"`
	QualificationDomain string `json:"qualificationDomain"`
}

// Optional image receipt and runtime digest fields are seed evidence; launches read the current channel independently.
type WorkerProfile struct {
	ImageSource         WorkerImageSource       `json:"imageSource"`
	Cell                string                  `json:"cell"`
	Environment         string                  `json:"environment"`
	Role                string                  `json:"role"`
	Architecture        string                  `json:"architecture"`
	Shape               string                  `json:"shape"`
	OCPUs               float64                 `json:"ocpus"`
	MemoryGB            float64                 `json:"memoryGb"`
	BootGB              int64                   `json:"bootGb"`
	AvailabilityDomains []string                `json:"availabilityDomains"`
	CompartmentRef      string                  `json:"compartmentRef"`
	SubnetRef           string                  `json:"subnetRef"`
	NSGRef              string                  `json:"nsgRef"`
	ImageReceipt        []byte                  `json:"imageReceipt,omitempty"`
	ImageDelegation     []byte                  `json:"imageDelegation,omitempty"`
	Runtime             string                  `json:"runtime"`
	RuntimeSHA256       string                  `json:"runtimeSha256,omitempty"`
	Bootstrap           WorkerBootstrapTemplate `json:"bootstrap"`
}

type WorkerBootstrapTemplate struct {
	Derivation         string `json:"derivation"`
	MaterialPlanSHA256 string `json:"materialPlanSha256"`
	VaultRef           string `json:"vaultRef"`
	KMSKeyRef          string `json:"kmsKeyRef"`
	// Each admitted instance receives only its own worker bundle, never a source or manager secret.
	RecipientPermission string `json:"recipientPermission"`
}

// WorkerRecipe is the exact launch candidate. Metadata contains public material only.
type WorkerRecipe struct {
	Cell                string            `json:"cell"`
	Environment         string            `json:"environment"`
	Role                string            `json:"role"`
	Architecture        string            `json:"architecture"`
	ImageID             string            `json:"imageId"`
	CompartmentID       string            `json:"compartmentId"`
	SubnetID            string            `json:"subnetId"`
	NSGIDs              []string          `json:"nsgIds"`
	AvailabilityDomains []string          `json:"availabilityDomains"`
	Shape               string            `json:"shape"`
	OCPUs               float64           `json:"ocpus"`
	MemoryGB            float64           `json:"memoryGb"`
	BootGB              int64             `json:"bootGb"`
	Metadata            map[string]string `json:"metadata"`
}
