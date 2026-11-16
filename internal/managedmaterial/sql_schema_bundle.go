package managedmaterial

// InitialSQLTable is one generation-one SQL table with an i64 primary key and
// a text payload. IDs are assigned by the caller before the InitialSpec is
// signed and remain unchanged across retries and credential rotations.
type InitialSQLTable struct {
	TableID       string `json:"table_id"`
	Name          string `json:"name"`
	KeyColumn     string `json:"key_column"`
	PayloadColumn string `json:"payload_column"`
}
