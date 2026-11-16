package capacityinventory

// SHA256 identifies the original quote, including its observed prices and
// validity interval. A later equal-cost quote has a different identity.
func (q Quote) SHA256() string {
	if q.scopeSHA256 == "" || q.issuedAt.IsZero() || q.expiresAt.IsZero() || len(q.prices) != 4 {
		return ""
	}
	return q.Original().SHA256()
}
