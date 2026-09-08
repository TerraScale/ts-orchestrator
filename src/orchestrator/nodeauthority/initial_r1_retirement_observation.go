package nodeauthority

import (
	"context"
	"errors"
)

// Retirement returns only the exact irreversible record for this original
// identity. A visible rename is synced before being accepted as cut authority.
func (g *InitialR1Guard) Retirement(ctx context.Context) (InitialR1Retirement, error) {
	if g == nil || ctx == nil {
		return InitialR1Retirement{}, errors.New("nodeauthority: retirement observation requires original guard")
	}
	dir, lock, _, err := g.lock(ctx, false, false)
	if err != nil {
		return InitialR1Retirement{}, err
	}
	defer dir.Close()
	defer lock.Close()
	record, err := g.read(dir)
	if err != nil {
		return InitialR1Retirement{}, err
	}
	if record.Retirement == nil {
		return InitialR1Retirement{}, errors.New("nodeauthority: source is not retired")
	}
	if err := dir.Sync(); err != nil {
		return InitialR1Retirement{}, err
	}
	if err := ctx.Err(); err != nil {
		return InitialR1Retirement{}, err
	}
	return *record.Retirement, nil
}
