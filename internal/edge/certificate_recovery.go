package edge

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func issuedData(data []byte, state certificateLocalState) []byte {
	data = stripIssuedState(data)
	metadata, _ := json.Marshal(state)
	return append(data, pem.EncodeToMemory(&pem.Block{Type: "EDGE ISSUANCE", Bytes: metadata})...)
}

func stripIssuedState(data []byte) []byte {
	var clean []byte
	for len(data) != 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "EDGE ISSUANCE" {
			clean = append(clean, pem.EncodeToMemory(block)...)
		}
		data = rest
	}
	return clean
}

func issuedState(data []byte) (certificateLocalState, bool) {
	for len(data) != 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "EDGE ISSUANCE" {
			var state certificateLocalState
			err := json.Unmarshal(block.Bytes, &state)
			return state, err == nil
		}
		data = rest
	}
	return certificateLocalState{}, false
}

func (c *certificateCache) completeLocal(ctx context.Context, key string, data []byte, state certificateLocalState) error {
	if err := c.local.Put(ctx, key, stripIssuedState(data)); err != nil {
		return err
	}
	if value, ok := c.memory.Load(key); ok {
		cert := value.(cachedCertificate)
		cert.data = stripIssuedState(cert.data)
		c.memory.Store(key, cert)
	}
	return c.saveState(ctx, key, state)
}

func (c *certificateCache) saveRetry(ctx context.Context, key string, retry certificateRetry) error {
	c.pending.Store(key, retry)
	data, err := json.Marshal(retry)
	if err != nil {
		return err
	}
	return c.local.Put(ctx, ".retry-"+key, data)
}

func (c *certificateCache) publishRetry(ctx context.Context, key string) error {
	pending, ok := c.pending.Load(key)
	if !ok {
		return nil
	}
	retry := pending.(certificateRetry)
	value, revision, err := c.shared(ctx, key)
	if err != nil {
		return err
	}
	if retry.Next.After(value.Retry.Next) {
		value.Retry.Next = retry.Next
		value.Retry.Attempt = max(value.Retry.Attempt, retry.Attempt)
		value.Retry.Updated = maxTime(value.Retry.Updated, retry.Updated)
		if _, err := c.write(ctx, key, value, revision); err != nil {
			return err
		}
	}
	if err := c.local.Delete(ctx, ".retry-"+key); err != nil {
		return err
	}
	c.pending.Delete(key)
	return nil
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func (c *certificateCache) repair(ctx context.Context, key string) error {
	local, err := c.local.Get(ctx, key)
	if err != nil {
		return err
	}
	if _, err := validCertificate(local, key); err != nil {
		return err
	}
	value, revision, readErr := c.shared(ctx, key)
	if readErr != nil && !errors.Is(readErr, errUnsupportedCertificate) {
		return readErr
	}
	if revision == 0 {
		return errors.New("edge: repair requires an existing record")
	}
	if value.Version != "v1" {
		return errors.New("edge: repair refuses an unsupported envelope version")
	}
	if _, err := c.decode(value, key); err == nil || errors.Is(err, autocert.ErrCacheMiss) {
		return errors.New("edge: record does not require repair")
	}
	c.mu.Lock()
	seal, keyID := c.seal, c.keyID
	c.mu.Unlock()
	value.KeyID = keyID
	value.Data = seal.Seal(nil, nil, stripIssuedState(local), []byte(key))
	if _, err := c.write(ctx, key, value, revision); err != nil {
		return err
	}
	c.unsupported.Delete(key)
	return nil
}

func (e *Edge) certificateRoster() (string, []string, error) {
	source, ok := e.meshNode().(interface {
		EdgeCertificateNodes() (string, []string, error)
	})
	if !ok {
		return "", nil, errors.New("edge: certificate roster unavailable")
	}
	return source.EdgeCertificateNodes()
}

func certificateName(key string) string {
	return strings.TrimSuffix(key, "+rsa")
}
