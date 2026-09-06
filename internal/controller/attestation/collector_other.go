//go:build !linux

package attestation

func NewNativeCollector(CollectorConfig) (Collector, error) { return nil, ErrRejected }
