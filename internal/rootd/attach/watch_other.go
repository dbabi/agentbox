//go:build !linux

package attach

func credEvents(string) (<-chan struct{}, func()) { return nil, func() {} }
