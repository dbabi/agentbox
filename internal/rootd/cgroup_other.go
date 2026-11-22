//go:build !linux

package rootd

import "errors"

func watchEvents(string) <-chan struct{} { return make(chan struct{}) }

func makeTaskDir(string, string, uint32) error { return errors.New("rootd runs on Linux only") }
