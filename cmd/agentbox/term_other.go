//go:build !linux

package main

import "os"

// attach runs on the box (Linux); elsewhere the terminal is left as it is.
func termSize(*os.File) (int, int) { return 24, 80 }
func rawTerm(*os.File) func()      { return func() {} }
