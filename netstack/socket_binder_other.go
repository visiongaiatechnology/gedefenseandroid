//go:build !android && !gdandroidhelper

package main

func bindSocketToUnderlying(_ uintptr, _ uint64) error { return nil }
