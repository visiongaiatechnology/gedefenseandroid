package main

import "sync/atomic"

type flowLimiter struct{ active atomic.Int32 }

func (l *flowLimiter) acquire() bool {
	for {
		current := l.active.Load()
		if current >= maxConcurrentFlows {
			return false
		}
		if l.active.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (l *flowLimiter) release() {
	for {
		current := l.active.Load()
		if current <= 0 {
			return
		}
		if l.active.CompareAndSwap(current, current-1) {
			return
		}
	}
}
