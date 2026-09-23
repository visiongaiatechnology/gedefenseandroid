package main

import (
	"sync/atomic"
	"time"
)

// powerConstrained is driven by Android screen/Doze/power-save state. It only changes housekeeping
// cadence and idle retention. Policy matching, blocking decisions and critical telemetry are never
// disabled or sampled.
var powerConstrained atomic.Bool
var telemetryDetailed atomic.Bool

func setPowerConstrained(value bool)  { powerConstrained.Store(value) }
func setTelemetryDetailed(value bool) { telemetryDetailed.Store(value) }

func currentTCPIdleTimeout(halfOpen bool) time.Duration {
	// Power saving must not break healthy established application sockets. Reaping them more
	// aggressively while the screen is off causes reconnect storms and can consume *more* power.
	// Only half-open handshakes get a tighter constrained timeout because they have not yet become
	// useful application state.
	if halfOpen {
		if powerConstrained.Load() {
			return tcpDozeHalfOpenTimeout
		}
		return tcpHalfOpenTimeout
	}
	return tcpIdleTimeout
}

func currentUDPIdleTimeout() time.Duration {
	// Preserve established UDP/QUIC/NAT lifetimes across screen/Doze transitions. Battery savings
	// come from event-driven housekeeping and telemetry coalescing, not forced reconnect churn.
	return udpIdleTimeout
}

func currentTCPHousekeepingInterval(urgent bool, hasFlows bool) time.Duration {
	if urgent {
		return tcpUrgentSweepInterval
	}
	if !hasFlows {
		return tcpNoFlowSweepInterval
	}
	if powerConstrained.Load() {
		return tcpConstrainedIdleSweepInterval
	}
	return tcpIdleSweepInterval
}

func currentTelemetryInterval(activeFlows int) time.Duration {
	constrained := powerConstrained.Load()
	detailed := telemetryDetailed.Load() && !constrained
	if activeFlows <= 0 {
		if detailed {
			return telemetryForegroundIdleInterval
		}
		return telemetryBackgroundIdleInterval
	}

	base := telemetryBackgroundInterval
	maxInterval := telemetryBackgroundMaxInterval
	if constrained {
		base = telemetryConstrainedInterval
		maxInterval = telemetryConstrainedMaxInterval
	} else if detailed {
		base = telemetryForegroundInterval
		maxInterval = telemetryForegroundMaxInterval
	}
	return scaleTelemetryInterval(base, maxInterval, activeFlows)
}

func scaleTelemetryInterval(base, maxInterval time.Duration, activeFlows int) time.Duration {
	if activeFlows <= telemetryTargetFramesPerSecond {
		return base
	}
	multiplier := (activeFlows + telemetryTargetFramesPerSecond - 1) / telemetryTargetFramesPerSecond
	interval := base * time.Duration(multiplier)
	if interval > maxInterval {
		return maxInterval
	}
	return interval
}
