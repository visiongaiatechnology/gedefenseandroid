package main

import "testing"

func TestGlobalUnackedBudget(t *testing.T) {
	m := &tcpManager{}
	chunk := 1024 * 1024
	for i := 0; i < maxTCPGlobalUnackedBytes/chunk; i++ {
		if !m.reserveUnacked(chunk) {
			t.Fatalf("budget refused chunk %d too early", i)
		}
	}
	if m.reserveUnacked(1) {
		t.Fatal("global unacked budget must fail closed at cap")
	}
	m.releaseUnacked(chunk)
	if !m.reserveUnacked(chunk) {
		t.Fatal("released global budget must become reusable")
	}
}

func TestDozePreservesEstablishedFlowLifetimes(t *testing.T) {
	setPowerConstrained(false)
	interactiveTCP := currentTCPIdleTimeout(false)
	interactiveUDP := currentUDPIdleTimeout()
	setPowerConstrained(true)
	defer setPowerConstrained(false)
	if currentTCPIdleTimeout(false) != interactiveTCP {
		t.Fatal("Doze must not force reconnect churn for established TCP flows")
	}
	if currentUDPIdleTimeout() != interactiveUDP {
		t.Fatal("Doze must not force reconnect churn for UDP/QUIC flows")
	}
	if currentTCPIdleTimeout(true) >= tcpHalfOpenTimeout {
		t.Fatal("Doze half-open timeout must remain tighter")
	}
}

func TestPowerGovernorCadence(t *testing.T) {
	setPowerConstrained(false)
	setTelemetryDetailed(true)
	foregroundTelemetry := currentTelemetryInterval(1)
	foregroundIdle := currentTelemetryInterval(0)
	interactiveTCP := currentTCPHousekeepingInterval(false, true)

	setTelemetryDetailed(false)
	backgroundTelemetry := currentTelemetryInterval(1)
	backgroundIdle := currentTelemetryInterval(0)
	if backgroundTelemetry <= foregroundTelemetry {
		t.Fatal("background telemetry must be less frequent than visible telemetry")
	}
	if backgroundIdle <= foregroundIdle {
		t.Fatal("background idle telemetry must wake less often")
	}

	setPowerConstrained(true)
	defer func() {
		setPowerConstrained(false)
		setTelemetryDetailed(false)
	}()
	if currentTelemetryInterval(1) <= backgroundTelemetry {
		t.Fatal("power-constrained telemetry must be less frequent than normal background telemetry")
	}
	if currentTCPHousekeepingInterval(false, true) <= interactiveTCP {
		t.Fatal("power-constrained idle TCP housekeeping must wake less often")
	}
	if currentTCPHousekeepingInterval(true, true) != tcpUrgentSweepInterval {
		t.Fatal("retransmission/half-open security correctness must keep urgent cadence")
	}
	if currentTelemetryInterval(1) > udpIdleTimeout/2 {
		t.Fatal("telemetry governor became excessively stale")
	}
}

func TestTCPHousekeepingCanSleepWhenNoFlows(t *testing.T) {
	setPowerConstrained(false)
	if currentTCPHousekeepingInterval(false, false) != tcpNoFlowSweepInterval {
		t.Fatal("empty TCP table should use the long event-driven sleep interval")
	}
	if currentTCPHousekeepingInterval(true, false) != tcpUrgentSweepInterval {
		t.Fatal("urgent work must override empty-table cadence")
	}
}

func TestTelemetryCadenceScalesWithFlowLoad(t *testing.T) {
	setPowerConstrained(false)
	setTelemetryDetailed(true)
	defer setTelemetryDetailed(false)
	low := currentTelemetryInterval(16)
	high := currentTelemetryInterval(512)
	if high <= low {
		t.Fatal("high-flow telemetry must reduce snapshot frequency")
	}
	if high > telemetryForegroundMaxInterval {
		t.Fatal("foreground telemetry exceeded freshness cap")
	}
}
