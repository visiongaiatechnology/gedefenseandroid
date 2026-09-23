package main

import "time"

const (
	maxConcurrentFlows           = 8192
	maxHalfOpenTCP               = 1024
	maxUDPFlows                  = 1024
	maxTelemetryQueue            = 4096
	maxTunWriteQueue             = 4096
	maxWireGuardPacketQueue      = 1024
	maxTCPUpstreamQueue          = 96
	maxTCPUnackedBytes           = 1024 * 1024
	maxTCPGlobalUnackedBytes     = 32 * 1024 * 1024
	maxTCPDialWorkers            = 64
	maxPacketBytes               = 65535
	defaultMSS                   = 1180
	maxTCPSegmentPayload         = 1200
	minWireGuardMTU              = 1280
	maxWireGuardMTU              = 1420
	fullFlowMTU                  = minWireGuardMTU
	maxFragmentDatagrams         = 256
	maxFragmentPiecesPerDatagram = 128
	maxFragmentDatagramBytes     = 65535
	maxFragmentReassemblyBytes   = 8 * 1024 * 1024
	maxDNSObservationBytes       = 4096
)

const (
	tcpDialTimeout                  = 8 * time.Second
	tcpWriteTimeout                 = 10 * time.Second
	tcpIdleTimeout                  = 10 * time.Minute
	tcpHalfOpenTimeout              = 20 * time.Second
	tcpDozeHalfOpenTimeout          = 8 * time.Second
	tcpHandshakeAckTimeout          = 15 * time.Second
	udpIdleTimeout                  = 90 * time.Second
	icmpEchoIdleTimeout             = 60 * time.Second
	retransmitAfter                 = 900 * time.Millisecond
	telemetryForegroundInterval     = 1 * time.Second
	telemetryForegroundMaxInterval  = 5 * time.Second
	telemetryBackgroundInterval     = 5 * time.Second
	telemetryBackgroundMaxInterval  = 30 * time.Second
	telemetryConstrainedInterval    = 15 * time.Second
	telemetryConstrainedMaxInterval = 60 * time.Second
	telemetryForegroundIdleInterval = 10 * time.Second
	telemetryBackgroundIdleInterval = 30 * time.Second
	telemetryTargetFramesPerSecond  = 128
	tcpUrgentSweepInterval          = 1 * time.Second
	tcpIdleSweepInterval            = 15 * time.Second
	tcpConstrainedIdleSweepInterval = 30 * time.Second
	tcpNoFlowSweepInterval          = 5 * time.Minute
	fragmentReassemblyTimeout       = 15 * time.Second
)
