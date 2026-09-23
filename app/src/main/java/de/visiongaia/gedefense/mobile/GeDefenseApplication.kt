package de.visiongaia.gedefense.mobile

import android.app.Application
import java.util.concurrent.RejectedExecutionException

// STATUS: PLATIN
class GeDefenseApplication : Application() {
    private val processBootstrap = BoundedExecutors.fixed(
        name = "gedefense-process-bootstrap",
        threads = 1,
        queueCapacity = 4,
    )

    override fun onCreate() {
        super.onCreate()
        TitanVisualMode.refresh(this)
        AppRuntime.initializeAsync(this)
        try {
            processBootstrap.execute {
                ThreatIntelJobs.schedule(this)
                IntegrityJobs.schedule(this)
                ResilienceJobs.schedule(this)
            }
        } catch (_: RejectedExecutionException) {
            // Job scheduling is enrichment. Runtime/security stores remain fail-closed and jobs can
            // be re-established by the boot/package-replaced receiver without blocking app launch.
        }
    }
}
