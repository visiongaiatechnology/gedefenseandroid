package de.visiongaia.gedefense.mobile

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import java.util.concurrent.RejectedExecutionException

/** Restores persisted JobScheduler coverage after reboot/package replacement without blocking the receiver main thread. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return

        val appContext = context.applicationContext
        val pending = goAsync()
        try {
            BOOT_EXECUTOR.execute {
                try {
                    ThreatIntelJobs.schedule(appContext)
                    IntegrityJobs.schedule(appContext)
                    ResilienceJobs.schedule(appContext)
                } finally {
                    pending.finish()
                }
            }
        } catch (_: RejectedExecutionException) {
            pending.finish()
        }
    }

    companion object {
        private val BOOT_EXECUTOR = BoundedExecutors.fixed(
            name = "gedefense-boot-receiver",
            threads = 1,
            queueCapacity = 2,
        )
    }
}
