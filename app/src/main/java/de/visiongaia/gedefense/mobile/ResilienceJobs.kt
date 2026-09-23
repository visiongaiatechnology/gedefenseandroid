package de.visiongaia.gedefense.mobile

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context

// STATUS: PLATIN
/** Periodic local-only reconciliation. Immediate VPN transport recovery remains event-driven. */
object ResilienceJobs {
    private const val JOB_ID = 0x4746
    private const val PERIOD_MS = 2L * 60L * 60L * 1000L
    private const val FLEX_MS = 30L * 60L * 1000L

    fun schedule(context: Context) {
        val scheduler = context.getSystemService(JobScheduler::class.java)
        val info = JobInfo.Builder(JOB_ID, ComponentName(context, ResilienceJobService::class.java))
            .setPersisted(true)
            .setPeriodic(PERIOD_MS, FLEX_MS)
            .build()
        scheduler.schedule(info)
    }
}
