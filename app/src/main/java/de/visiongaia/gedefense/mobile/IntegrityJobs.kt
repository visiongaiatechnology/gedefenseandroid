package de.visiongaia.gedefense.mobile

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context

object IntegrityJobs {
    private const val JOB_ID = 0x4745
    fun schedule(context: Context) {
        val scheduler = context.getSystemService(JobScheduler::class.java)
        val info = JobInfo.Builder(JOB_ID, ComponentName(context, IntegrityJobService::class.java))
            .setPersisted(true)
            .setPeriodic(6L * 60L * 60L * 1000L, 30L * 60L * 1000L)
            .build()
        scheduler.schedule(info)
    }
}
