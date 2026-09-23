package de.visiongaia.gedefense.mobile

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context

object ThreatIntelJobs{
    private const val JOB_ID=0x4744
    fun schedule(context:Context){
        val scheduler=context.getSystemService(JobScheduler::class.java)
        val info=JobInfo.Builder(JOB_ID,ComponentName(context,ThreatIntelJobService::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).setPersisted(true)
            .setPeriodic(60*60*1000L,15*60*1000L).build()
        scheduler.schedule(info)
    }
}
