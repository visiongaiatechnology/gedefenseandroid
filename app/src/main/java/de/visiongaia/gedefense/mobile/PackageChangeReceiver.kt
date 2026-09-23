package de.visiongaia.gedefense.mobile

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class PackageChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart?.takeIf { it.isNotBlank() } ?: return
        val action = intent.action ?: return
        val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
        val pending = goAsync()
        AppRuntime.executeWhenReady(context) { runtime ->
            if (runtime == null || !runtime.setup.isWizardCompleted()) {
                pending.finish()
                return@executeWhenReady
            }
            if (!runtime.executeBackground("package-change") {
                try {
                    runtime.installGuard.handlePackageEvent(packageName, action, replacing, runtime.threatIndex.get())
                    runtime.notifyStateChanged()
                } finally {
                    pending.finish()
                }
            }) pending.finish()
        }
    }
}
