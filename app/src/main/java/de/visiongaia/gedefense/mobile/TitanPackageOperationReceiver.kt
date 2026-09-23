package de.visiongaia.gedefense.mobile

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller

class TitanPackageOperationReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_UNINSTALL_RESULT) return
        val data = intent.data ?: return
        if (data.scheme != RESULT_SCHEME || data.authority != RESULT_AUTHORITY || data.pathSegments.size != 2) return
        val packageName = data.pathSegments[0].take(180)
        val nonce = data.pathSegments[1]
        if (!PACKAGE_PATTERN.matches(packageName) || !NONCE_PATTERN.matches(nonce)) return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val detail = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty().take(240)
        val pending = goAsync()
        AppRuntime.executeWhenReady(context) { runtime ->
            if (runtime == null) {
                pending.finish()
                return@executeWhenReady
            }
            if (!runtime.executeBackground("titan-package-result") {
                try {
                    try {
                runtime.xdr.recordTitanPackageRemoval(packageName, status == PackageInstaller.STATUS_SUCCESS, status, detail)
            } catch (error: Throwable) {
                runtime.recordXdrFailure("titan_package_removal", error)
            }
                    runtime.notifyStateChanged()
                } finally {
                    pending.finish()
                }
            }) pending.finish()
        }
    }

    companion object {
        const val ACTION_UNINSTALL_RESULT = "de.visiongaia.gedefense.mobile.TITAN_UNINSTALL_RESULT"
        const val RESULT_SCHEME = "gedefense"
        const val RESULT_AUTHORITY = "titan-uninstall-result"
        private val NONCE_PATTERN = Regex("[0-9a-f]{32}")
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")
    }
}
