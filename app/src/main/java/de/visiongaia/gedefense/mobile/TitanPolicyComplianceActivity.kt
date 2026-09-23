package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.os.Bundle
import java.util.concurrent.RejectedExecutionException

// STATUS: PLATIN
class TitanPolicyComplianceActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent?.action != DevicePolicyManager.ACTION_ADMIN_POLICY_COMPLIANCE) {
            complete(RESULT_CANCELED)
            return
        }

        val appContext = applicationContext
        val packageNameSnapshot = packageName
        val admin = ComponentName(appContext, TitanDeviceAdminReceiver::class.java)
        val organization = getString(R.string.app_name)
        try {
            COMPLIANCE_EXECUTOR.execute {
                val dpm = appContext.getSystemService(DevicePolicyManager::class.java)
                val owner = try {
                    BoundedAndroidCall.call { dpm.isDeviceOwnerApp(packageNameSnapshot) }
                } catch (_: RuntimeException) {
                    false
                }
                if (!owner) {
                    runOnUiThread { complete(RESULT_CANCELED) }
                    return@execute
                }

                // Organization name is presentation metadata. A transient platform failure must not
                // claim ownership failure after Device Owner status itself was verified.
                try {
                    BoundedAndroidCall.call { dpm.setOrganizationName(admin, organization) }
                } catch (_: RuntimeException) {
                    // Explicit best-effort operation: Device Owner verification above is authoritative.
                }
                runOnUiThread { complete(RESULT_OK) }
            }
        } catch (_: RejectedExecutionException) {
            complete(RESULT_CANCELED)
        }
    }

    private fun complete(result: Int) {
        if (isFinishing || isDestroyed) return
        setResult(result)
        finish()
    }

    companion object {
        private val COMPLIANCE_EXECUTOR = BoundedExecutors.direct(
            name = "gedefense-titan-compliance",
            threads = 1,
        )
    }
}
