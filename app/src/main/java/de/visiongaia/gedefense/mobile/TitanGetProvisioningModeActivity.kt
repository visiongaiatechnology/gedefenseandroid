package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.os.Build
import android.os.Bundle

class TitanGetProvisioningModeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent?.action != DevicePolicyManager.ACTION_GET_PROVISIONING_MODE) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val allowed = intent.getIntegerArrayListExtra(DevicePolicyManager.EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES)
            if (allowed != null && DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE !in allowed) {
                setResult(RESULT_CANCELED)
                finish()
                return
            }
        }

        val result = Intent().putExtra(
            DevicePolicyManager.EXTRA_PROVISIONING_MODE,
            DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE,
        )
        setResult(RESULT_OK, result)
        finish()
    }
}
