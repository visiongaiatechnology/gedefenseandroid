package de.visiongaia.gedefense.mobile

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.os.UserHandle

// STATUS: PLATIN
class TitanDeviceAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        withRuntime(context) { runtime ->
            runtime.xdr.recordTitanLightState(true)
            runtime.notifyStateChanged()
        }
    }

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        withRuntime(context) { runtime ->
            runtime.xdr.recordTitanLightState(false)
            runtime.notifyStateChanged()
        }
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        context.getString(R.string.titan_light_disable_warning)

    override fun onPasswordFailed(context: Context, intent: Intent, user: UserHandle) {
        super.onPasswordFailed(context, intent, user)
        withRuntime(context) { runtime ->
            val attempts = try {
                BoundedAndroidCall.call {
                    context.getSystemService(DevicePolicyManager::class.java).currentFailedPasswordAttempts
                }
            } catch (_: RuntimeException) {
                -1
            }
            runtime.xdr.recordTitanLightPasswordFailure(attempts)
            runtime.notifyStateChanged()
        }
    }

    override fun onPasswordSucceeded(context: Context, intent: Intent, user: UserHandle) {
        super.onPasswordSucceeded(context, intent, user)
        withRuntime(context) { runtime ->
            runtime.xdr.recordTitanLightPasswordSuccess()
            runtime.notifyStateChanged()
        }
    }

    private fun withRuntime(context: Context, action: (AppRuntime) -> Unit) {
        val pending = goAsync()
        AppRuntime.executeWhenReady(context) { runtime ->
            if (runtime == null) {
                pending.finish()
                return@executeWhenReady
            }
            if (!runtime.executeBackground("titan-admin-event") {
                    try {
                        action(runtime)
                    } finally {
                        pending.finish()
                    }
                }
            ) {
                pending.finish()
            }
        }
    }
}
