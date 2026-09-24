package de.visiongaia.gedefense.mobile

import android.os.Bundle
import android.view.WindowManager
import com.journeyapps.barcodescanner.CaptureActivity

/**
 * Local-only QR capture boundary for WireGuard profile import.
 *
 * The embedded scanner keeps the private WireGuard configuration inside GeDefense instead of
 * delegating the QR image or decoded private key to Google Play Services or a third-party scanner
 * application. FLAG_SECURE prevents screenshots/recents capture while the scanner is visible.
 */
class WireGuardQrScannerActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }
}
