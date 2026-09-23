package com.penumbraos.hook

import android.util.Log

/** Hooks for the music experience APK (`humane.experience.music`). */
object MusicHooks {

    private const val TAG = "PenumbraHook"

    fun install(cl: ClassLoader) {
        Log.w(TAG, "Installing music hooks...")

        TcmSilencer.install(cl)

        ConnectivityCheckBypass.install(cl)

        TidalAuthBypass.install(cl)

        EndpointTypeBypass.install(cl)

        Log.w(TAG, "Music hooks installed")
    }
}
