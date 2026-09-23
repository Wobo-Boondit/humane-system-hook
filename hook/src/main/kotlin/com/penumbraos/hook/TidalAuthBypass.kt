package com.penumbraos.hook

import android.util.Log
import java.util.concurrent.CompletableFuture

/**
 * Force `TidalUserManager`'s token getters to complete with a non-empty stub so
 * the Tidal client issues REST requests instead of throwing "To play music,
 * please link your music account". The shim ignores the token value.
 */
object TidalAuthBypass {

    private const val TAG = "PenumbraHook"

    private const val TIDAL_USER_MANAGER =
        "humane.experience.music.provider.tidal.auth.TidalUserManager"

    private const val STUB_TOKEN = "penumbra-shim-token"

    fun install(cl: ClassLoader) {
        val clazz = try {
            cl.loadClass(TIDAL_USER_MANAGER)
        } catch (_: ClassNotFoundException) {
            Log.w(TAG, "  $TIDAL_USER_MANAGER not found, skipping Tidal auth bypass")
            return
        }

        var hooked = 0
        for (methodName in listOf("getTokenFromSharedInstance", "fetchToken")) {
            try {
                clazz.getDeclaredMethod(methodName)
            } catch (_: NoSuchMethodException) {
                Log.w(TAG, "  TidalUserManager.$methodName() missing, skipping")
                continue
            }
            HookUtils.hookMethodAfter(clazz, methodName, emptyArray()) { param ->
                if (param.throwable == null) {
                    param.result = CompletableFuture.completedFuture(STUB_TOKEN)
                }
            }
            hooked++
        }

        if (hooked > 0) {
            Log.w(TAG, "  Tidal auth bypass installed (token -> non-empty stub, $hooked getter(s))")
        } else {
            Log.w(TAG, "  No Tidal token getters found, auth bypass inactive")
        }
    }
}
