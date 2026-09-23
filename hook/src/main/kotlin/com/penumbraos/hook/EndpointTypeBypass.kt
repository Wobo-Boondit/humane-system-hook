package com.penumbraos.hook

import android.util.Log

/**
 * Redirect the music app's Tidal REST client to the local shim by hooking
 * `EndpointType.baseUrl()` and rewriting the API host to our plaintext local
 * server (plaintext sidesteps Tidal's cert pinning). AUTH/LOGIN are left alone.
 */
object EndpointTypeBypass {

    private const val TAG = "PenumbraHook"

    private const val ENDPOINT_TYPE_CLASS =
        "humane.experience.music.provider.tidal.util.EndpointType"

    private const val TIDAL_API_ORIGIN = "https://api.tidal.com"

    const val SHIM_API_BASE = "http://127.0.0.1:8080/tidal-shim"

    fun install(cl: ClassLoader) {
        val clazz = try {
            cl.loadClass(ENDPOINT_TYPE_CLASS)
        } catch (_: ClassNotFoundException) {
            Log.w(TAG, "  $ENDPOINT_TYPE_CLASS not found, skipping Tidal redirect")
            return
        }

        try {
            clazz.getDeclaredMethod("baseUrl").also { it.isAccessible = true }
        } catch (_: NoSuchMethodException) {
            Log.w(TAG, "  EndpointType.baseUrl() missing, skipping Tidal redirect")
            return
        }

        HookUtils.hookMethodAfter(clazz, "baseUrl", emptyArray()) { param ->
            if (param.throwable != null) return@hookMethodAfter
            val original = param.result as? String ?: return@hookMethodAfter
            if (original.startsWith(TIDAL_API_ORIGIN)) {
                val redirected = SHIM_API_BASE + original.removePrefix(TIDAL_API_ORIGIN)
                param.result = redirected
                Log.w(TAG, "  EndpointType.baseUrl() redirected: $original -> $redirected")
            }
        }

        Log.w(TAG, "  Tidal API redirect installed (-> $SHIM_API_BASE)")
    }
}
