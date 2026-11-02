// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.content.Context
import android.os.Build
import android.provider.Settings
import uniffi.refineid_rapp.rappDisplayNameMaxBytes

/**
 * The name an endpoint sends for itself in `pairing.hello`, `session.ready`
 * and `session.hello` (RAPP v26.11.2 sections 4.3 items 3 and 4, 7.1): 1 to
 * [MAX_BYTES] bytes of UTF-8 holding at least one character that is not
 * white space. A label for people; nothing finds or matches a pairing by it.
 */
internal class RappDisplayName private constructor(
    /** The name as the binding takes it. */
    val text: String,
) {
    override fun equals(other: Any?): Boolean = other is RappDisplayName && text == other.text

    override fun hashCode(): Int = text.hashCode()

    override fun toString(): String = "RappDisplayName"

    companion object {
        /** Most UTF-8 bytes a display name carries (section 7.1). */
        val MAX_BYTES: Int = rappDisplayNameMaxBytes().toInt()

        /** The name [text] states, or null when it is blank or longer than [MAX_BYTES]. */
        fun parse(text: String): RappDisplayName? =
            if (text.isBlank() || text.encodeToByteArray().size > MAX_BYTES) null else RappDisplayName(text)

        /**
         * [text] shortened at a character boundary to at most [MAX_BYTES]
         * bytes of UTF-8, so a long device name still names the device; null
         * when nothing but white space is left.
         */
        fun shortened(text: String): RappDisplayName? {
            var bytes = 0
            val kept = StringBuilder()
            var index = 0
            while (index < text.length) {
                val codePoint = text.codePointAt(index)
                val width = String(Character.toChars(codePoint)).encodeToByteArray().size
                if (bytes + width > MAX_BYTES) break
                kept.appendCodePoint(codePoint)
                bytes += width
                index += Character.charCount(codePoint)
            }
            return parse(kept.toString())
        }
    }
}

/**
 * The role this device takes in RAPP (owner decision recorded in
 * `doc/architecture/0013-rapp-android.md`). The custodian is a phone with
 * NFC; a tablet, and any device without NFC, is a computer: a requester only,
 * never a custodian.
 */
internal enum class RappDeviceRole {
    CUSTODIAN,
    REQUESTER,
    ;

    companion object {
        /**
         * The smallest width, in density-independent pixels, from which a
         * display is a tablet's: the `sw600dp` resource qualifier's bound.
         */
        const val TABLET_SMALLEST_WIDTH_DP = 600

        /**
         * The role of a device with NFC or without ([hasNfc]), whose built-in
         * display is [smallestWidthDp] wide on its narrower side, and that
         * folds or not ([foldable]). A foldable is a phone whichever way it
         * is open, so its role never changes with its hinge.
         */
        fun of(
            hasNfc: Boolean,
            smallestWidthDp: Int,
            foldable: Boolean,
        ): RappDeviceRole {
            val tablet = !foldable && smallestWidthDp >= TABLET_SMALLEST_WIDTH_DP
            return if (hasNfc && !tablet) CUSTODIAN else REQUESTER
        }

        /** The role of the device [context] runs on. */
        fun of(context: Context): RappDeviceRole {
            val packages = context.packageManager
            return of(
                hasNfc = packages.hasSystemFeature(android.content.pm.PackageManager.FEATURE_NFC),
                smallestWidthDp = builtInSmallestWidthDp(context),
                foldable = packages.hasSystemFeature(android.content.pm.PackageManager.FEATURE_SENSOR_HINGE_ANGLE),
            )
        }

        /**
         * The built-in display's narrower side in density-independent
         * pixels: the display itself, never the window, so a split screen
         * does not change the role.
         */
        private fun builtInSmallestWidthDp(context: Context): Int {
            val display =
                context
                    .getSystemService(android.hardware.display.DisplayManager::class.java)
                    ?.getDisplay(android.view.Display.DEFAULT_DISPLAY)
                    ?: return 0
            val mode = display.mode
            val narrowerPx = minOf(mode.physicalWidth, mode.physicalHeight)
            // The device's own density, not the one the user's display size setting chose.
            val densityDpi = android.util.DisplayMetrics.DENSITY_DEVICE_STABLE
            if (densityDpi <= 0) return 0
            return narrowerPx * android.util.DisplayMetrics.DENSITY_DEFAULT / densityDpi
        }
    }
}

/**
 * The name this device gives itself on every pairing and session (RAPP
 * v26.11.2 section 4.3 items 3 and 4): a phone, the custodian, its device
 * name; a tablet, a computer, "Android - " before it, as every computer
 * names its operating system first. The device name is the one the user set
 * in the system settings, or the model name when none is set. Read afresh on
 * every call, so a renamed device carries its new name into the next
 * session.
 */
internal object RappLocalName {
    /** The operating system, which a computer's name starts with. */
    const val OPERATING_SYSTEM = "Android"

    /** What a computer's name starts with (section 4.3 item 3). */
    const val REQUESTER_PREFIX = "$OPERATING_SYSTEM - "

    /**
     * The name of a device whose user-set name is [deviceName] and whose
     * model is [model], in [role]. A device with neither, which Android
     * does not ship, is named by its operating system alone.
     */
    fun of(
        role: RappDeviceRole,
        deviceName: String?,
        model: String,
    ): RappDisplayName {
        val name =
            listOfNotNull(deviceName, model)
                .map(String::trim)
                .firstOrNull(String::isNotEmpty)
                ?: OPERATING_SYSTEM
        val shown =
            when (role) {
                RappDeviceRole.CUSTODIAN -> name
                RappDeviceRole.REQUESTER -> REQUESTER_PREFIX + name
            }
        return checkNotNull(RappDisplayName.shortened(shown))
    }

    /** The name of the device [context] runs on, in the role the application fixed for the process. */
    fun of(context: Context): RappDisplayName =
        of(
            role =
                (context.applicationContext as? fi.refineid.android.RefineIdApplication)?.rappRole
                    ?: RappDeviceRole.of(context),
            deviceName =
                try {
                    Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)
                } catch (_: SecurityException) {
                    null
                },
            model = Build.MODEL.orEmpty(),
        )
}
