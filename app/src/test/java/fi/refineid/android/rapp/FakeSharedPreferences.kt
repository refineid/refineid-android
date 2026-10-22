// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.content.SharedPreferences

/** In-memory preferences for catalog and settings tests. */
internal class FakeSharedPreferences : SharedPreferences {
    val data = mutableMapOf<String, Any?>()

    override fun getAll(): MutableMap<String, *> = HashMap(data)

    override fun getString(
        key: String?,
        defValue: String?,
    ): String? = data[key] as? String ?: defValue

    override fun getStringSet(
        key: String?,
        defValues: MutableSet<String>?,
    ): MutableSet<String>? = (data[key] as? Set<*>)?.filterIsInstance<String>()?.toMutableSet() ?: defValues

    override fun getInt(
        key: String?,
        defValue: Int,
    ): Int = data[key] as? Int ?: defValue

    override fun getLong(
        key: String?,
        defValue: Long,
    ): Long = data[key] as? Long ?: defValue

    override fun getFloat(
        key: String?,
        defValue: Float,
    ): Float = data[key] as? Float ?: defValue

    override fun getBoolean(
        key: String?,
        defValue: Boolean,
    ): Boolean = data[key] as? Boolean ?: defValue

    override fun contains(key: String?): Boolean = data.containsKey(key)

    override fun edit(): SharedPreferences.Editor = Editor(this)

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit

    class Editor(
        private val prefs: FakeSharedPreferences,
    ) : SharedPreferences.Editor {
        private val temp = mutableMapOf<String, Any?>()
        private val removed = mutableSetOf<String>()
        private var clear = false

        override fun putString(
            key: String?,
            value: String?,
        ): SharedPreferences.Editor =
            apply {
                key?.let {
                    temp[it] =
                        value
                }
            }

        override fun putStringSet(
            key: String?,
            values: MutableSet<String>?,
        ): SharedPreferences.Editor =
            apply {
                key?.let {
                    temp[it] =
                        values
                }
            }

        override fun putInt(
            key: String?,
            value: Int,
        ): SharedPreferences.Editor =
            apply {
                key?.let {
                    temp[it] =
                        value
                }
            }

        override fun putLong(
            key: String?,
            value: Long,
        ): SharedPreferences.Editor =
            apply {
                key?.let {
                    temp[it] =
                        value
                }
            }

        override fun putFloat(
            key: String?,
            value: Float,
        ): SharedPreferences.Editor =
            apply {
                key?.let {
                    temp[it] =
                        value
                }
            }

        override fun putBoolean(
            key: String?,
            value: Boolean,
        ): SharedPreferences.Editor =
            apply {
                key?.let {
                    temp[it] =
                        value
                }
            }

        override fun remove(key: String?): SharedPreferences.Editor = apply { key?.let { removed.add(it) } }

        override fun clear(): SharedPreferences.Editor = apply { clear = true }

        override fun commit(): Boolean {
            apply()
            return true
        }

        override fun apply() {
            if (clear) prefs.data.clear()
            removed.forEach { prefs.data.remove(it) }
            prefs.data.putAll(temp)
        }
    }
}
