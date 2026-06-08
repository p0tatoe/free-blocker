package dev.michaelylee.freeblocker.core

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * This is the blocklist impl, which stores the rules in a set <string>
 */
class DnsFilter {
    private val TAG = "DnsFilter"

    @Volatile
    private var blocklist: Set<String> = emptySet()

    var rustProxyCallback: ((List<String>) -> Unit)? = null

    /**
     * Domains whose blocking is temporarily paused.
     * Key = lowercased domain, Value = epoch-millis expiry time
     * ([Long.MAX_VALUE] for indefinite pauses).
     *
     * A paused domain stays in the persisted manual-blocked list but is
     * removed from the live [blocklist] so [shouldBlock] won't match it.
     * When the pause expires (or the user resumes), the domain is moved
     * back into the live blocklist.
     */
    private val pausedDomains = ConcurrentHashMap<String, Long>()

    @Synchronized
    fun updateBlocklist(newBlocklist: Set<String>) {
        this.blocklist = newBlocklist.filter { it.isNotBlank() }.toSet()
        Log.d(TAG, "DnsFilter initialized with ${this.blocklist.size} static rules.")
        rustProxyCallback?.invoke(blocklist.toList())
    }

    /**
     * Adds a single domain to the live blocklist immediately.
     * Used when the user adds a manual blocked domain so it takes effect
     * without waiting for a full blocklist refresh.
     */
    @Synchronized
    fun addDomain(domain: String) {
        val cleaned = domain.lowercase().trim()
        if (cleaned.isNotEmpty()) {
            blocklist = blocklist + cleaned
            Log.d(TAG, "Added domain to live filter: $cleaned (total: ${blocklist.size})")
            rustProxyCallback?.invoke(blocklist.toList())
        }
    }

    /**
     * Removes a single domain from the live blocklist immediately.
     * Used when the user whitelists a domain so it is unblocked without
     * waiting for a full blocklist refresh.
     */
    @Synchronized
    fun removeDomain(domain: String) {
        val cleaned = domain.lowercase().trim()
        if (cleaned.isNotEmpty()) {
            blocklist = blocklist - cleaned
            Log.d(TAG, "Removed domain from live filter: $cleaned (total: ${blocklist.size})")
            rustProxyCallback?.invoke(blocklist.toList())
        }
    }

    // -------------------------------------------------------------------------
    // Per-domain pause
    // -------------------------------------------------------------------------

    /**
     * Pauses blocking for [domain] until [expiresAt] epoch millis.
     * Use [Long.MAX_VALUE] for an indefinite pause.
     *
     * The domain is removed from the live blocklist so [shouldBlock] will
     * not match it.  It remains in the persisted manual-blocked list so
     * the user can resume later.
     */
    @Synchronized
    fun pauseDomain(domain: String, expiresAt: Long) {
        val cleaned = domain.lowercase().trim()
        if (cleaned.isNotEmpty()) {
            pausedDomains[cleaned] = expiresAt
            blocklist = blocklist - cleaned
            Log.d(TAG, "Paused domain: $cleaned until ${if (expiresAt == Long.MAX_VALUE) "indefinitely" else expiresAt}")
            rustProxyCallback?.invoke(blocklist.toList())
        }
    }

    /**
     * Resumes blocking for a previously paused [domain].
     * The domain is re-added to the live blocklist.
     */
    @Synchronized
    fun resumeDomain(domain: String) {
        val cleaned = domain.lowercase().trim()
        if (cleaned.isNotEmpty()) {
            pausedDomains.remove(cleaned)
            blocklist = blocklist + cleaned
            Log.d(TAG, "Resumed domain: $cleaned (total: ${blocklist.size})")
            rustProxyCallback?.invoke(blocklist.toList())
        }
    }

    @Synchronized
    fun clear() {
        this.blocklist = emptySet()
        pausedDomains.clear()
        Log.d(TAG, "DnsFilter memory cleared.")
        rustProxyCallback?.invoke(blocklist.toList())
    }

    fun getBlocklist(): List<String> = blocklist.toList()
}