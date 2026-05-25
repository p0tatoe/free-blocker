package dev.michaelylee.freeblocker.core

import android.util.Log

/**
 * This is the blocklist impl, which stores the rules in a set <string>
 */
class DnsFilter {
    private val TAG = "DnsFilter"

    @Volatile
    private var blocklist: Set<String> = emptySet()

    fun updateBlocklist(newBlocklist: Set<String>) {
        this.blocklist = newBlocklist
        Log.d(TAG, "DnsFilter initialized with ${newBlocklist.size} static rules.")
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
        }
    }

    fun shouldBlock(domain: String): Boolean {
        if (domain.isEmpty() || blocklist.isEmpty()) return false

        var candidate = domain.lowercase().trim()

        while (candidate.contains(".")) {
            if (blocklist.contains(candidate)) {
                Log.i(TAG, "Blocked query for: $domain (matched rule: $candidate)")
                return true
            }
            val next = candidate.substringAfter(".")
            // Stop before we reach a bare TLD (e.g. "com") — no blocklist rule
            // will ever be just a TLD, and checking it is unnecessary work.
            if (!next.contains(".")) break
            candidate = next
        }

        return false
    }

    fun clear() {
        this.blocklist = emptySet()
        Log.d(TAG, "DnsFilter memory cleared.")
    }
}