package dev.michaelylee.freeblocker.data

/**
 * A transient data structure used only by the UI to show the users custom rules
 */

data class FilterRule(
    val domain: String,
    val isEnabled: Boolean
)