package dev.michaelylee.freeblocker

import android.content.Context
import dev.michaelylee.freeblocker.core.DnsFilter
import dev.michaelylee.freeblocker.data.BlocklistFetcher
import dev.michaelylee.freeblocker.data.BlocklistRepository
import dev.michaelylee.freeblocker.data.UserPreferences

object ServiceLocator {

    lateinit var dnsFilter: DnsFilter
        private set

    @android.annotation.SuppressLint("StaticFieldLeak")
    lateinit var blocklistRepository: BlocklistRepository
        private set

    fun init(context: Context) {
        if (::dnsFilter.isInitialized) return  // already set up
        val appContext = context.applicationContext
        dnsFilter = DnsFilter()
        blocklistRepository = BlocklistRepository(
            context         = appContext,
            dnsFilter       = dnsFilter,
            userPreferences = UserPreferences(appContext),
            fetcher         = BlocklistFetcher()
        )
    }
}