package dev.michaelylee.freeblocker

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.michaelylee.freeblocker.core.DnsFilter
import dev.michaelylee.freeblocker.core.DnsProxyServer
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class QuicTest {
    @Test
    fun testQuicResolution() = runBlocking {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val filter = DnsFilter()
        val server = DnsProxyServer(appContext, filter)

        // Raw DNS query for google.com
        val query = byteArrayOf(
            0x12.toByte(), 0x34.toByte(), 0x01.toByte(), 0x00.toByte(), 
            0x00.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 
            0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 
            0x06.toByte(), 'g'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(), 
            'g'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(), 
            0x03.toByte(), 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 
            0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 0x00.toByte(), 0x01.toByte()
        )

        for (i in 1..3) {
            Log.d("QuicTest", "--- Sending query $i ---")
            val start = System.currentTimeMillis()
            val response = server.handleDnsQuery(query)
            val duration = System.currentTimeMillis() - start
            Log.d("QuicTest", "Received response $i of size: ${response.size} in ${duration}ms")
            Thread.sleep(500)
        }
        
        // Wait a little to let logs propagate
        Thread.sleep(1000)
    }
}
