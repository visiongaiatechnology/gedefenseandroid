package de.visiongaia.gedefense.mobile

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

// STATUS: PLATIN
/**
 * Central construction helpers for explicitly bounded daemon worker pools.
 *
 * JDK convenience factories such as newFixedThreadPool/newSingleThreadExecutor hide an unbounded
 * LinkedBlockingQueue. Security-sensitive Android work must instead state both worker and backlog
 * limits explicitly so overload becomes observable rejection instead of unbounded memory growth.
 */
object BoundedExecutors {
    fun fixed(name: String, threads: Int, queueCapacity: Int): ThreadPoolExecutor {
        require(name.length in 1..48 && name.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        require(threads in 1..32)
        require(queueCapacity in 1..8192)
        return ThreadPoolExecutor(
            threads,
            threads,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(queueCapacity),
            namedFactory(name),
            ThreadPoolExecutor.AbortPolicy(),
        )
    }

    fun direct(name: String, threads: Int = 1): ThreadPoolExecutor {
        require(name.length in 1..48 && name.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        require(threads in 1..32)
        return ThreadPoolExecutor(
            threads,
            threads,
            0L,
            TimeUnit.MILLISECONDS,
            SynchronousQueue(),
            namedFactory(name),
            ThreadPoolExecutor.AbortPolicy(),
        )
    }

    private fun namedFactory(name: String): ThreadFactory {
        val ids = AtomicInteger(0)
        return ThreadFactory { runnable ->
            Thread(runnable, "$name-${ids.incrementAndGet()}").apply { isDaemon = true }
        }
    }
}
