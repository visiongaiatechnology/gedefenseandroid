package de.visiongaia.gedefense.mobile

import android.os.SystemClock
import java.util.PriorityQueue
import java.util.concurrent.atomic.AtomicLong

// STATUS: PLATIN
/**
 * Single-owner delayed execution lane with a hard backlog ceiling.
 *
 * ScheduledThreadPoolExecutor uses an unbounded DelayQueue. VPN control work is security-sensitive
 * and must instead fail closed under overload. This scheduler stores at most [capacity] pending
 * tasks and executes them serially on one daemon thread. Shutdown clears queued work atomically.
 */
class BoundedSerialScheduler(
    threadName: String,
    private val capacity: Int,
) : AutoCloseable {
    private data class Task(
        val dueElapsed: Long,
        val sequence: Long,
        val action: () -> Unit,
    ) : Comparable<Task> {
        override fun compareTo(other: Task): Int {
            val due = dueElapsed.compareTo(other.dueElapsed)
            return if (due != 0) due else sequence.compareTo(other.sequence)
        }
    }

    private val lock = Object()
    private val sequence = AtomicLong(0L)
    private val queue = PriorityQueue<Task>()
    @Volatile private var closed = false
    private val worker: Thread

    init {
        require(threadName.length in 1..64)
        require(capacity in 1..1024)
        worker = Thread(::loop, threadName).apply {
            isDaemon = true
            start()
        }
    }

    fun execute(action: () -> Unit): Boolean = schedule(0L, action)

    fun schedule(delayMillis: Long, action: () -> Unit): Boolean {
        require(delayMillis in 0L..24L * 60L * 60L * 1000L) { "delay outside allowed range" }
        val due = saturatingAdd(SystemClock.elapsedRealtime(), delayMillis)
        synchronized(lock) {
            if (closed || queue.size >= capacity) return false
            queue.add(Task(due, sequence.incrementAndGet(), action))
            lock.notifyAll()
            return true
        }
    }

    fun shutdownNow() {
        synchronized(lock) {
            if (closed) return
            closed = true
            queue.clear()
            lock.notifyAll()
        }
        worker.interrupt()
    }

    override fun close() = shutdownNow()

    private fun loop() {
        while (true) {
            var task: Task? = null
            synchronized(lock) {
                while (task == null) {
                    if (closed) return
                    val next = queue.peek()
                    if (next == null) {
                        try {
                            lock.wait()
                        } catch (_: InterruptedException) {
                            if (closed) return
                        }
                    } else {
                        val remaining = next.dueElapsed - SystemClock.elapsedRealtime()
                        if (remaining > 0L) {
                            try {
                                lock.wait(remaining)
                            } catch (_: InterruptedException) {
                                if (closed) return
                            }
                        } else {
                            task = queue.remove()
                        }
                    }
                }
            }
            try {
                task?.action?.invoke()
            } catch (_: Throwable) {
                // Callers own domain failure handling. The serial lane must survive one bad task.
            }
        }
    }

    private fun saturatingAdd(a: Long, b: Long): Long =
        if (Long.MAX_VALUE - a < b) Long.MAX_VALUE else a + b
}
