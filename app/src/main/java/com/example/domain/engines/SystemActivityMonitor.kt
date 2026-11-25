package com.example.domain.engines

import android.app.ActivityManager
import android.content.Context
import android.net.TrafficStats
import android.os.Process
import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.isActive
import java.io.File
import kotlin.math.ln

data class SystemLoadSnapshot(
    val cpuLoad: Float = 0.18f,
    val networkLoad: Float = 0.12f,
    val networkKbps: Float = 0f,
    val memoryPressure: Float = 0.25f,
    val cpuSource: String = "ProcessCPU"
)

class SystemActivityMonitor(private val context: Context) {

    fun observeSystemLoad(intervalMs: Long = 1200L): Flow<SystemLoadSnapshot> = flow {
        var prevProcCpuMs = Process.getElapsedCpuTime()
        var prevWallMs = SystemClock.elapsedRealtime()
        var prevStat = readProcStatCpu()
        var prevRx = TrafficStats.getTotalRxBytes().takeIf { it >= 0 } ?: 0L
        var prevTx = TrafficStats.getTotalTxBytes().takeIf { it >= 0 } ?: 0L
        val cores = Runtime.getRuntime().availableProcessors().coerceAtLeast(1)

        while (currentCoroutineContext().isActive) {
            delay(intervalMs)

            val nowWallMs = SystemClock.elapsedRealtime()
            val wallDeltaMs = (nowWallMs - prevWallMs).coerceAtLeast(1L)
            prevWallMs = nowWallMs

            // 1. Real CPU activity: try /proc/stat first, fallback to Process.getElapsedCpuTime + memory pressure
            val currentStat = readProcStatCpu()
            val (cpuLoad, sourceLabel) = if (prevStat != null && currentStat != null) {
                val totalDelta = (currentStat.total - prevStat.total).coerceAtLeast(1L)
                val idleDelta = (currentStat.idle - prevStat.idle).coerceAtLeast(0L)
                val util = ((totalDelta - idleDelta).toFloat() / totalDelta.toFloat()).coerceIn(0.05f, 1f)
                prevStat = currentStat
                util to "/proc/stat"
            } else {
                prevStat = currentStat
                val nowProcCpuMs = Process.getElapsedCpuTime()
                val procDelta = (nowProcCpuMs - prevProcCpuMs).coerceAtLeast(0L)
                prevProcCpuMs = nowProcCpuMs
                val procRatio = (procDelta.toFloat() / (wallDeltaMs * cores).toFloat())
                // Blend process CPU usage with real runtime heap activity for responsive feedback
                val rt = Runtime.getRuntime()
                val heapRatio = ((rt.totalMemory() - rt.freeMemory()).toFloat() / rt.maxMemory().coerceAtLeast(1L).toFloat())
                ((procRatio * 2.2f + heapRatio * 0.35f).coerceIn(0.08f, 1f)) to "ProcessCPU"
            }

            // 2. Real Network throughput via TrafficStats
            val nowRx = TrafficStats.getTotalRxBytes().takeIf { it >= 0 } ?: prevRx
            val nowTx = TrafficStats.getTotalTxBytes().takeIf { it >= 0 } ?: prevTx
            val bytesDelta = ((nowRx - prevRx).coerceAtLeast(0L) + (nowTx - prevTx).coerceAtLeast(0L))
            prevRx = nowRx
            prevTx = nowTx

            val bytesPerSec = bytesDelta * (1000f / wallDeltaMs.toFloat())
            val kbps = bytesPerSec / 1024f
            // Logarithmic normalization: 0 KB/s -> ~0.08, 10 KB/s -> ~0.40, 250 KB/s -> ~0.75, 2+ MB/s -> ~1.0
            val netLoad = if (bytesPerSec <= 1f) {
                0.08f
            } else {
                (ln((bytesPerSec / 128f).toDouble() + 1.0) / ln(16384.0)).toFloat().coerceIn(0.08f, 1f)
            }

            // 3. Real System RAM pressure via ActivityManager
            val memPressure = runCatching {
                val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                val info = ActivityManager.MemoryInfo()
                am.getMemoryInfo(info)
                if (info.totalMem > 0) {
                    (1f - (info.availMem.toFloat() / info.totalMem.toFloat())).coerceIn(0.1f, 1f)
                } else 0.3f
            }.getOrDefault(0.3f)

            emit(
                SystemLoadSnapshot(
                    cpuLoad = cpuLoad,
                    networkLoad = netLoad,
                    networkKbps = kbps,
                    memoryPressure = memPressure,
                    cpuSource = sourceLabel
                )
            )
        }
    }.flowOn(Dispatchers.IO)

    private data class ProcStatSample(val total: Long, val idle: Long)

    private fun readProcStatCpu(): ProcStatSample? {
        return try {
            val file = File("/proc/stat")
            if (!file.exists() || !file.canRead()) return null
            val firstLine = file.bufferedReader().use { it.readLine() } ?: return null
            val parts = firstLine.trim().split(Regex("\\s+"))
            if (parts.size < 5 || parts[0] != "cpu") return null
            val nums = parts.drop(1).mapNotNull { it.toLongOrNull() }
            if (nums.size < 4) return null
            val idle = nums[3] + (nums.getOrNull(4) ?: 0L)
            val total = nums.sum()
            ProcStatSample(total = total, idle = idle)
        } catch (_: Exception) {
            null
        }
    }
}
