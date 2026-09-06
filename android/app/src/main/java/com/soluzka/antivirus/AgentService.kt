package com.soluzka.antivirus

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import org.json.JSONArray
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.UUID

class AgentService : Service() {

    companion object {
        private const val SERVER_URL = "https://isolation-bytes.com"
        private const val API_KEY = BuildConfig.API_KEY
        private const val CHANNEL_ID = "isolation_bytes_agent"
        private const val NOTIFICATION_ID = 1
        private const val HEARTBEAT_INTERVAL = 30000L // 30 seconds
        private const val SCAN_INTERVAL = 60000L // 60 seconds
        private const val MAX_FILE_SIZE = 50L * 1024 * 1024 // 50 MB
        private const val AGENT_VERSION = "1.8.948.0"
    }

    private lateinit var handler: Handler
    private lateinit var wakeLock: PowerManager.WakeLock
    private var deviceId: String = ""
    private var registered = false
    private var filesScanned = 0
    private var threatsBlocked = 0
    private var quarantinedCount = 0
    private var lastScanFindings: JSONArray = JSONArray()

    // Suspicious file extensions to flag on Android
    private val suspiciousExtensions = setOf(
        ".apk", ".dex", ".jar", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".wsf", ".hta", ".scr", ".pif", ".com", ".msi", ".sh", ".pl",
        ".rb", ".lua", ".php", ".asp", ".jsp"
    )

    // High-risk extensions that should be blocked immediately
    private val highRiskExtensions = setOf(
        ".apk", ".dex", ".jar", ".bat", ".cmd", ".ps1", ".vbs",
        ".hta", ".scr", ".pif", ".com", ".sh"
    )

    private val heartbeatRunnable = object : Runnable {
        override fun run() {
            try {
                sendHeartbeat()
            } catch (e: Exception) {
                // Ignore — will retry next interval
            }
            handler.postDelayed(this, HEARTBEAT_INTERVAL)
        }
    }

    private val scanRunnable = object : Runnable {
        override fun run() {
            try {
                performScan()
            } catch (e: Exception) {
                // Ignore — will retry next interval
            }
            handler.postDelayed(this, SCAN_INTERVAL)
        }
    }

    override fun onCreate() {
        super.onCreate()
        handler = Handler(Looper.getMainLooper())

        // Acquire wake lock so agent keeps running when screen is off
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "IsolationBytes::Agent")
        wakeLock.acquire(24 * 60 * 60 * 1000L) // 24 hours

        // Get or create device ID
        val prefs = getSharedPreferences("isolation_bytes", Context.MODE_PRIVATE)
        deviceId = prefs.getString("device_id", null) ?: run {
            val id = "ANDROID-${UUID.randomUUID().toString().take(8).uppercase()}"
            prefs.edit().putString("device_id", id).apply()
            id
        }

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Register first, then start heartbeats
        Thread {
            try {
                register()
            } catch (e: Exception) {
                // Will retry
            }
        }.start()

        handler.postDelayed(heartbeatRunnable, HEARTBEAT_INTERVAL)
        handler.postDelayed(scanRunnable, SCAN_INTERVAL)
        return START_STICKY // Restart if killed
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        handler.removeCallbacks(heartbeatRunnable)
        handler.removeCallbacks(scanRunnable)
        if (wakeLock.isHeld) wakeLock.release()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Isolation Bytes Agent",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Network monitoring and security reporting"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Isolation Bytes")
            .setContentText("Security monitoring active")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun register() {
        val data = JSONObject().apply {
            put("device_id", deviceId)
            put("hostname", android.os.Build.MODEL)
            put("os", "android")
            put("os_version", android.os.Build.VERSION.RELEASE)
            put("agent_version", AGENT_VERSION)
            put("api_key", API_KEY)
        }
        postJson("$SERVER_URL/agent/register", data)
        registered = true
    }

    private fun sendHeartbeat() {
        if (!registered) {
            register()
            return
        }

        val data = JSONObject().apply {
            put("device_id", deviceId)
            put("cpu_usage", 0)
            put("mem_usage", getMemUsage())
            put("disk_usage", 0)
            put("uptime", getUptime())
            put("files_scanned", filesScanned)
            put("threats_blocked", threatsBlocked)
            put("quarantined_count", quarantinedCount)
            put("scan_dirs", JSONArray().apply {
                put("/storage/emulated/0/Download")
                put("/storage/emulated/0/Documents")
                put("/storage/emulated/0/Pictures")
                put("/storage/emulated/0/Music")
                put("/storage/emulated/0/Movies")
                put("/storage/emulated/0/DCIM")
                put("/storage/emulated/0/Android/data")
            })
            put("network_connections", JSONArray())
            put("network_devices", JSONArray())
            put("processes", JSONArray())
            put("process_count", 0)
            put("connection_count", 0)
            put("flagged_connections", JSONArray())
            put("watched_connections", JSONArray())
            put("flagged_count", 0)
            put("watched_count", 0)
            put("findings", lastScanFindings)
        }
        postJson("$SERVER_URL/agent/heartbeat", data)
    }

    private fun getMemUsage(): Int {
        val mi = android.app.ActivityManager.MemoryInfo()
        val am = getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        am.getMemoryInfo(mi)
        return ((mi.totalMem - mi.availMem) * 100 / mi.totalMem).toInt()
    }

    private fun getUptime(): String {
        val ms = android.os.SystemClock.elapsedRealtime()
        val totalSecs = ms / 1000
        val days = totalSecs / 86400
        val hours = (totalSecs % 86400) / 3600
        val mins = (totalSecs % 3600) / 60
        return "${days}d ${hours}h ${mins}m"
    }

    private fun performScan() {
        val scanDirs = listOf(
            "/storage/emulated/0/Download",
            "/storage/emulated/0/Documents",
            "/storage/emulated/0/Pictures",
            "/storage/emulated/0/Music",
            "/storage/emulated/0/Movies",
            "/storage/emulated/0/DCIM",
            "/storage/emulated/0/Android/data",
            getExternalFilesDir(null)?.absolutePath ?: "",
            filesDir.absolutePath
        ).filter { it.isNotEmpty() && File(it).exists() }

        val findings = JSONArray()
        var scanned = 0

        for (dirPath in scanDirs) {
            try {
                val dir = File(dirPath)
                if (!dir.isDirectory) continue
                dir.walkTopDown().forEach { file ->
                    if (!file.isFile) return@forEach
                    if (file.length() > MAX_FILE_SIZE) return@forEach
                    if (!file.canRead()) return@forEach

                    val ext = file.extension.lowercase()
                    if (ext.isNotEmpty() && ".$ext" in suspiciousExtensions) {
                        val severity = if (".${ext}" in highRiskExtensions) "high" else "medium"
                        val blocked = blockFile(file)
                        val finding = JSONObject().apply {
                            put("path", file.absolutePath)
                            put("severity", severity)
                            put("reason", "Suspicious file extension: .$ext")
                            put("rule", "android_suspicious_ext")
                            put("hash", hashFile(file))
                            put("quarantined", false)
                            put("blocked", blocked)
                        }
                        findings.put(finding)
                        scanned++

                        if (".${ext}" in highRiskExtensions) {
                            threatsBlocked++
                            val qok = quarantineFile(file)
                            if (qok) {
                                finding.put("quarantined", true)
                                quarantinedCount++
                            } else {
                                finding.put("quarantine_error", true)
                            }
                        }
                    }
                    scanned++
                }
            } catch (e: Exception) {
                // Permission denied or similar — skip
            }
        }

        filesScanned += scanned
        lastScanFindings = findings

        // Report findings to cloud
        if (findings.length() > 0) {
            val reportData = JSONObject().apply {
                put("device_id", deviceId)
                put("type", "scan")
                put("files_scanned", scanned)
                put("findings", findings)
                put("quarantined_count", quarantinedCount)
                put("timestamp", System.currentTimeMillis())
            }
            Thread { postJson("$SERVER_URL/agent/report", reportData) }.start()
        }
    }

    private fun blockFile(file: File): Boolean {
        """Block a file by removing all permissions so it can't execute/read/write."""
        return try {
            file.setReadable(false)
            file.setWritable(false)
            file.setExecutable(false)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun unblockFile(file: File): Boolean {
        """Restore permissions on a previously blocked file."""
        return try {
            file.setReadable(true)
            file.setWritable(true)
            file.setExecutable(false)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun quarantineFile(file: File): Boolean {
        """Move a malicious file to the app's private quarantine directory."""
        return try {
            val quarantineDir = File(filesDir, "quarantine")
            if (!quarantineDir.exists()) quarantineDir.mkdirs()
            val hash = hashFile(file).take(16)
            val dest = File(quarantineDir, "${hash}_${file.name}")
            file.copyTo(dest, overwrite = true)
            file.delete()
            // Write metadata sidecar
            val meta = File(quarantineDir, "${hash}_${file.name}.meta")
            meta.writeText("original_path=${file.absolutePath}\nquarantined_at=${System.currentTimeMillis()}\n")
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun hashFile(file: File): String {
        return try {
            val bytes = file.readBytes()
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(bytes)
            digest.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            "unknown"
        }
    }

    private fun postJson(urlStr: String, data: JSONObject) {
        try {
            // Validate URL to prevent SSRF — only HTTPS to our server is allowed
            val parsed = URL(urlStr)
            if (parsed.protocol != "https" || parsed.host != URL(SERVER_URL).host) {
                return
            }
            val conn = (parsed.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                doOutput = true
                connectTimeout = 10000
                readTimeout = 10000
            }
            conn.outputStream.use { it.write(data.toString().toByteArray()) }
            conn.responseCode // Trigger the request
            conn.disconnect()
        } catch (e: Exception) {
            // Network error — will retry next heartbeat
        }
    }
}
