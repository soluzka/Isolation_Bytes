// Isolation Bytes - PWA Service Worker
const CACHE_NAME = 'isolation-bytes-v4';
const CLOUD_URL = 'https://isolation-bytes.com';
const API_KEY = 'af5caf8d3d8080f8a8686f72dfa52eb92dad9ef95ebfdcd6f6494cf99ed6b909';
const PWA_DEVICE_ID = 'PWA-' + (self.registration ? self.registration.scope : 'unknown').slice(-12, -1).toUpperCase();
const AGENT_VERSION = '1.8.944.0';
const APP_SHELL = [
    '/',
    '/install',
    '/static/manifest.json',
    '/static/sw.js',
    '/static/icon-192.png',
    '/static/icon-512.png',
    '/static/icon-512-maskable.png',
    '/static/favicon.ico',
    '/static/style.css',
    '/static/styles.css',
    '/static/app.js',
    '/static/shield_bg.png'
];

// Suspicious file extensions to block in downloads
const SUSPICIOUS_EXTS = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.wsf', '.hta', '.scr', '.pif', '.com', '.msi', '.jar', '.sh', '.apk',
    '.dex', '.lnk', '.reg', '.inf'];
const HIGH_RISK_EXTS = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
    '.hta', '.scr', '.pif', '.com', '.msi', '.jar', '.apk'];

var pwaFilesScanned = 0;
var pwaThreatsBlocked = 0;
var pwaQuarantined = 0;
var pwaFindings = [];

// Install — cache the app shell
self.addEventListener('install', function(e) {
    e.waitUntil(
        caches.open(CACHE_NAME).then(function(cache) {
            return cache.addAll(APP_SHELL).catch(function() {
                // Don't fail if some assets aren't found
                return Promise.resolve();
            });
        })
    );
    self.skipWaiting();
});

// Activate — clean up old caches and start PWA agent heartbeat
self.addEventListener('activate', function(e) {
    e.waitUntil(
        caches.keys().then(function(names) {
            return Promise.all(
                names.filter(function(n) { return n !== CACHE_NAME; })
                     .map(function(n) { return caches.delete(n); })
            );
        }).then(function() {
            // Register this PWA as a device on the cloud
            return fetch(CLOUD_URL + '/agent/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    device_id: PWA_DEVICE_ID,
                    hostname: 'PWA (Browser)',
                    os: navigator.platform || 'browser',
                    os_version: navigator.userAgent,
                    agent_version: AGENT_VERSION,
                    api_key: API_KEY
                })
            }).catch(function() { /* fail silently */ });
        })
    );
    self.clients.claim();

    // Start periodic heartbeat — reports PWA status to cloud dashboard
    setInterval(function() {
        fetch(CLOUD_URL + '/agent/heartbeat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                device_id: PWA_DEVICE_ID,
                cpu_usage: 0,
                mem_usage: 0,
                disk_usage: 0,
                uptime: '0d 0h 0m',
                files_scanned: pwaFilesScanned,
                threats_blocked: pwaThreatsBlocked,
                quarantined_count: pwaQuarantined,
                scan_dirs: [],
                network_connections: [],
                network_devices: [],
                processes: [],
                process_count: 0,
                connection_count: 0,
                flagged_connections: [],
                watched_connections: [],
                flagged_count: 0,
                watched_count: 0,
                findings: pwaFindings.slice(-50)
            })
        }).catch(function() { /* fail silently */ });
    }, 30000); // every 30 seconds
});

// Fetch — network-first for API/routes, cache-first for static assets
// Also intercepts downloads of suspicious files and blocks them
self.addEventListener('fetch', function(e) {
    var url = new URL(e.request.url);

    // Never cache API calls or POST requests — always go to network
    if (url.pathname.startsWith('/api/') || e.request.method !== 'GET') {
        return fetch(e.request);
    }

    // Check if this is a download of a suspicious file
    var pathname = url.pathname.toLowerCase();
    var ext = pathname.substring(pathname.lastIndexOf('.'));
    if (SUSPICIOUS_EXTS.indexOf(ext) !== -1) {
        pwaFilesScanned++;
        var severity = (HIGH_RISK_EXTS.indexOf(ext) !== -1) ? 'high' : 'medium';
        var isHighRisk = HIGH_RISK_EXTS.indexOf(ext) !== -1;
        pwaThreatsBlocked++;
        if (isHighRisk) pwaQuarantined++;

        // Report the blocked download to the cloud
        pwaFindings.push({
            path: url.href,
            severity: severity,
            reason: 'Blocked download of suspicious file type: ' + ext,
            rule: 'pwa_download_block',
            hash: '',
            quarantined: isHighRisk,
            blocked: true
        });

        // Block the download by returning an error response
        e.respondWith(new Response(
            'Blocked by Isolation Bytes: Suspicious file type ' + ext,
            {status: 403, statusText: 'Blocked by Isolation Bytes',
             headers: {'Content-Type': 'text/plain'}}
        ));
        return;
    }

    // Cache-first for static assets
    if (url.pathname.startsWith('/static/')) {
        e.respondWith(
            caches.match(e.request).then(function(cached) {
                return cached || fetch(e.request).then(function(resp) {
                    if (resp.ok) {
                        var clone = resp.clone();
                        caches.open(CACHE_NAME).then(function(c) { c.put(e.request, clone); });
                    }
                    return resp;
                });
            })
        );
        return;
    }

    // Network-first for pages, fall back to cache when offline
    e.respondWith(
        fetch(e.request).then(function(resp) {
            if (resp.ok && resp.type === 'basic') {
                var clone = resp.clone();
                caches.open(CACHE_NAME).then(function(c) { c.put(e.request, clone); });
            }
            return resp;
        }).catch(function() {
            return caches.match(e.request).then(function(cached) {
                return cached || caches.match('/');
            });
        })
    );
});
