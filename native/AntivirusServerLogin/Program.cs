using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace AntivirusServerLogin;

internal static class NativeMethods
{
    [DllImport("kernel32.dll", SetLastError = false)]
    internal static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", SetLastError = false)]
    internal static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool pbDebuggerPresent);

    [DllImport("ntdll.dll")]
    internal static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref int processInformation, int processInformationLength, out int returnLength);
}

internal static class AntiDebug
{
    private static bool IsDebugged()
    {
        if (NativeMethods.IsDebuggerPresent()) return true;

        bool remote = false;
        NativeMethods.CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref remote);
        if (remote) return true;

        int debugPort = 0;
        if (NativeMethods.NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 7, ref debugPort, sizeof(int), out _) == 0 && debugPort != 0)
            return true;

        if (Environment.Is64BitProcess != (IntPtr.Size == 8))
            return true;

        return false;
    }

    public static void Check()
    {
        if (IsDebugged())
        {
            Environment.FailFast("Security check failed.");
        }
    }

    public static void StartTimer()
    {
        var t = new System.Windows.Forms.Timer { Interval = 1500 };
        t.Tick += (s, e) => Check();
        t.Start();
    }
}

public static class Global
{
    public const string AUMID = "soluzka.moodman_6y1ky6f75hc8p!App";
    public const string PAYMENT_URL = "https://apps.microsoft.com/detail/9P6XVZGRN9B7";
    public const string PUBLIC_KEY = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0apZ+SMcknYerhU6oTYK
X5AYSAO0+Ih5QZb74BOoaTMDBu0Lu/qcWeyXIiCbILJUgBW5IzSXcWNo/QLqGrAo
7soJT1K1drqe1wH65E3Bdk4laivdyic7a/7eZjffZ7e/eyYcfTKIEGJ7VS7WRo3T
HNptL3f69/zLdvLvSuKk/0sCRU/wOJSFwqL+NtxFbEoelCWclZhuZa/+adw5v+xB
RpnG+p6DFGAH7D97klAJHC3GyCpa5URUacd3aqY6u2HG1vixvIrfIEZPuFKL9MV0
asOfnjcrq63SHW08pvfv9J10PXisy1pPo+p0k6IjzU+b7ec1SqCZbhjt/KuUGGyV
LwIDAQAB
-----END PUBLIC KEY-----";
}

[ComVisible(true)]
public class ScriptObject
{
    private readonly LoginForm _form;
    public ScriptObject(LoginForm form) => _form = form;

    public string GetMachineId() => _form.GetMachineId();
    public void Purchase(string machineId = "") => _form.OpenPublicPage("purchase", machineId);
    public void OpenPublicPage(string page, string machineId = "") => _form.OpenPublicPage(page, machineId);
    public void OpenUrl(string url) => _form.OpenUrl(url);
    public void LoadLicense(string data) => _form.LoadLicense(data);
    public void Login(string user, string pass) => _form.Login(user, pass);
    public void Launch() => _form.LaunchApp();
    public void RedeemPurchase(string paymentId, string user, string pass, string email = "") => _form.RedeemPurchase(paymentId, user, pass, email);
    public void ForgotPassword() => _form.ForgotPassword();
    public string GetEnv(string key) => _form.GetEnv(key) ?? "";
}

static class Program
{
    public static void SetBrowserFeatureControl()
    {
        try
        {
            var fileName = Path.GetFileName(Process.GetCurrentProcess().MainModule?.FileName ?? "AntivirusServerLogin.exe");
            using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION");
            key?.SetValue(fileName, 11001, RegistryValueKind.DWord);
            key?.SetValue("AntivirusServerLogin.exe", 11001, RegistryValueKind.DWord);
            key?.SetValue("Antivirus Server Login.exe", 11001, RegistryValueKind.DWord);
        }
        catch { }
    }

    [STAThread]
    static int Main(string[] args)
    {
        SetBrowserFeatureControl();

        if (args.Contains("--verify"))
        {
            var form = new LoginForm();
            return form.TryLoadExistingLicense() ? 0 : 1;
        }

        // Install the Windows service (auto-start, survives logoff) if not
        // already installed. Runs in the background — non-blocking.
        System.Threading.Tasks.Task.Run(() => ServiceInstaller.EnsureInstalled());

        // Ensure Caddy is installed (downloads if missing) — non-blocking.
        System.Threading.Tasks.Task.Run(() => CaddyInstaller.EnsureInstalled());

        // Start the Flask cloud server (isolation-bytes.com) in the background
        // if it's not already running. Non-blocking — the form will retry
        // fetching the page until the server is ready.
        CloudServerStarter.EnsureRunning();

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new LoginForm());
        return 0;
    }
}

/// <summary>
/// Installs and starts the AntivirusCloudServer Windows service so the cloud
/// server auto-starts on boot and survives logoff. Extracts the embedded
/// cloud_service.py, ensures Python + pywin32 are available, then installs
/// the service. All operations are best-effort and non-fatal — the launcher
/// still works without the service (it just won't auto-start on boot).
/// </summary>
internal static class ServiceInstaller
{
    private const string ServiceName = "AntivirusCloudServer";

    /// <summary>Check if the Windows service is installed.</summary>
    private static bool IsServiceInstalled()
    {
        try
        {
            foreach (var line in RunCaptured("sc.exe", $"query {ServiceName}", 5000))
            {
                if (line.Contains("SERVICE_NAME", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch { }
        return false;
    }

    /// <summary>Check if the service is currently running.</summary>
    private static bool IsServiceRunning()
    {
        try
        {
            foreach (var line in RunCaptured("sc.exe", $"query {ServiceName}", 5000))
            {
                if (line.Contains("STATE", StringComparison.OrdinalIgnoreCase) &&
                    line.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch { }
        return false;
    }

    /// <summary>Run a process and capture stdout+stderr lines.</summary>
    private static List<string> RunCaptured(string fileName, string args, int timeoutMs)
    {
        var result = new List<string>();
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi);
        if (p is null) return result;
        while (!p.StandardOutput.EndOfStream) result.Add(p.StandardOutput.ReadLine() ?? "");
        while (!p.StandardError.EndOfStream) result.Add(p.StandardError.ReadLine() ?? "");
        p.WaitForExit(timeoutMs);
        return result;
    }

    /// <summary>Run a command elevated (UAC prompt) and wait for it.</summary>
    private static int RunElevated(string fileName, string args, int timeoutMs = 60000)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using var p = Process.Start(psi);
            if (p is null) return -1;
            p.WaitForExit(timeoutMs);
            return p.ExitCode;
        }
        catch { return -1; }
    }

    /// <summary>Extract the embedded cloud_service.py to the runtime directory.</summary>
    private static string? ExtractServiceScript()
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream("cloud_service_py");
            if (stream is null) return null;

            var runtimeDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "AntivirusServer");
            Directory.CreateDirectory(runtimeDir);

            var scriptPath = Path.Combine(runtimeDir, "cloud_service.py");
            using var fs = new FileStream(scriptPath, FileMode.Create, FileAccess.Write);
            stream.CopyTo(fs);
            return scriptPath;
        }
        catch { return null; }
    }

    /// <summary>Extract the embedded cloud_server.exe to the runtime directory.</summary>
    private static string? ExtractServerExe()
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream("cloud_server_exe");
            if (stream is null) return null;

            var runtimeDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "AntivirusServer");
            Directory.CreateDirectory(runtimeDir);

            var exePath = Path.Combine(runtimeDir, "cloud_server.exe");
            if (!File.Exists(exePath) || new FileInfo(exePath).Length != stream.Length)
            {
                using var fs = new FileStream(exePath, FileMode.Create, FileAccess.Write);
                stream.CopyTo(fs);
            }
            return exePath;
        }
        catch { return null; }
    }

    /// <summary>Ensure pywin32 is installed for the given Python.</summary>
    private static void EnsurePywin32(string python)
    {
        try
        {
            // Check if pywin32 is already installed
            var lines = RunCaptured(python, "-c \"import win32serviceutil; print('ok')\"", 10000);
            if (lines.Any(l => l.Contains("ok"))) return;

            // Install pywin32
            RunCaptured(python, "-m pip install pywin32", 120000);
            // Run post-install to register DLLs
            var scriptsDir = Path.Combine(Path.GetDirectoryName(python) ?? "", "Scripts");
            var postInstall = Path.Combine(scriptsDir, "pywin32_postinstall.py");
            if (File.Exists(postInstall))
                RunElevated(python, $"\"{postInstall}\" -install", 30000);
        }
        catch { }
    }

    /// <summary>
    /// Main entry: ensure the Windows service is installed and running.
    /// Called in a background thread from Main — never throws.
    /// </summary>
    public static void EnsureInstalled()
    {
        // Already installed and running? Nothing to do.
        if (IsServiceInstalled() && IsServiceRunning()) return;

        // Extract the service script and server EXE to the runtime dir.
        var scriptPath = ExtractServiceScript();
        var serverExe = ExtractServerExe();
        if (scriptPath is null) return;

        // Find or install Python
        var python = CloudServerStarter.FindPython();
        if (python is null)
        {
            CloudServerStarter.EnsurePythonInstalled();
            python = CloudServerStarter.FindPython();
        }
        if (python is null) return;

        // Ensure pywin32 is available
        EnsurePywin32(python);

        // Install the service (elevated)
        if (!IsServiceInstalled())
        {
            RunElevated(python, $"\"{scriptPath}\" install", 30000);
            // Configure auto-start + crash recovery
            RunElevated("sc.exe", $"config {ServiceName} start= auto", 10000);
            RunElevated("sc.exe", $"failure {ServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000", 10000);
        }

        // Start the service (elevated)
        if (!IsServiceRunning())
        {
            RunElevated("sc.exe", $"start {ServiceName}", 30000);
        }
    }
}

/// <summary>
/// Ensures Caddy reverse proxy is installed. Downloads the Caddy binary from
/// GitHub releases if it's not already present on disk. Caddy is a single
/// executable — no installer needed, just download and run.
/// </summary>
internal static class CaddyInstaller
{
    private const string CaddyVersion = "2.8.4";
    private const string CaddyDownloadUrl =
        "https://github.com/caddyserver/caddy/releases/download/v{0}/caddy_{0}_windows_amd64.zip";
    private const string CaddyExeName = "caddy.exe";

    /// <summary>Get the runtime directory where Caddy should live.</summary>
    private static string GetCaddyDir()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "IsolationBytes", "caddy");
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>Search known locations for an existing Caddy install.</summary>
    private static string? FindExistingCaddy()
    {
        var candidates = new List<string>
        {
            Path.Combine(GetCaddyDir(), CaddyExeName),
            @"C:\caddy\caddy.exe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Caddy", CaddyExeName),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Caddy", CaddyExeName),
        };
        foreach (var c in candidates)
        {
            try { if (File.Exists(c)) return c; } catch { }
        }
        return null;
    }

    /// <summary>
    /// Download and extract Caddy to the runtime directory if not already
    /// installed. Returns the path to caddy.exe, or null on failure.
    /// </summary>
    public static string? EnsureInstalled()
    {
        // Already installed?
        var existing = FindExistingCaddy();
        if (existing is not null) return existing;

        try
        {
            var caddyDir = GetCaddyDir();
            var exePath = Path.Combine(caddyDir, CaddyExeName);
            if (File.Exists(exePath)) return exePath;

            // Download Caddy zip from GitHub releases
            var url = string.Format(CaddyDownloadUrl, CaddyVersion);
            var zipPath = Path.Combine(Path.GetTempPath(), "caddy_download.zip");

            using (var client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromMinutes(3);
                client.DefaultRequestHeaders.Add("User-Agent", "AntivirusServerLauncher");
                var bytes = client.GetByteArrayAsync(url).Result;
                File.WriteAllBytes(zipPath, bytes);
            }

            // Extract caddy.exe from the zip
            System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, caddyDir, overwriteFiles: true);
            try { File.Delete(zipPath); } catch { }

            // The zip contains caddy.exe at the root
            if (File.Exists(exePath)) return exePath;

            // Some versions put it in a subfolder — search for it
            var found = Directory.GetFiles(caddyDir, CaddyExeName, SearchOption.AllDirectories);
            if (found.Length > 0)
            {
                // Move it to the root of caddyDir
                if (found[0] != exePath)
                {
                    try { File.Move(found[0], exePath, overwrite: true); } catch { }
                }
                if (File.Exists(exePath)) return exePath;
                return found[0];
            }
            return null;
        }
        catch { return null; }
    }
}

/// <summary>
/// Finds and starts the Flask cloud server (cloud_server.py) so the website
/// at isolation-bytes.com is available. Does nothing if the server is already
/// listening on port 8000.
/// </summary>
internal static class CloudServerStarter
{
    private const int ServerPort = 8000;

    /// <summary>True if something is already listening on the server port.</summary>
    private static bool IsPortListening()
    {
        try
        {
            using var client = new System.Net.Sockets.TcpClient();
            var ar = client.BeginConnect("127.0.0.1", ServerPort, null, null);
            var ok = ar.AsyncWaitHandle.WaitOne(500);
            if (!ok) return false;
            client.EndConnect(ar);
            return true;
        }
        catch { return false; }
    }

    /// <summary>Wait up to ~15 seconds for the server to start listening.</summary>
    public static void WaitForServer(int timeoutMs = 15000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (IsPortListening()) return;
            System.Threading.Thread.Sleep(500);
        }
    }

    /// <summary>Find cloud_server.py relative to the launcher EXE or install dirs.</summary>
    private static string? FindCloudServerScript()
    {
        var local = Path.GetDirectoryName(Application.ExecutablePath);
        var candidates = new List<string>();

        if (!string.IsNullOrEmpty(local))
        {
            // Same folder as launcher
            candidates.Add(Path.Combine(local, "cloud", "cloud_server.py"));
            candidates.Add(Path.Combine(local, "cloud_server.py"));
            // One/two/three levels up (dev layout, install layouts)
            candidates.Add(Path.Combine(local, "..", "cloud", "cloud_server.py"));
            candidates.Add(Path.Combine(local, "..", "..", "cloud", "cloud_server.py"));
            candidates.Add(Path.Combine(local, "..", "..", "..", "cloud", "cloud_server.py"));
            // Sibling "Antivirus Server" folder
            candidates.Add(Path.Combine(local, "Antivirus Server", "cloud", "cloud_server.py"));
            candidates.Add(Path.Combine(local, "..", "Antivirus Server", "cloud", "cloud_server.py"));
        }

        // Program Files install layouts
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        candidates.Add(Path.Combine(pf, "Antivirus Server", "cloud", "cloud_server.py"));
        candidates.Add(Path.Combine(pf86, "Antivirus Server", "cloud", "cloud_server.py"));
        candidates.Add(Path.Combine(pf, "AntivirusServer", "cloud", "cloud_server.py"));
        candidates.Add(Path.Combine(pf86, "AntivirusServer", "cloud", "cloud_server.py"));

        // Runtime dir from service.cache (highest priority — insert at front)
        try
        {
            var envPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntivirusServer", "service.cache");
            if (File.Exists(envPath))
            {
                foreach (var line in File.ReadAllLines(envPath))
                {
                    if (line.StartsWith("ANTIVIRUS_RUNTIME_DIR="))
                    {
                        var runtimeDir = line.Substring("ANTIVIRUS_RUNTIME_DIR=".Length).Trim();
                        if (!string.IsNullOrEmpty(runtimeDir))
                        {
                            candidates.Insert(0, Path.Combine(runtimeDir, "cloud", "cloud_server.py"));
                            candidates.Insert(1, Path.Combine(runtimeDir, "cloud_server.py"));
                        }
                        break;
                    }
                }
            }
        }
        catch { }

        // Check service.cache for a runtime dir hint (no embedded env used)
        try
        {
            var envPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntivirusServer", "service.cache");
            if (File.Exists(envPath))
            {
                foreach (var line in File.ReadAllLines(envPath))
                {
                    if (line.StartsWith("ANTIVIRUS_RUNTIME_DIR="))
                    {
                        var runtimeDir = line.Substring("ANTIVIRUS_RUNTIME_DIR=".Length).Trim();
                        if (!string.IsNullOrEmpty(runtimeDir))
                        {
                            candidates.Insert(0, Path.Combine(runtimeDir, "cloud", "cloud_server.py"));
                            candidates.Insert(1, Path.Combine(runtimeDir, "cloud_server.py"));
                        }
                        break;
                    }
                }
            }
        }
        catch { }

        foreach (var c in candidates)
        {
            try { if (File.Exists(c)) return Path.GetFullPath(c); } catch { }
        }
        return null;
    }

    /// <summary>Find a standalone cloud_server.exe (PyInstaller build, no Python needed).</summary>
    private static string? FindCloudServerExe()
    {
        var local = Path.GetDirectoryName(Application.ExecutablePath);
        var candidates = new List<string>();

        if (!string.IsNullOrEmpty(local))
        {
            candidates.Add(Path.Combine(local, "cloud_server.exe"));
            candidates.Add(Path.Combine(local, "cloud", "cloud_server.exe"));
            candidates.Add(Path.Combine(local, "..", "cloud_server.exe"));
            candidates.Add(Path.Combine(local, "..", "cloud", "cloud_server.exe"));
            candidates.Add(Path.Combine(local, "..", "..", "cloud_server.exe"));
            candidates.Add(Path.Combine(local, "Antivirus Server", "cloud_server.exe"));
            candidates.Add(Path.Combine(local, "dist", "cloud_server.exe"));
        }

        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        candidates.Add(Path.Combine(pf, "Antivirus Server", "cloud_server.exe"));
        candidates.Add(Path.Combine(pf86, "Antivirus Server", "cloud_server.exe"));
        candidates.Add(Path.Combine(pf, "AntivirusServer", "cloud_server.exe"));
        candidates.Add(Path.Combine(pf86, "AntivirusServer", "cloud_server.exe"));

        // Runtime dir from service.cache
        try
        {
            var envPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntivirusServer", "service.cache");
            if (File.Exists(envPath))
            {
                foreach (var line in File.ReadAllLines(envPath))
                {
                    if (line.StartsWith("ANTIVIRUS_RUNTIME_DIR="))
                    {
                        var runtimeDir = line.Substring("ANTIVIRUS_RUNTIME_DIR=".Length).Trim();
                        if (!string.IsNullOrEmpty(runtimeDir))
                            candidates.Insert(0, Path.Combine(runtimeDir, "cloud_server.exe"));
                        break;
                    }
                }
            }
        }
        catch { }

        foreach (var c in candidates)
        {
            try { if (File.Exists(c)) return Path.GetFullPath(c); } catch { }
        }
        return null;
    }

    /// <summary>Find the python executable to run the server with.</summary>
    internal static string? FindPython()
    {
        var candidates = new List<string>
        {
            "python.exe",
            "python",
            "py",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python", "Python311", "python.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python", "Python312", "python.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python", "Python313", "python.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python", "Python310", "python.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python", "Python39", "python.exe"),
            @"C:\Program Files\Python311\python.exe",
            @"C:\Program Files\Python312\python.exe",
            @"C:\Program Files\Python313\python.exe",
            @"C:\Program Files\Python310\python.exe",
            @"C:\Program Files\Python39\python.exe",
            @"C:\Program Files (x86)\Python311\python.exe",
            @"C:\Program Files (x86)\Python312\python.exe",
        };

        foreach (var c in candidates)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = c,
                    Arguments = "--version",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using var p = Process.Start(psi);
                if (p is not null)
                {
                    p.WaitForExit(3000);
                    if (p.ExitCode == 0) return c;
                }
            }
            catch { }
        }
        return null;
    }

    /// <summary>
    /// Extract the embedded Python 3.11 installer and run it silently to
    /// install Python for all users. Returns true if Python is available
    /// after the install (or was already installed).
    /// </summary>
    internal static bool EnsurePythonInstalled()
    {
        // Already installed?
        if (FindPython() is not null) return true;

        try
        {
            // Extract the embedded installer to temp.
            var asm = Assembly.GetExecutingAssembly();
            var resourceName = "python_installer.exe";
            var tempInstaller = Path.Combine(Path.GetTempPath(), "python-3.11.9-amd64.exe");

            using (var stream = asm.GetManifestResourceStream(resourceName))
            {
                if (stream is null) return false; // Installer not embedded.
                using var fs = new FileStream(tempInstaller, FileMode.Create, FileAccess.Write);
                stream.CopyTo(fs);
            }

            // Run the installer silently for all users:
            //   /quiet       — no UI
            //   InstallAllUsers=1 — install for all users
            //   PrependPath=1     — add to PATH
            //   Include_pip=1     — include pip
            var psi = new ProcessStartInfo
            {
                FileName = tempInstaller,
                Arguments = "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1",
                UseShellExecute = false,
                CreateNoWindow = true,
                Verb = "runas",
            };
            var proc = Process.Start(psi);
            if (proc is not null)
            {
                proc.WaitForExit(120000); // Wait up to 2 minutes.
            }

            try { File.Delete(tempInstaller); } catch { }

            // Check again if Python is now available.
            return FindPython() is not null;
        }
        catch { return false; }
    }

    /// <summary>
    /// Start the Flask cloud server if it's not already running and the
    /// script can be found. Non-blocking — starts the server in a background
    /// thread and returns immediately. The form will retry fetching the page.
    /// </summary>
    /// <summary>
    /// Extract the embedded cloud_server.py to a temp folder so it can be
    /// run with Python. Returns the path to the extracted script, or null.
    /// </summary>
    private static string? ExtractEmbeddedServer()
    {
        try
        {
            var script = CloudServer.GetDecrypted();
            if (string.IsNullOrEmpty(script)) return null;

            // Extract to a temp folder next to the launcher (so it can find
            // templates/, static/, website/, etc. relative to the project root).
            var local = Path.GetDirectoryName(Application.ExecutablePath);
            string extractDir;
            if (!string.IsNullOrEmpty(local))
                extractDir = Path.Combine(local, "cloud");
            else
                extractDir = Path.Combine(Path.GetTempPath(), "AntivirusServer", "cloud");

            Directory.CreateDirectory(extractDir);
            var scriptPath = Path.Combine(extractDir, "cloud_server.py");
            File.WriteAllText(scriptPath, script);
            return scriptPath;
        }
        catch { return null; }
    }

    /// <summary>
    /// Extract the embedded cloud_server.exe to a temp folder so it can be
    /// run without any external files. Returns the path to the extracted EXE.
    /// </summary>
    private static string? ExtractEmbeddedCloudServerExe()
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            var resourceName = "cloud_server_exe";
            using var stream = asm.GetManifestResourceStream(resourceName);
            if (stream is null) return null;

            // Extract to a temp folder next to the launcher
            var local = Path.GetDirectoryName(Application.ExecutablePath);
            string extractDir;
            if (!string.IsNullOrEmpty(local))
                extractDir = Path.Combine(local, "cloud");
            else
                extractDir = Path.Combine(Path.GetTempPath(), "AntivirusServer", "cloud");

            Directory.CreateDirectory(extractDir);
            var exePath = Path.Combine(extractDir, "cloud_server.exe");

            // Only extract if it doesn't exist or is a different size
            if (!File.Exists(exePath) || new FileInfo(exePath).Length != stream.Length)
            {
                using var fs = new FileStream(exePath, FileMode.Create, FileAccess.Write);
                stream.CopyTo(fs);
            }
            return exePath;
        }
        catch { return null; }
    }

    public static void EnsureRunning()
    {
        if (IsPortListening())
        {
            StartCloudflareTunnel();
            return;
        }

        // 1. Prefer a standalone cloud_server.exe on disk (no Python needed).
        var serverExe = FindCloudServerExe();

        // 2. If not on disk, extract the embedded cloud_server.exe from the launcher.
        if (serverExe is null)
            serverExe = ExtractEmbeddedCloudServerExe();

        if (serverExe is not null)
        {
            var workingDir = Path.GetDirectoryName(serverExe) ?? "";
            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var proc = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = serverExe,
                            WorkingDirectory = workingDir,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            WindowStyle = ProcessWindowStyle.Hidden,
                        },
                        EnableRaisingEvents = true,
                    };
                    proc.Start();
                }
                catch { }
            });

            // Also start the Cloudflare tunnel so the public URL works
            StartCloudflareTunnel();
            return;
        }

        // 3. Fallback: try to find cloud_server.py on disk.
        var script = FindCloudServerScript();

        // 4. If not found, extract the embedded copy from the launcher.
        if (script is null)
            script = ExtractEmbeddedServer();

        if (script is null) return;

        // 5. Make sure Python is installed (extracts + runs embedded installer
        // if Python is not found on the system).
        var python = FindPython();
        if (python is null)
        {
            System.Threading.Tasks.Task.Run(() =>
            {
                EnsurePythonInstalled();
            }).Wait(120000);
            python = FindPython();
        }

        if (python is null) return;

        var wd = Path.GetDirectoryName(script) ?? "";
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = python,
                        Arguments = $"\"{script}\"",
                        WorkingDirectory = wd,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden,
                    },
                    EnableRaisingEvents = true,
                };
                proc.Start();
            }
            catch { }
        });
    }

    /// <summary>
    /// Start the Cloudflare tunnel (cloudflared.exe) so the public URL
    /// (isolation-bytes.com) works alongside the local server.
    /// Does nothing if protected external credentials are unavailable or it is already running.
    /// </summary>
    private static string? ExtractCloudflaredResource(string resourceName, string fileName)
    {
        try
        {
            var runtimeDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "IsolationBytes", "cloudflared");
            Directory.CreateDirectory(runtimeDir);
            var outputPath = Path.Combine(runtimeDir, fileName);
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
            if (stream is null) return null;
            if (!File.Exists(outputPath) || new FileInfo(outputPath).Length != stream.Length)
            {
                using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
                stream.CopyTo(output);
            }
            return outputPath;
        }
        catch { return null; }
    }

    private static string? FindCloudflareConfig()
    {
        var candidates = new[]
        {
            Environment.GetEnvironmentVariable("CLOUDFLARED_CONFIG"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cloudflared", "config.yml"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "IsolationBytes", "cloudflared", "config.yml"),
        };

        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate) || !File.Exists(candidate)) continue;
            try
            {
                var lines = File.ReadAllLines(candidate);
                var tunnel = lines.FirstOrDefault(line => line.TrimStart().StartsWith("tunnel:", StringComparison.OrdinalIgnoreCase));
                var credential = lines.FirstOrDefault(line => line.TrimStart().StartsWith("credentials-file:", StringComparison.OrdinalIgnoreCase));
                if (tunnel is null || credential is null || tunnel.Contains("YOUR_TUNNEL_ID", StringComparison.OrdinalIgnoreCase)) continue;
                var credentialPath = credential[(credential.IndexOf(':') + 1)..].Trim().Trim('"', '\'');
                credentialPath = Environment.ExpandEnvironmentVariables(credentialPath);
                if (File.Exists(credentialPath)) return candidate;
            }
            catch { }
        }
        return null;
    }

    private static void StartCloudflareTunnel()
    {
        try
        {
            ExtractCloudflaredResource("cloudflared_config_template", "config.template.yml");
            if (Process.GetProcessesByName("cloudflared").Length > 0) return;

            // Search portable locations for cloudflared.exe
            var cloudflaredExe = ExtractCloudflaredResource("cloudflared_exe", "cloudflared.exe");
            if (cloudflaredExe is null || !File.Exists(cloudflaredExe))
            {
                // Search known locations on disk
                var candidates = new[]
                {
                    @"C:\caddy\cloudflared.exe",
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IsolationBytes", "cloudflared", "cloudflared.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "cloudflared", "cloudflared.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "cloudflared", "cloudflared.exe"),
                };
                foreach (var c in candidates)
                {
                    if (File.Exists(c)) { cloudflaredExe = c; break; }
                }
            }
            if (cloudflaredExe is null || !File.Exists(cloudflaredExe)) return;

            var cloudflaredConfig = FindCloudflareConfig();
            var tunnelName = Environment.GetEnvironmentVariable("CLOUDFLARED_TUNNEL_NAME") ?? "isolation-bytes";

            System.Threading.Tasks.Task.Run(() =>
            {
                System.Threading.Thread.Sleep(5000);
                try
                {
                    if (cloudflaredConfig is not null)
                    {
                        // Named tunnel with config + credentials
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = cloudflaredExe,
                            Arguments = $"tunnel --config \"{cloudflaredConfig}\" run {tunnelName}",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        });
                    }
                    else
                    {
                        // No credentials available — start a quick tunnel (temporary URL)
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = cloudflaredExe,
                            Arguments = $"tunnel --url http://127.0.0.1:8000",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        });
                    }
                }
                catch { }
            });
        }
        catch { }
    }
}

public class LoginForm : Form
{
    private readonly WebBrowser _browser;
    private JsonNode? _loadedLicense;
    private bool _canLaunch = false;

    public LoginForm()
    {
        AntiDebug.Check();
        AntiDebug.StartTimer();
        Text = "Antivirus Server";
        Size = new System.Drawing.Size(760, 760);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = System.Drawing.Color.FromArgb(13, 27, 42);

        _browser = new WebBrowser
        {
            Dock = DockStyle.Fill,
            ScriptErrorsSuppressed = true,
            AllowWebBrowserDrop = false,
            IsWebBrowserContextMenuEnabled = false
        };
        _browser.ObjectForScripting = new ScriptObject(this);
        Controls.Add(_browser);

        _browser.DocumentCompleted += (s, e) =>
        {
            try
            {
                var doc = _browser.Document;
                if (doc is not null)
                {
                    var mid = GetMachineId();
                    var elHome = doc.GetElementById("homeMachineId");
                    if (elHome is not null) elHome.SetAttribute("value", mid);
                    var elPurchase = doc.GetElementById("purchaseMachineId");
                    if (elPurchase is not null) elPurchase.SetAttribute("value", mid);
                    var elLic = doc.GetElementById("machineId");
                    if (elLic is not null) elLic.SetAttribute("value", mid);
                    var elRedeem = doc.GetElementById("redeemMachineId");
                    if (elRedeem is not null) elRedeem.SetAttribute("value", mid);
                }
            }
            catch { }
        };

        _browser.Navigating += (s, e) =>
        {
            var url = e.Url?.ToString() ?? "";
            if (url.StartsWith("app:", StringComparison.OrdinalIgnoreCase))
            {
                e.Cancel = true;
                HandleAppUrl(url);
                return;
            }
            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                e.Cancel = true;
                try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); }
                catch { }
            }
        };
        _browser.NewWindow += (s, e) =>
        {
            e.Cancel = true;
            var url = _browser.StatusText;
            if (string.IsNullOrWhiteSpace(url)) return;
            try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); }
            catch { }
        };

        Load += async (s, e) =>
        {
            // Show a loading screen immediately so the window isn't white
            // while the server starts up.
            var loadingHtml = "<html><head><style>" +
                "* { font-family: 'Segoe UI', sans-serif; }" +
                "body { background: #0b1321; color: #e0e1dd; display: flex; " +
                "flex-direction: column; align-items: center; justify-content: center; " +
                "height: 100vh; margin: 0; }" +
                ".spinner { width: 40px; height: 40px; border: 3px solid #415a77; " +
                "border-top: 3px solid #00b4d8; border-radius: 50%; " +
                "animation: spin 1s linear infinite; margin-bottom: 20px; }" +
                "@keyframes spin { 100% { transform: rotate(360deg); } }" +
                "h2 { color: #90e0ef; font-weight: 400; }" +
                "p { color: #778da9; font-size: 0.9rem; }" +
                "</style></head><body>" +
                "<div class='spinner'></div>" +
                "<h2>Starting Antivirus Server...</h2>" +
                "<p>Please wait while the server loads.</p>" +
                "</body></html>";
            _browser.DocumentText = loadingHtml;

            string html;
            var publicUrl = GetEnv("PUBLIC_URL");
            if (string.IsNullOrWhiteSpace(publicUrl))
                publicUrl = "https://isolation-bytes.com/";

            // Try LOCAL URLs first — the server runs locally so this is fastest
            // and doesn't depend on the Cloudflare tunnel being up.
            // The public URL is only used for external access, not the launcher.
            var urls = new[] { "http://127.0.0.1:8000/", "http://localhost:8000/", "https://127.0.0.1:8443/" };
            html = LoginHtml.GetDecrypted();

            // Retry fetching from the server for up to ~30 seconds (server
            // may still be starting up from CloudServerStarter.EnsureRunning).
            var deadline = DateTime.UtcNow.AddSeconds(30);
            bool fetched = false;
            while (DateTime.UtcNow < deadline && !fetched)
            {
                foreach (var url in urls.Distinct())
                {
                    try
                    {
                        var handler = new HttpClientHandler
                        {
                            ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
                        };
                        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
                        html = await http.GetStringAsync(url).ConfigureAwait(false);
                        fetched = true;
                        break;
                    }
                    catch { }
                }
                if (!fetched) await System.Threading.Tasks.Task.Delay(1000);
            }

            html = html.Replace("{{MACHINE_ID}}", GetMachineId()).Replace("{{ADMIN_USERNAME}}", GetEnv("ADMIN_USERNAME") ?? "");
            var mid = GetMachineId().Replace("\\", "\\\\").Replace("'", "\\'").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "");
            var admin = (GetEnv("ADMIN_USERNAME") ?? "").Replace("\\", "\\\\").Replace("'", "\\'").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "");
            var siteUrl = (GetEnv("PUBLIC_URL") ?? "https://isolation-bytes.com/").TrimEnd('/');
            var paymentUrl = (GetEnv("PAYMENT_URL") ?? "").Replace("\\", "\\\\").Replace("'", "\\'").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "");
            var hostScript = "<script>" + "\n" +
                "window.SoluzkaHost = {" + "\n" +
                "  OpenPublicPage: function(p,m) { window.location = 'app:openpage?page=' + encodeURIComponent(p||'') + '&m=' + encodeURIComponent(m||''); }," + "\n" +
                "  OpenUrl: function(u) { window.location = 'app:openurl?url=' + encodeURIComponent(u||''); }," + "\n" +
                "  Purchase: function(m) { window.location = 'app:openpage?page=purchase&m=' + encodeURIComponent(m||''); }," + "\n" +
                "  RedeemPurchase: function(pid,u,p,e) { var mid = document.getElementById('redeemMachineId') ? document.getElementById('redeemMachineId').value : ''; window.location = '" + siteUrl + "/?page=redeem&pid=' + encodeURIComponent(pid) + '&u=' + encodeURIComponent(u) + '&p=' + encodeURIComponent(p) + '&e=' + encodeURIComponent(e || '') + '&m=' + encodeURIComponent(mid); }," + "\n" +
                "  LoadLicense: function(d) { window.location = 'app:loadlicense?d=' + encodeURIComponent(d); }," + "\n" +
                "  Login: function(u,p) { var mid = document.getElementById('machineId') ? document.getElementById('machineId').value : ''; window.location = '" + siteUrl + "/?page=login&u=' + encodeURIComponent(u) + '&p=' + encodeURIComponent(p) + '&m=' + encodeURIComponent(mid); }," + "\n" +
                "  Launch: function() { window.location = 'app:launch'; }," + "\n" +
                "  ForgotPassword: function() { var mid = document.getElementById('machineId') ? document.getElementById('machineId').value : ''; window.location = '" + siteUrl + "/?page=forgot&m=' + encodeURIComponent(mid); }," + "\n" +
                "  GetMachineId: function() { return '" + mid + "'; }," + "\n" +
                "  GetEnv: function(k) { return (k === 'ADMIN_USERNAME') ? '" + admin + "' : ''; }" + "\n" +
                "};" + "\n" +
                "</script>";
            var headIdx = html.IndexOf("<head>", StringComparison.OrdinalIgnoreCase);
            if (headIdx >= 0) html = html.Insert(headIdx + "<head>".Length, hostScript);
            else html = hostScript + html;
            _browser.Invoke(new Action(() => _browser.DocumentText = html));
        };
    }

    private void HandleAppUrl(string url)
    {
        try
        {
            var u = new Uri(url);
            var query = u.Query.TrimStart('?');
            var parts = query.Split('&');
            var q = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in parts)
            {
                var kv = part.Split('=', 2);
                var key = Uri.UnescapeDataString(kv[0]);
                var value = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : "";
                q[key] = value;
            }
            var action = u.AbsolutePath.Trim('/').ToLowerInvariant();
            switch (action)
            {
                case "openpage": OpenPublicPage(q.TryGetValue("page", out var p) ? p : "purchase", q.TryGetValue("m", out var pm) ? pm : ""); break;
                case "openurl": if (q.TryGetValue("url", out var targetUrl)) OpenUrl(targetUrl); break;
                case "purchase": OpenPublicPage("purchase", q.TryGetValue("m", out var m) ? m : ""); break;
                case "redeem": OpenPublicPage("redeem", q.TryGetValue("m", out var rm) ? rm : ""); break;
                case "activate": OpenPublicPage("activate", q.TryGetValue("m", out var am) ? am : ""); break;
                case "loadlicense": LoadLicense(q.TryGetValue("d", out var d) ? d : ""); break;
                case "login": Login(q.TryGetValue("u", out var lu) ? lu : "", q.TryGetValue("p", out var lp) ? lp : ""); break;
                case "launch": LaunchApp(); break;
                case "forgot": ForgotPassword(); break;
            }
        }
        catch { }
    }

    public string GetMachineId()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            if (key is not null)
            {
                var uuidBytes = key.GetValue("SystemUUID") as byte[];
                if (uuidBytes is not null && uuidBytes.Length == 16)
                {
                    var uuid = new Guid(uuidBytes).ToString();
                    if (!string.IsNullOrWhiteSpace(uuid) &&
                        !uuid.Equals("00000000-0000-0000-0000-000000000000", StringComparison.OrdinalIgnoreCase))
                        return uuid;
                }

                var sn = key.GetValue("BaseBoardSerialNumber") as string;
                if (!string.IsNullOrWhiteSpace(sn) &&
                    !sn.Equals("NONE", StringComparison.OrdinalIgnoreCase) &&
                    !sn.Contains("O.E.M.", StringComparison.OrdinalIgnoreCase))
                    return sn;
            }
        }
        catch { }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            var guid = key?.GetValue("MachineGuid") as string;
            if (!string.IsNullOrWhiteSpace(guid))
                return guid;
        }
        catch { }

        return Environment.MachineName;
    }

    public bool TryLoadExistingLicense()
    {
        try
        {
            var path = GetLicensePath();
            if (!File.Exists(path)) return false;
            var text = File.ReadAllText(path);
            var node = JsonNode.Parse(text);
            if (node is null) return false;
            if (VerifyLicenseNode(node))
            {
                _loadedLicense = node;
                return true;
            }
        }
        catch { }
        return false;
    }

    public void LoadLicense(string raw)
    {
        raw = raw?.Trim() ?? "";
        if (string.IsNullOrEmpty(raw))
        {
            CallJs("setStatus", "Paste your license first.", true);
            return;
        }

        if (!raw.Contains('{'))
        {
            try
            {
                raw = Encoding.UTF8.GetString(Convert.FromBase64String(raw));
            }
            catch
            {
                CallJs("setStatus", "License is not valid base64 or JSON.", true);
                return;
            }
        }

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(raw);
        }
        catch
        {
            CallJs("setStatus", "Could not parse license JSON.", true);
            return;
        }

        if (node is null || !VerifyLicenseNode(node))
        {
            CallJs("setStatus", "License is not valid for this machine or has expired.", true);
            return;
        }

        _loadedLicense = node;
        File.WriteAllText(GetLicensePath(), node.ToJsonString());
        CallJs("setStatus", "License accepted. Enter your username and password and click Login.", false);
    }

    public void Login(string user, string pass)
    {
        if (_loadedLicense is null)
        {
            CallJs("setStatus", "Load a license first.", true);
            return;
        }

        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(pass))
        {
            CallJs("setStatus", "Enter username and password.", true);
            return;
        }

        var licUser = _loadedLicense["username"]?.GetValue<string>();
        if (licUser != user)
        {
            CallJs("setStatus", "Username does not match.", true);
            return;
        }

        var salt = _loadedLicense["salt"]?.GetValue<string>() ?? "";
        var expected = _loadedLicense["password_hash"]?.GetValue<string>() ?? "";
        var actual = HashPassword(pass, salt);

        if (actual != expected)
        {
            CallJs("setStatus", "Incorrect password.", true);
            return;
        }

        _canLaunch = true;
        WriteEnvFile();
        CallJs("setStatus", "Login successful. Click Launch to open Antivirus Server.", false);
        CallJs("setLaunchEnabled", true);
    }

    private void WriteEnvFile()
    {
        try
        {
            var envDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntivirusServer");
            Directory.CreateDirectory(envDir);
            File.SetAttributes(envDir, File.GetAttributes(envDir) | FileAttributes.Hidden);
            var envPath = Path.Combine(envDir, "service.cache");

            // Only write the runtime dir — no embedded env, no admin credentials
            var runtime = Path.Combine(envDir);
            var envLines = new List<string> { $"ANTIVIRUS_RUNTIME_DIR={runtime}" };

            // Preserve any existing lines that aren't ANTIVIRUS_RUNTIME_DIR
            if (File.Exists(envPath))
            {
                foreach (var line in File.ReadAllLines(envPath))
                {
                    if (!line.StartsWith("ANTIVIRUS_RUNTIME_DIR="))
                        envLines.Add(line);
                }
            }

            File.WriteAllText(envPath, string.Join("\n", envLines));
            File.Encrypt(envPath);
            File.SetAttributes(envPath, FileAttributes.Hidden | FileAttributes.System);
        }
        catch { }
    }

    // Cache config fetched from the server (admin-controlled .env)
    private static Dictionary<string, string>? _serverConfig = null;
    private static readonly object _configLock = new();

    private static Dictionary<string, string> FetchServerConfig()
    {
        lock (_configLock)
        {
            if (_serverConfig != null) return _serverConfig;
            var defaults = new Dictionary<string, string>
            {
                {"PUBLIC_URL", "https://isolation-bytes.com"},
                {"LICENSE_SERVER", "https://isolation-bytes.com"},
                {"PAYMENT_URL", ""},
                {"PROXY_PORT", "8000"},
                {"HTTPS_PORT", "443"},
            };
            // Try to fetch from the server's /api/config endpoint
            try
            {
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(3);
                var resp = client.GetStringAsync("http://127.0.0.1:8000/api/config").Result;
                var json = System.Text.Json.JsonDocument.Parse(resp);
                foreach (var prop in json.RootElement.EnumerateObject())
                {
                    defaults[prop.Name.ToUpper()] = prop.Value.ToString();
                }
            }
            catch { }
            _serverConfig = defaults;
            return _serverConfig;
        }
    }

    public string? GetEnv(string key)
    {
        var config = FetchServerConfig();
        if (config.TryGetValue(key.ToUpper(), out var val))
            return val;
        return null;
    }

    public void OpenUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch { }
    }

    public void OpenPublicPage(string page, string machineId = "")
    {
        var publicUrl = GetEnv("PUBLIC_URL");
        if (string.IsNullOrWhiteSpace(publicUrl))
            publicUrl = "https://isolation-bytes.com/";

        publicUrl = publicUrl.TrimEnd('/');
        var mid = string.IsNullOrWhiteSpace(machineId) ? GetMachineId() : machineId;
        var target = $"{publicUrl}/?page={Uri.EscapeDataString(page)}&machine_id={Uri.EscapeDataString(mid)}";
        OpenUrl(target);
    }

    public void Purchase(string machineId = "")
    {
        OpenPublicPage("purchase", machineId);
    }

    public async void RedeemPurchase(string paymentId, string user, string pass, string email = "")
    {
        var server = GetEnv("LICENSE_SERVER");
        if (string.IsNullOrWhiteSpace(server))
        {
            CallJs("setRedeemStatus", "No license server configured.", true);
            return;
        }

        paymentId = paymentId?.Trim() ?? "";
        user = user?.Trim() ?? "";
        pass = pass ?? "";
        email = email?.Trim() ?? "";
        if ((string.IsNullOrEmpty(paymentId) && string.IsNullOrEmpty(email)) || string.IsNullOrEmpty(user) || string.IsNullOrEmpty(pass))
        {
            CallJs("setRedeemStatus", "Enter payment ID, email, or both, plus username and password.", true);
            return;
        }

        try
        {
            var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => true };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            var json = new JsonObject
            {
                ["machine_id"] = GetMachineId(),
                ["payment_id"] = paymentId,
                ["username"] = user,
                ["password"] = pass,
                ["email"] = email
            };
            var content = new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json");
            var resp = await client.PostAsync($"{server.TrimEnd('/')}/redeem", content);
            var body = await resp.Content.ReadAsStringAsync();
            if (resp.IsSuccessStatusCode)
            {
                LoadLicense(body);
            }
            else
            {
                var msg = body;
                try
                {
                    var node = JsonNode.Parse(body);
                    msg = node?["error"]?.GetValue<string>() ?? body;
                }
                catch { }
                CallJs("setRedeemStatus", msg, true);
            }
        }
        catch (Exception ex)
        {
            CallJs("setRedeemStatus", $"License server error: {ex.Message}", true);
        }
    }

    public void ForgotPassword()
    {
        var url = GetEnv("PUBLIC_URL") ?? "https://isolation-bytes.com/";
        try { Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true }); }
        catch { }
    }

    private string FindAntivirusServerExe()
    {
        var candidates = new List<string>();
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        candidates.Add(Path.Combine(pf, "Antivirus Server", "Antivirus Server.exe"));
        candidates.Add(Path.Combine(pf, "Antivirus Server", "AntivirusServer.exe"));
        var local = Path.GetDirectoryName(Application.ExecutablePath);
        if (!string.IsNullOrEmpty(local))
        {
            candidates.Add(Path.Combine(local, "Antivirus Server", "Antivirus Server.exe"));
            candidates.Add(Path.Combine(local, "AntivirusServer.exe"));
            candidates.Add(Path.Combine(local, "..", "dist", "Antivirus Server", "Antivirus Server.exe"));
            candidates.Add(Path.Combine(local, "dist", "Antivirus Server", "Antivirus Server.exe"));
        }
        foreach (var c in candidates)
        {
            if (File.Exists(c))
                return Path.GetFullPath(c);
        }
        return string.Empty;
    }

    public void LaunchApp()
    {
        if (!_canLaunch)
        {
            CallJs("setStatus", "You must purchase, load a license, and log in first.", true);
            return;
        }

        var exe = FindAntivirusServerExe();
        if (string.IsNullOrEmpty(exe))
        {
            CallJs("setStatus", "Antivirus Server.exe not found. Install the app first.", true);
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                WorkingDirectory = Path.GetDirectoryName(exe),
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });
            CallJs("setStatus", "Antivirus Server started in the background.", false);
        }
        catch (Exception ex)
        {
            CallJs("setStatus", $"Could not launch app: {ex.Message}", true);
        }
    }

    private static string HashPassword(string password, string salt)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(salt + password));
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    private bool VerifyLicenseNode(JsonNode node)
    {
        var machineId = GetMachineId();
        var licMachine = node["machine_id"]?.GetValue<string>();
        if (licMachine != machineId)
            return false;

        var exp = node["exp"]?.GetValue<long?>();
        if (exp.HasValue)
        {
            var expTime = DateTimeOffset.FromUnixTimeSeconds(exp.Value).UtcDateTime;
            if (DateTime.UtcNow > expTime)
                return false;
        }

        var signature = node["signature"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(signature))
            return false;

        var data = new JsonObject();
        foreach (var prop in node.AsObject())
        {
            if (prop.Key != "signature" && prop.Value is not null)
                data.Add(prop.Key, prop.Value.DeepClone());
        }

        var sorted = new JsonObject(data.OrderBy(p => p.Key, StringComparer.Ordinal).ToDictionary(p => p.Key, p => p.Value));
        var dataBytes = Encoding.UTF8.GetBytes(sorted.ToJsonString());

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(Global.PUBLIC_KEY.ToCharArray());
            var signatureBytes = Convert.FromBase64String(signature);
            return rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    private static string GetLicensePath()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntivirusServer");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "credentials.lic");
    }

    private void CallJs(string name, params object[] args)
    {
        if (_browser.Document is null) return;
        _browser.Invoke(new Action(() =>
        {
            try { _browser.Document?.InvokeScript(name, args); }
            catch { }
        }));
    }
}
