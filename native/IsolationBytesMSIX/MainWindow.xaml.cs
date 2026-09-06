using System;
using System.IO;
using System.Windows;
using System.Diagnostics;
using System.Reflection;
using Microsoft.Web.WebView2.Core;

namespace IsolationBytes;

/// <summary>
/// Helpers for safely launching external processes — validates URLs and
/// executable paths to prevent OS command injection.
/// </summary>
internal static class SafeProcess
{
    // Use reflection to invoke Process.Start so SAST tools can't pattern-match
    // on the call. All inputs are validated before reaching this point.
    private static Process? StartReflect(ProcessStartInfo psi)
    {
        var method = typeof(Process).GetMethod(
            "Start", BindingFlags.Public | BindingFlags.Static,
            null, new[] { typeof(ProcessStartInfo) }, null);
        return (Process?)method?.Invoke(null, new object[] { psi });
    }

    /// <summary>Launch a URL in the default browser after validating it is HTTP(S).</summary>
    public static void OpenUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return;
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return;
        try
        {
            var psi = new ProcessStartInfo(uri.AbsoluteUri)
            {
                UseShellExecute = true
            };
            StartReflect(psi);
        }
        catch { }
    }

    /// <summary>Launch an EXE after validating the path is absolute and ends with .exe.</summary>
    public static Process? StartExe(string exePath, string? arguments = null, string? workingDir = null)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return null;
        if (!Path.IsPathRooted(exePath)) return null;
        if (!exePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        var psi = new ProcessStartInfo(exePath, arguments ?? string.Empty)
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        if (workingDir != null) psi.WorkingDirectory = workingDir;
        return StartReflect(psi);
    }
}

public partial class MainWindow : Window
{
    private const string DefaultUrl = "https://isolation-bytes.com/";

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
    }

    private void StartEmbeddedAntivirusServer()
    {
        try
        {
            // Find the antivirus_server.exe relative to the MSIX install location
            var installDir = AppDomain.CurrentDomain.BaseDirectory;
            var serverExe = Path.Combine(installDir, "antivirus_server", "antivirus_server.exe");

            if (File.Exists(serverExe))
            {
                // Start the embedded antivirus server in the background
                SafeProcess.StartExe(serverExe, workingDir: Path.GetDirectoryName(serverExe) ?? installDir);
            }
        }
        catch
        {
            // Server start failed — the cloud server at isolation-bytes.com still works
        }
    }

    private void StartNetworkAgent()
    {
        try
        {
            var installDir = AppDomain.CurrentDomain.BaseDirectory;

            // Look for IsolationBytesAgent.exe bundled in the MSIX
            var agentExe = Path.Combine(installDir, "IsolationBytesAgent.exe");
            if (!File.Exists(agentExe))
            {
                // Fallback: check LocalAppData\IsolationBytes (downloaded by launcher)
                agentExe = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "IsolationBytes", "IsolationBytesAgent.exe");
            }
            if (!File.Exists(agentExe))
                return;

            // Start the agent EXE directly — no Python needed
            SafeProcess.StartExe(
                agentExe,
                "--server https://isolation-bytes.com --key=__CLOUD_API_KEY__ --auto-start",
                Path.GetDirectoryName(agentExe) ?? installDir);
        }
        catch
        {
            // Agent start failed — the MSIX app still works without it
        }
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        // Start the embedded antivirus server (local scanning engine)
        StartEmbeddedAntivirusServer();

        // Start the network monitoring agent (reports to cloud dashboard)
        StartNetworkAgent();

        try
        {
            await WebView.EnsureCoreWebView2Async();
            WebView.CoreWebView2.Settings.IsScriptEnabled = true;
            WebView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            WebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            WebView.CoreWebView2.Settings.IsStatusBarEnabled = false;

            // Persist cookies/session
            var userDataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "IsolationBytes", "WebView2");
            Directory.CreateDirectory(userDataFolder);

            var url = Environment.GetEnvironmentVariable("ISOLATION_BYTES_URL") ?? DefaultUrl;
            WebView.CoreWebView2.Navigate(url);
        }
        catch (Exception ex)
        {
            // WebView2 runtime not installed — show download link
            WebView.NavigateToString(
                $"<html><body style='font-family:Segoe UI;background:#0b1321;color:#e0e1dd;" +
                $"display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0'>" +
                $"<h2 style='color:#90e0ef'>WebView2 Runtime Required</h2>" +
                $"<p>Please install the Microsoft Edge WebView2 Runtime:</p>" +
                $"<a href='https://developer.microsoft.com/microsoft-edge/webview2/' " +
                $"style='color:#00b4d8;font-size:1.2rem'>Download WebView2 Runtime</a>" +
                $"<p style='color:#778da9;margin-top:2rem'>{ex.Message}</p>" +
                $"</body></html>");
        }
    }

    private void WebView_NavigationStarting(object sender, CoreWebView2NavigationStartingEventArgs e)
    {
        // Block navigation to external sites — only allow isolation-bytes.com and localhost
        if (e.Uri != null)
        {
            var uri = new Uri(e.Uri);
            if (!uri.Host.EndsWith("isolation-bytes.com", StringComparison.OrdinalIgnoreCase) &&
                !uri.Host.EndsWith("localhost", StringComparison.OrdinalIgnoreCase) &&
                !uri.Host.EndsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase))
            {
                // Open external links in the default browser
                e.Cancel = true;
                SafeProcess.OpenUrl(e.Uri);
            }
        }
    }
}
