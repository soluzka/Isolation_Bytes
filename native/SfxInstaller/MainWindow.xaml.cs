using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace SfxInstaller;

public partial class MainWindow : Window
{
    private Process? _installer;
    private string InstallerExe =>
        Path.Combine(AppContext.BaseDirectory, "installer_backend", "Install_AntivirusServer.exe");

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
        Closed += (_, _) => _installer?.Dispose();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var userData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "IsolationBytes", "SfxWebView2");
            Directory.CreateDirectory(userData);

            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: userData);
            await WebView.EnsureCoreWebView2Async(environment);

            WebView.CoreWebView2.Settings.IsScriptEnabled = true;
            WebView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            WebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            WebView.CoreWebView2.Settings.IsStatusBarEnabled = false;

            WebView.CoreWebView2.WebMessageReceived += WebMessageReceived;
            WebView.CoreWebView2.NavigationStarting += WebViewNavigationStarting;
            WebView.CoreWebView2.Navigate(
                new Uri(Path.Combine(AppContext.BaseDirectory, "installer.html")).AbsoluteUri);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Microsoft Edge WebView2 Runtime is required.\n\n" + ex.Message,
                "Isolation Bytes Installer",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Close();
        }
    }

    private void WebViewNavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (e.Uri.StartsWith("https://isolation-bytes.com", StringComparison.OrdinalIgnoreCase))
            return;

        if (e.Uri.StartsWith("file:///", StringComparison.OrdinalIgnoreCase))
            return;

        e.Cancel = true;
    }

    private void WebView_NavigationStarting(object sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (e.Uri.StartsWith("https://isolation-bytes.com", StringComparison.OrdinalIgnoreCase))
            return;
        if (e.Uri.StartsWith("file:///", StringComparison.OrdinalIgnoreCase))
            return;
        e.Cancel = true;
    }

    private void WebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        var message = e.TryGetWebMessageAsString();
        if (string.Equals(message, "install", StringComparison.OrdinalIgnoreCase))
        {
            _ = RunInstallerAsync();
        }
        else if (string.Equals(message, "cancel", StringComparison.OrdinalIgnoreCase))
        {
            Close();
        }
    }

    private async Task RunInstallerAsync()
    {
        if (_installer is not null && !_installer.HasExited)
            return;

        if (!File.Exists(InstallerExe))
        {
            await PostStatus("error", "Installer backend was not found in the SFX package.");
            return;
        }

        try
        {
            await PostStatus("working", "Installing Isolation Bytes…");

            var start = new ProcessStartInfo
            {
                FileName = InstallerExe,
                WorkingDirectory = Path.GetDirectoryName(InstallerExe)!,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            _installer = Process.Start(start);
            if (_installer is null)
            {
                await PostStatus("error", "Windows could not start the installer backend.");
                return;
            }

            await _installer.WaitForExitAsync();

            if (_installer.ExitCode == 0)
            {
                await PostStatus("success", "Installation completed. Isolation Bytes is ready.");
                await Task.Delay(900);
                Close();
            }
            else
            {
                await PostStatus("error",
                    $"Installation stopped with exit code {_installer.ExitCode}. " +
                    "Check the installation log for details.");
            }
        }
        catch (Exception ex)
        {
            await PostStatus("error", "Installation failed: " + ex.Message);
        }
    }

    private async Task PostStatus(string state, string message)
    {
        try
        {
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                state,
                message
            });
            await WebView.CoreWebView2.ExecuteScriptAsync(
                $"window.setInstallerStatus({System.Text.Json.JsonSerializer.Serialize(payload)});");
        }
        catch
        {
            // The installer can continue even if the status view closes.
        }
    }
}
