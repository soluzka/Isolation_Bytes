using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

namespace AntivirusProtectedAdmin;

internal sealed class AdminService : ServiceBase
{
    private Process? _process;
    private bool _stopping;

    private static void Log(string message)
    {
        try
        {
            var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntivirusServer", "logs");
            Directory.CreateDirectory(logDir);
            var path = Path.Combine(logDir, "antivirus_protected_admin.log");
            File.AppendAllText(path, $"[{DateTime.Now:O}] {message}{Environment.NewLine}");
        }
        catch
        {
        }
    }

    public AdminService()
    {
        ServiceName = "AntivirusProtectedAdmin";
        CanStop = true;
        CanPauseAndContinue = false;
        CanShutdown = true;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        _stopping = false;
        try
        {
            Log($"OnStart called. args={string.Join(", ", args)}. BaseDirectory={AppContext.BaseDirectory}");
            var worker = FindWorker();
            Log($"Starting worker: {worker}");
            _process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = worker,
                    Arguments = "--worker",
                    WorkingDirectory = Path.GetDirectoryName(worker) ?? AppContext.BaseDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = false,
                    RedirectStandardError = false,
                },
                EnableRaisingEvents = true,
            };
            _process.Exited += (_, _) =>
            {
                Log($"Worker exited with code {_process?.ExitCode}. stopping={_stopping}");
                if (!_stopping)
                {
                    Stop();
                }
            };
            _process.Start();
            Log("Worker process started.");
        }
        catch (Exception ex)
        {
            Log($"OnStart failed: {ex}");
            throw;
        }
    }

    protected override void OnStop()
    {
        _stopping = true;
        Log("OnStop called.");
        if (_process is not null && !_process.HasExited)
        {
            try
            {
                _process.Kill();
                _process.WaitForExit(5000);
            }
            catch (Exception)
            {
            }
        }
        _process?.Dispose();
        _process = null;
        base.OnStop();
        Log("OnStop completed.");
    }

    private string FindWorker()
    {
        var name = "AntivirusProtectedAdminWorker.exe";
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "AntivirusProtectedAdminWorker", name),
            Path.Combine(AppContext.BaseDirectory, name),
            Path.Combine(Directory.GetParent(AppContext.BaseDirectory)?.FullName ?? AppContext.BaseDirectory, name),
        };
        foreach (var path in candidates)
        {
            Log($"FindWorker checking: {path} -> exists={File.Exists(path)}");
            if (File.Exists(path))
            {
                return path;
            }
        }
        throw new FileNotFoundException($"Worker executable not found: {name}");
    }
}
