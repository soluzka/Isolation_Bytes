using System;
using System.IO;
using System.ServiceProcess;

namespace AntivirusProtectedAdmin;

internal static class Program
{
    private static void Log(string message)
    {
        try
        {
            var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AntivirusServer", "logs");
            Directory.CreateDirectory(logDir);
            var path = Path.Combine(logDir, "antivirus_protected_admin.log");
            File.AppendAllText(path, $"[{DateTime.Now:O}] Program: {message}{Environment.NewLine}");
        }
        catch
        {
        }
    }

    private static void Main(string[] args)
    {
        try
        {
            Log($"Main started. args={string.Join(", ", args)}");
            ServiceBase.Run(new AdminService());
            Log("Main exiting normally.");
        }
        catch (Exception ex)
        {
            Log($"Main crashed: {ex}");
            throw;
        }
    }
}
