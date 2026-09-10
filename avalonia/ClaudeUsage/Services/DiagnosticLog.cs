namespace ClaudeUsage.Services;

/// Appends timestamped lines to %TEMP%\claude-usage-debug.log for
/// diagnosing cookie-reading and API connectivity issues.
internal static class DiagnosticLog
{
    internal static readonly string LogPath =
        Path.Combine(Path.GetTempPath(), "claude-usage-debug.log");

    public static void Write(string message)
    {
        try
        {
            File.AppendAllText(LogPath, $"{DateTime.Now:HH:mm:ss.fff} {message}\n");
        }
        catch { }
    }
}
