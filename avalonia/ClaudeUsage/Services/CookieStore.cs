using Microsoft.Data.Sqlite;

namespace ClaudeUsage.Services;

/// Shared Chromium cookie-DB reading. The SQLite schema is identical across
/// platforms; only the per-value decryption differs, so callers pass a decrypt
/// delegate receiving (hostKey, encryptedValue).
internal static class CookieStore
{
    private const string CookieQuery =
        """
        SELECT host_key, name, encrypted_value
        FROM cookies
        WHERE host_key LIKE '%claude.ai%'
          AND name IN ('sessionKey', 'lastActiveOrg')
        """;

    public static IEnumerable<(string Name, string Value)> ReadClaudeCookies(
        string cookiePath, Func<string, byte[], string> decrypt)
    {
        var walPath = cookiePath + "-wal";
        var walInfo = File.Exists(walPath)
            ? $"exists ({new FileInfo(walPath).Length:N0} bytes)"
            : "absent";

        DiagnosticLog.Write($"ReadClaudeCookies: {cookiePath}");
        DiagnosticLog.Write($"  WAL: {walInfo}");

        // Strategy 1: open the live DB with immutable=1 (bypasses WAL/SHM entirely).
        // Retry up to 3 times because Windows Defender and other AV products
        // transiently lock SQLite files during scans — Chromium's own code does the
        // same retry loop for this exact reason.
        // NOTE: immutable=1 skips WAL replay; if a WAL exists, returned data may be stale.
        Exception? lastEx = null;
        for (int i = 0; i < 3; i++)
        {
            if (i > 0) Thread.Sleep(150 * i);
            try
            {
                DiagnosticLog.Write($"  Strategy 1 (immutable, attempt {i + 1})");
                var r = QueryDirect(cookiePath, decrypt);
                DiagnosticLog.Write($"  Strategy 1 OK: {r.Count} rows; WAL={walInfo} (WAL skipped by immutable=1)");
                if (File.Exists(walPath))
                    DiagnosticLog.Write("  WARNING: WAL exists — Strategy 1 data may be stale; consider Strategy 2/3");
                return r;
            }
            catch (Exception ex) { lastEx = ex; DiagnosticLog.Write($"  Strategy 1 fail: {ex.Message}"); }
        }

        // Strategy 2: copy the DB (plus its WAL file if present) to a temp location
        // and open the copy. This covers cases where the immutable open fails
        // because the SHM file is exclusively held by Claude.
        Exception? copyEx = null;
        try
        {
            DiagnosticLog.Write("  Strategy 2 (file copy)");
            var r = QueryViaCopy(cookiePath, decrypt);
            DiagnosticLog.Write($"  Strategy 2 OK: {r.Count} rows");
            return r;
        }
        catch (Exception ex) { copyEx = ex; DiagnosticLog.Write($"  Strategy 2 fail: {ex.Message}"); }

        // Strategy 3 (Windows only): Claude holds the file with exclusive sharing,
        // which blocks both SQLite opens and FileStream copies. DuplicateHandle lets
        // us read through Claude's existing handle without triggering a sharing check.
        if (OperatingSystem.IsWindows())
        {
            try
            {
                DiagnosticLog.Write("  Strategy 3 (handle dup)");
                var r = QueryViaHandleDuplicate(cookiePath, decrypt);
                DiagnosticLog.Write($"  Strategy 3 OK: {r.Count} rows");
                return r;
            }
            catch (Exception dupEx)
            {
                DiagnosticLog.Write($"  Strategy 3 fail: {dupEx.Message}");
                throw new InvalidOperationException(
                    $"Cannot read Claude cookies. " +
                    $"Direct: {lastEx?.Message} | " +
                    $"Copy: {copyEx?.Message} | " +
                    $"Handle dup: {dupEx.Message}");
            }
        }

        throw new InvalidOperationException(
            $"Cannot read Claude cookies — " +
            $"Direct: {lastEx?.Message} | Copy: {copyEx?.Message}");
    }

    private static List<(string, string)> QueryDirect(string cookiePath, Func<string, byte[], string> decrypt)
    {
        // immutable=1 tells SQLite to skip all WAL/SHM handling and read the main
        // DB file directly without acquiring any locks.
        // URI format on Windows must NOT have a leading slash before the drive
        // letter: "file:C:/path" not "file:///C:/path".
        var uri = "file:" + cookiePath.Replace('\\', '/') + "?immutable=1";
        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = uri,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString();

        using var conn = new SqliteConnection(cs);
        conn.Open();
        return ExecuteQuery(conn, decrypt);
    }

    private static List<(string, string)> QueryViaCopy(string cookiePath, Func<string, byte[], string> decrypt)
    {
        var tempDb = Path.Combine(Path.GetTempPath(), $"claude-cookies-{Guid.NewGuid():N}.db");
        var tempWal = tempDb + "-wal";
        var walPath = cookiePath + "-wal";

        try
        {
            CopyShared(cookiePath, tempDb);

            var walCopied = false;
            if (File.Exists(walPath))
            {
                try { CopyShared(walPath, tempWal); walCopied = true; }
                catch (Exception ex) { DiagnosticLog.Write($"  Strategy 2 WAL copy fail: {ex.Message}"); }
            }

            DiagnosticLog.Write($"  Strategy 2: main DB copied, WAL copied={walCopied}");

            var cs = new SqliteConnectionStringBuilder
            {
                DataSource = tempDb,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString();

            using var conn = new SqliteConnection(cs);
            conn.Open();
            return ExecuteQuery(conn, decrypt);
        }
        finally
        {
            try { File.Delete(tempDb); } catch { }
            try { File.Delete(tempWal); } catch { }
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static List<(string, string)> QueryViaHandleDuplicate(
        string cookiePath, Func<string, byte[], string> decrypt)
    {
        var tempDb = Path.Combine(Path.GetTempPath(), $"claude-cookies-{Guid.NewGuid():N}.db");
        var tempWal = tempDb + "-wal";
        var walPath = cookiePath + "-wal";
        var walExists = File.Exists(walPath);

        try
        {
            bool walCopied;
            if (walExists)
            {
                // Copy main DB and WAL in a single handle-enumeration pass so we
                // don't pay two separate 8-second timeouts.
                var (dbOk, walDupOk) = WindowsLockedFileCopier.TryCopyWithWal(
                    cookiePath, tempDb, walPath, tempWal);

                if (!dbOk)
                    throw new InvalidOperationException(
                        "Could not find or duplicate Claude's file handle for the Cookies database. " +
                        "Ensure the Claude desktop app is running.");

                walCopied = walDupOk;
                if (!walCopied)
                {
                    // Handle dup may not find the WAL handle if Chrome holds it with
                    // different sharing flags; try a plain shared-mode copy as fallback.
                    try { CopyShared(walPath, tempWal); walCopied = true; }
                    catch { }
                }

                DiagnosticLog.Write($"  Strategy 3: dbCopied=true, walCopied={walCopied}");
                if (!walCopied)
                    DiagnosticLog.Write("  WARNING: WAL copy failed — session key may be stale");
            }
            else
            {
                if (!WindowsLockedFileCopier.TryCopy(cookiePath, tempDb))
                    throw new InvalidOperationException(
                        "Could not find or duplicate Claude's file handle for the Cookies database. " +
                        "Ensure the Claude desktop app is running.");

                walCopied = false;
                DiagnosticLog.Write("  Strategy 3: dbCopied=true, walCopied=false (no WAL file)");
            }

            var cs = new SqliteConnectionStringBuilder
            {
                DataSource = tempDb,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString();

            using var conn = new SqliteConnection(cs);
            conn.Open();
            return ExecuteQuery(conn, decrypt);
        }
        finally
        {
            try { File.Delete(tempDb); } catch { }
            try { File.Delete(tempWal); } catch { }
        }
    }

    // Opens the source with FILE_SHARE_READ|WRITE|DELETE so we can read it while
    // another process (Claude, an AV scanner) has it open.
    private static void CopyShared(string src, string dst)
    {
        using var srcStream = new FileStream(src, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var dstStream = new FileStream(dst, FileMode.Create, FileAccess.Write,
            FileShare.None);
        srcStream.CopyTo(dstStream);
    }

    private static List<(string, string)> ExecuteQuery(SqliteConnection conn, Func<string, byte[], string> decrypt)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = CookieQuery;

        var results = new List<(string, string)>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var hostKey = reader.GetString(0);
            var name = reader.GetString(1);
            var encrypted = (byte[])reader["encrypted_value"];
            results.Add((name, decrypt(hostKey, encrypted)));
        }
        return results;
    }
}
