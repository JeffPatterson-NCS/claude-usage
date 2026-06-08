using Microsoft.Data.Sqlite;

namespace ClaudeUsage.Services;

/// Shared Chromium cookie-DB reading. The SQLite schema is identical across
/// platforms; only the per-value decryption differs, so callers pass a decrypt
/// delegate.
internal static class CookieStore
{
    private const string CookieQuery =
        """
        SELECT name, encrypted_value
        FROM cookies
        WHERE (host_key LIKE '%claude.ai%' OR host_key LIKE '%anthropic.com%')
          AND name IN ('sessionKey', 'lastActiveOrg')
        """;

    public static IEnumerable<(string Name, string Value)> ReadClaudeCookies(
        string cookiePath, Func<byte[], string> decrypt)
    {
        // Strategy 1: open the live DB with immutable=1 (bypasses WAL/SHM entirely).
        // Retry up to 3 times because Windows Defender and other AV products
        // transiently lock SQLite files during scans — Chromium's own code does the
        // same retry loop for this exact reason.
        Exception? lastEx = null;
        for (int i = 0; i < 3; i++)
        {
            if (i > 0) Thread.Sleep(150 * i);
            try { return QueryDirect(cookiePath, decrypt); }
            catch (Exception ex) { lastEx = ex; }
        }

        // Strategy 2: copy the DB (plus its WAL file if present) to a temp location
        // and open the copy. This covers cases where the immutable open fails
        // because the SHM file is exclusively held by Claude.
        Exception? copyEx = null;
        try { return QueryViaCopy(cookiePath, decrypt); }
        catch (Exception ex) { copyEx = ex; }

        // Strategy 3 (Windows only): Claude holds the file with exclusive sharing,
        // which blocks both SQLite opens and FileStream copies. DuplicateHandle lets
        // us read through Claude's existing handle without triggering a sharing check.
        if (OperatingSystem.IsWindows())
        {
            try { return QueryViaHandleDuplicate(cookiePath, decrypt); }
            catch (Exception dupEx)
            {
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

    private static IEnumerable<(string, string)> QueryDirect(string cookiePath, Func<byte[], string> decrypt)
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

    private static IEnumerable<(string, string)> QueryViaCopy(string cookiePath, Func<byte[], string> decrypt)
    {
        var tempDb = Path.Combine(Path.GetTempPath(), $"claude-cookies-{Guid.NewGuid():N}.db");
        var tempWal = tempDb + "-wal";
        var walPath = cookiePath + "-wal";

        try
        {
            CopyShared(cookiePath, tempDb);
            if (File.Exists(walPath))
                CopyShared(walPath, tempWal);

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
    private static IEnumerable<(string, string)> QueryViaHandleDuplicate(
        string cookiePath, Func<byte[], string> decrypt)
    {
        var tempDb = Path.Combine(Path.GetTempPath(), $"claude-cookies-{Guid.NewGuid():N}.db");
        var tempWal = tempDb + "-wal";
        var walPath = cookiePath + "-wal";
        try
        {
            if (!WindowsLockedFileCopier.TryCopy(cookiePath, tempDb))
                throw new InvalidOperationException(
                    "Could not find or duplicate Claude's file handle for the Cookies database. " +
                    "Ensure the Claude desktop app is running.");

            // Best-effort copy of the WAL file — the main DB may be sufficient without it.
            if (File.Exists(walPath))
            {
                try { CopyShared(walPath, tempWal); }
                catch { WindowsLockedFileCopier.TryCopy(walPath, tempWal); }
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

    private static List<(string, string)> ExecuteQuery(SqliteConnection conn, Func<byte[], string> decrypt)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = CookieQuery;

        var results = new List<(string, string)>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var name = reader.GetString(0);
            var encrypted = (byte[])reader["encrypted_value"];
            results.Add((name, decrypt(encrypted)));
        }
        return results;
    }
}
