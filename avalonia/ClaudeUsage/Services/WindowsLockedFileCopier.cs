using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ClaudeUsage.Services;

/// Copies files that another process holds with exclusive sharing by
/// duplicating that process's open file handles. This bypasses Win32 sharing
/// rules because DuplicateHandle operates on the kernel object directly —
/// no new CreateFile call is made, so no sharing check is triggered.
[SupportedOSPlatform("windows")]
internal static class WindowsLockedFileCopier
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc,
        out IntPtr dstHandle, uint access, bool inherit, uint opts);

    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        IntPtr h, char[] buf, uint bufLen, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileSizeEx(IntPtr h, out long size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateFileMappingW(
        IntPtr h, IntPtr sec, uint protect, uint hi, uint lo, IntPtr name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr MapViewOfFile(
        IntPtr map, uint access, uint hi, uint lo, UIntPtr bytes);

    [DllImport("kernel32.dll")] private static extern bool UnmapViewOfFile(IntPtr p);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(IntPtr h);

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryInformationProcess(
        IntPtr proc, int cls, IntPtr info, int len, out int returned);

    [StructLayout(LayoutKind.Sequential)]
    private struct HandleEntry
    {
        public IntPtr HandleValue;
        public UIntPtr HandleCount;
        public UIntPtr PointerCount;
        public uint GrantedAccess;
        public uint ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    private const uint PROCESS_DUP_HANDLE = 0x0040;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint DUPLICATE_SAME_ACCESS = 0x0002;
    private const int ProcessHandleInformation = 51;
    private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    private const uint FILE_TYPE_DISK = 0x0001;
    private const uint PAGE_READONLY = 0x02;
    private const uint FILE_MAP_READ = 0x04;
    private const long MaxReasonableSize = 200 * 1024 * 1024; // 200 MB sanity cap

    /// Copies sourcePath to destPath by finding Claude's open handle and
    /// duplicating it. Returns true on success.
    public static bool TryCopy(string sourcePath, string destPath)
    {
        var (dbCopied, _) = TryCopyWithWal(sourcePath, destPath, null, null);
        return dbCopied;
    }

    /// Copies both the main DB file and its WAL companion in a single
    /// handle-enumeration pass so only one 8-second timeout applies.
    /// Returns (DbCopied, WalCopied) — DbCopied is required for success,
    /// WalCopied is best-effort.
    public static (bool DbCopied, bool WalCopied) TryCopyWithWal(
        string dbPath, string dbDest, string? walPath, string? walDest)
    {
        var targets = new List<(string Canon, string Dest)>
        {
            (Path.GetFullPath(dbPath), dbDest)
        };
        if (walPath != null && walDest != null)
            targets.Add((Path.GetFullPath(walPath), walDest));

        var copied = new bool[targets.Count];

        var worker = new Thread(() =>
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (!proc.ProcessName.Equals("claude", StringComparison.OrdinalIgnoreCase))
                    continue;

                DiagnosticLog.Write($"  HandleDup: scanning pid={proc.Id} ({proc.ProcessName})");
                try { TryCopyFromProcess(proc.Id, targets, copied); }
                catch (Exception ex) { DiagnosticLog.Write($"  HandleDup pid={proc.Id} error: {ex.Message}"); }

                if (copied[0]) break; // primary found
            }
        }) { IsBackground = true };

        worker.Start();
        worker.Join(8_000);

        if (!worker.IsAlive)
            DiagnosticLog.Write($"  HandleDup: completed within timeout. db={copied[0]}, wal={copied.Length > 1 && copied[1]}");
        else
            DiagnosticLog.Write("  HandleDup: timed out after 8 s");

        return (copied[0], copied.Length > 1 && copied[1]);
    }

    private static void TryCopyFromProcess(
        int pid, IReadOnlyList<(string Canon, string Dest)> targets, bool[] copied)
    {
        var procH = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, false, pid);
        if (procH == IntPtr.Zero) return;
        try { EnumerateAndCopy(procH, targets, copied); }
        finally { CloseHandle(procH); }
    }

    private static void EnumerateAndCopy(
        IntPtr procH, IReadOnlyList<(string Canon, string Dest)> targets, bool[] copied)
    {
        int bufLen = 0x10000;
        var buf = IntPtr.Zero;
        try
        {
            while (true)
            {
                buf = Marshal.AllocHGlobal(bufLen);
                var st = NtQueryInformationProcess(procH, ProcessHandleInformation,
                    buf, bufLen, out int needed);
                if (st == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                    bufLen = needed + 0x1000;
                    continue;
                }
                if (st != 0) return;
                break;
            }

            // Buffer layout: [UIntPtr count][UIntPtr reserved][HandleEntry * count]
            var count = (long)(ulong)Marshal.PtrToStructure<UIntPtr>(buf);
            var entryBase = new IntPtr(buf.ToInt64() + IntPtr.Size * 2);
            var stride = Marshal.SizeOf<HandleEntry>();
            var remaining = targets.Count;

            DiagnosticLog.Write($"  HandleDup: {count} handles to scan for {targets.Count} target(s)");

            for (long i = 0; i < count && remaining > 0; i++)
            {
                var e = Marshal.PtrToStructure<HandleEntry>(
                    new IntPtr(entryBase.ToInt64() + i * stride));

                // Skip handles that clearly lack file read bits.
                if ((e.GrantedAccess & 0x0001u) == 0) continue;

                if (!DuplicateHandle(procH, e.HandleValue, GetCurrentProcess(),
                        out var dup, 0, false, DUPLICATE_SAME_ACCESS) || dup == IntPtr.Zero)
                    continue;

                try
                {
                    // Skip non-disk handles (pipes, sockets, etc.) before calling
                    // GetFinalPathNameByHandleW, which can hang indefinitely on
                    // Electron's named-pipe handles (Node.js IPC).
                    if (GetFileType(dup) != FILE_TYPE_DISK) continue;

                    var pathBuf = new char[32768];
                    var n = GetFinalPathNameByHandleW(dup, pathBuf, (uint)pathBuf.Length, 0);
                    if (n == 0) continue;

                    var p = new string(pathBuf, 0, (int)n);
                    if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];

                    for (int t = 0; t < targets.Count; t++)
                    {
                        if (copied[t]) continue;
                        if (!string.Equals(p, targets[t].Canon, StringComparison.OrdinalIgnoreCase))
                            continue;

                        DiagnosticLog.Write($"  HandleDup: found target[{t}] = {Path.GetFileName(p)}");

                        if (!GetFileSizeEx(dup, out var size) || size <= 0 || size > MaxReasonableSize)
                            break;

                        var map = CreateFileMappingW(dup, IntPtr.Zero, PAGE_READONLY, 0, 0, IntPtr.Zero);
                        if (map == IntPtr.Zero) break;
                        try
                        {
                            var view = MapViewOfFile(map, FILE_MAP_READ, 0, 0, UIntPtr.Zero);
                            if (view == IntPtr.Zero) break;
                            try
                            {
                                var bytes = new byte[(int)size];
                                Marshal.Copy(view, bytes, 0, (int)size);
                                File.WriteAllBytes(targets[t].Dest, bytes);
                                copied[t] = true;
                                remaining--;
                                DiagnosticLog.Write($"  HandleDup: copied target[{t}] ({size:N0} bytes)");
                            }
                            finally { UnmapViewOfFile(view); }
                        }
                        finally { CloseHandle(map); }
                        break;
                    }
                }
                finally { CloseHandle(dup); }
            }
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }
}
