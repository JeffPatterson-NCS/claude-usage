using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ClaudeUsage.Services;

/// Copies a file that another process holds with exclusive sharing by
/// duplicating that process's open file handle. This bypasses Win32 sharing
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
    private const uint PAGE_READONLY = 0x02;
    private const uint FILE_MAP_READ = 0x04;
    private const long MaxReasonableSize = 200 * 1024 * 1024; // 200 MB sanity cap

    /// <summary>
    /// Copies <paramref name="sourcePath"/> to <paramref name="destPath"/> by
    /// finding Claude's open handle and duplicating it. Returns true on success.
    /// </summary>
    public static bool TryCopy(string sourcePath, string destPath)
    {
        var canonical = Path.GetFullPath(sourcePath);
        var found = false;

        // GetFinalPathNameByHandleW can block indefinitely on Electron's named-pipe
        // handles (Node IPC). Run the whole enumeration on a background thread with
        // a hard timeout so the caller is never hung.
        var worker = new Thread(() =>
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (!proc.ProcessName.Equals("claude", StringComparison.OrdinalIgnoreCase))
                    continue;
                try { if (TryCopyFromProcess(proc.Id, canonical, destPath)) { found = true; return; } }
                catch { }
            }
        }) { IsBackground = true };

        worker.Start();
        worker.Join(8_000);
        return found;
    }

    private static bool TryCopyFromProcess(int pid, string canonical, string dest)
    {
        var procH = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, false, pid);
        if (procH == IntPtr.Zero) return false;
        try { return EnumerateAndCopy(procH, canonical, dest); }
        finally { CloseHandle(procH); }
    }

    private static bool EnumerateAndCopy(IntPtr procH, string canonical, string dest)
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
                if (st != 0) return false;
                break;
            }

            // Buffer layout: [UIntPtr count][UIntPtr reserved][HandleEntry * count]
            var count = (long)(ulong)Marshal.PtrToStructure<UIntPtr>(buf);
            var entryBase = new IntPtr(buf.ToInt64() + IntPtr.Size * 2);
            var stride = Marshal.SizeOf<HandleEntry>();

            for (long i = 0; i < count; i++)
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
                    var pathBuf = new char[32768];
                    var n = GetFinalPathNameByHandleW(dup, pathBuf, (uint)pathBuf.Length, 0);
                    if (n == 0) continue;

                    var p = new string(pathBuf, 0, (int)n);
                    if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
                    if (!string.Equals(p, canonical, StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (!GetFileSizeEx(dup, out var size) || size <= 0 || size > MaxReasonableSize)
                        continue;

                    // Read via memory-mapped view to avoid advancing the file position
                    // in Claude's handle (which shares the same kernel file object).
                    var map = CreateFileMappingW(dup, IntPtr.Zero, PAGE_READONLY, 0, 0, IntPtr.Zero);
                    if (map == IntPtr.Zero) continue;
                    try
                    {
                        var view = MapViewOfFile(map, FILE_MAP_READ, 0, 0, UIntPtr.Zero);
                        if (view == IntPtr.Zero) continue;
                        try
                        {
                            var bytes = new byte[(int)size];
                            Marshal.Copy(view, bytes, 0, (int)size);
                            File.WriteAllBytes(dest, bytes);
                            return true;
                        }
                        finally { UnmapViewOfFile(view); }
                    }
                    finally { CloseHandle(map); }
                }
                finally { CloseHandle(dup); }
            }
            return false;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }
}
