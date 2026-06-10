namespace ClaudeUsage.Services;

/// Front door for reading the Claude desktop app's session cookies. Dispatches
/// to the platform-specific implementation at runtime — this is the one place
/// the cross-platform app genuinely diverges per OS.
public static class ClaudeCookies
{
    // OrgId is the clean UUID used in URL paths.
    // RawOrgCookieValue is the full decrypted lastActiveOrg string sent back in Cookie headers.
    // ExtraCookies carries Cloudflare cookies (cf_clearance, __cf_bm) needed to pass bot detection.
    public sealed record Cookies(string SessionKey, string OrgId, string RawOrgCookieValue,
        IReadOnlyDictionary<string, string>? ExtraCookies = null);

    public static Cookies Read()
    {
        if (OperatingSystem.IsWindows())
            return WindowsCookieReader.Read();
        if (OperatingSystem.IsMacOS())
            return MacCookieReader.Read();
        if (OperatingSystem.IsLinux())
            return LinuxCookieReader.Read();

        throw new PlatformNotSupportedException(
            "Reading Claude desktop cookies is not implemented for this platform.");
    }
}
