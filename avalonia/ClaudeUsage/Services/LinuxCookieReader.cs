using System.Runtime.Versioning;

namespace ClaudeUsage.Services;

/// Linux cookie reader: Chromium on Linux uses the hardcoded password "peanuts"
/// (no keychain), then the same PBKDF2 + AES-128-CBC scheme as macOS.
[SupportedOSPlatform("linux")]
internal static class LinuxCookieReader
{
    public static ClaudeCookies.Cookies Read()
    {
        var aesKey = UnixCookieDecryptor.DeriveKey("peanuts");

        var configHome = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var baseDir = Path.Combine(configHome, "Claude");

        var cookiePath = Path.Combine(baseDir, "Cookies");
        if (!File.Exists(cookiePath))
            cookiePath = Path.Combine(baseDir, "Network", "Cookies");
        if (!File.Exists(cookiePath))
            throw new InvalidOperationException(
                "Claude cookie store not found — is the Claude desktop app installed and logged in?");

        string? sessionKey = null, orgId = null;
        foreach (var (name, value) in CookieStore.ReadClaudeCookies(cookiePath, (_, enc) => UnixCookieDecryptor.DecryptCookie(enc, aesKey)))
        {
            switch (name)
            {
                case "sessionKey": sessionKey = value; break;
                case "lastActiveOrg": orgId = value; break;
            }
        }

        if (string.IsNullOrEmpty(sessionKey))
            throw new InvalidOperationException("session key not found — log in via the Claude desktop app");
        if (string.IsNullOrEmpty(orgId))
            throw new InvalidOperationException("organization ID not found in cookies");

        return new ClaudeCookies.Cookies(sessionKey, orgId, orgId);
    }
}
