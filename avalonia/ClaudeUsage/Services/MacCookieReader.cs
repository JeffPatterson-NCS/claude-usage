using System.Diagnostics;
using System.Runtime.Versioning;

namespace ClaudeUsage.Services;

/// macOS cookie reader: derives the AES key from the "Claude Safe Storage"
/// Keychain entry, then delegates to UnixCookieDecryptor for the actual
/// AES-128-CBC decryption (same scheme as Linux, different password source).
[SupportedOSPlatform("macos")]
internal static class MacCookieReader
{
    public static ClaudeCookies.Cookies Read()
    {
        var aesKey = UnixCookieDecryptor.DeriveKey(ReadKeychainPassword());

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var cookiePath = Path.Combine(home, "Library", "Application Support", "Claude", "Cookies");
        if (!File.Exists(cookiePath))
            cookiePath = Path.Combine(home, "Library", "Application Support", "Claude", "Network", "Cookies");
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

    private static string ReadKeychainPassword()
    {
        var psi = new ProcessStartInfo("security")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("find-generic-password");
        psi.ArgumentList.Add("-s"); psi.ArgumentList.Add("Claude Safe Storage");
        psi.ArgumentList.Add("-a"); psi.ArgumentList.Add("Claude Key");
        psi.ArgumentList.Add("-w");

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("could not launch the 'security' tool");
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit();
        if (proc.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
            throw new InvalidOperationException("keychain lookup failed (is Claude desktop installed?)");

        return output.Trim();
    }
}
