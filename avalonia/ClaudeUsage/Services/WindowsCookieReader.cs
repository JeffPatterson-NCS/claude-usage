using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeUsage.Services;

/// Windows cookie reader: DPAPI-wrapped master key + AES-256-GCM cookies
/// (the Chromium "v10"/"v11" scheme). Counterpart to the macOS Keychain path.
[SupportedOSPlatform("windows")]
internal static class WindowsCookieReader
{
    public static ClaudeCookies.Cookies Read()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var baseDir = Path.Combine(appData, "Claude");
        var localStatePath = Path.Combine(baseDir, "Local State");

        // Newer Chromium stores cookies under Network/, older versions at the root.
        var cookiePath = Path.Combine(baseDir, "Network", "Cookies");
        if (!File.Exists(cookiePath))
            cookiePath = Path.Combine(baseDir, "Cookies");

        if (!File.Exists(localStatePath) || !File.Exists(cookiePath))
            throw new InvalidOperationException(
                "Claude desktop data not found — is the Claude desktop app installed and logged in?");

        var aesKey = ReadMasterKey(localStatePath);

        string? sessionKey = null, orgId = null;
        var extra = new Dictionary<string, string>();
        foreach (var (name, value) in CookieStore.ReadClaudeCookies(cookiePath, (host, enc) => DecryptValue(host, enc, aesKey)))
        {
            // First-wins: rows are ordered most-recently-accessed first, so the
            // first match for each name is the freshest and most likely correct.
            switch (name)
            {
                case "sessionKey" when sessionKey is null: sessionKey = value; break;
                case "lastActiveOrg" when orgId is null: orgId = value; break;
                case "cf_clearance" when !extra.ContainsKey("cf_clearance"): extra[name] = value; break;
                case "__cf_bm" when !extra.ContainsKey("__cf_bm"): extra[name] = value; break;
            }
        }

        if (string.IsNullOrEmpty(sessionKey))
            throw new InvalidOperationException("session key not found — log in via the Claude desktop app");
        if (string.IsNullOrEmpty(orgId))
            throw new InvalidOperationException("organization ID not found in cookies");

        // The decrypted lastActiveOrg value may have binary garbage prepended to
        // the UUID. Extract just the UUID portion so the URL stays well-formed.
        var rawOrgId = orgId;
        orgId = ExtractUuid(orgId) ?? orgId;
        DiagnosticLog.Write($"WindowsCookieReader: sessionKey.Length={sessionKey.Length}, " +
            $"sessionKey starts with sk-ant={sessionKey.StartsWith("sk-ant", StringComparison.Ordinal)}, orgId={orgId}" +
            (orgId != rawOrgId ? $" (extracted from {rawOrgId.Length}-char raw value)" : "") +
            $", cf_clearance={extra.ContainsKey("cf_clearance")}, __cf_bm={extra.ContainsKey("__cf_bm")}");
        DiagnosticLog.Write($"  Log file: {DiagnosticLog.LogPath}");

        return new ClaudeCookies.Cookies(sessionKey, orgId, rawOrgId, extra.Count > 0 ? extra : null);
    }

    private static byte[] ReadMasterKey(string localStatePath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(localStatePath));
        var encodedKey = doc.RootElement
            .GetProperty("os_crypt")
            .GetProperty("encrypted_key")
            .GetString()
            ?? throw new InvalidOperationException("os_crypt.encrypted_key missing from Local State");

        var blob = Convert.FromBase64String(encodedKey);

        const string dpapiPrefix = "DPAPI";
        if (blob.Length <= dpapiPrefix.Length ||
            Encoding.ASCII.GetString(blob, 0, dpapiPrefix.Length) != dpapiPrefix)
            throw new InvalidOperationException("unexpected encrypted_key format (missing DPAPI prefix)");

        var wrapped = blob[dpapiPrefix.Length..];
        return ProtectedData.Unprotect(wrapped, optionalEntropy: null, DataProtectionScope.CurrentUser);
    }

    private static readonly Regex UuidRegex =
        new(@"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static string? ExtractUuid(string value)
    {
        var m = UuidRegex.Match(value);
        return m.Success ? m.Value : null;
    }

    private static string DecryptValue(string hostKey, byte[] encrypted, byte[] key)
    {
        // v10 / v11: AES-256-GCM. Layout: [3-byte prefix][12 nonce][cipher][16 tag]
        if (encrypted.Length > 3 &&
            encrypted[0] == (byte)'v' && encrypted[1] == (byte)'1' &&
            (encrypted[2] == (byte)'0' || encrypted[2] == (byte)'1'))
        {
            const int nonceLen = 12, tagLen = 16;
            if (encrypted.Length < 3 + nonceLen + tagLen)
                throw new InvalidOperationException("cookie ciphertext too short");

            var nonce = encrypted.AsSpan(3, nonceLen);
            var cipherLen = encrypted.Length - 3 - nonceLen - tagLen;
            var cipher = encrypted.AsSpan(3 + nonceLen, cipherLen);
            var tag = encrypted.AsSpan(encrypted.Length - tagLen, tagLen);

            var plain = new byte[cipherLen];
            using var gcm = new AesGcm(key, tagLen);
            gcm.Decrypt(nonce, cipher, tag, plain);
            return DecodePlaintext(hostKey, plain);
        }

        // Legacy (pre-v10) values are wrapped directly with DPAPI.
        var decrypted = ProtectedData.Unprotect(encrypted, optionalEntropy: null, DataProtectionScope.CurrentUser);
        return DecodePlaintext(hostKey, decrypted);
    }

    /// Since Chromium cookie-DB meta version 24 (Chrome ~130+), the decrypted
    /// plaintext is SHA-256(host_key) followed by the value — the hash binds the
    /// value to its row. Strip the 32-byte prefix only when it verifies, so
    /// older databases without the prefix pass through unchanged.
    private static string DecodePlaintext(string hostKey, byte[] plain)
    {
        const int hashLen = 32;
        if (plain.Length >= hashLen &&
            plain.AsSpan(0, hashLen).SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes(hostKey))))
        {
            return Encoding.UTF8.GetString(plain, hashLen, plain.Length - hashLen);
        }

        // Latin-1 maps each byte 0x00–0xFF to the same Unicode code point, so any
        // residual binary bytes round-trip without loss.
        return Encoding.Latin1.GetString(plain);
    }
}
