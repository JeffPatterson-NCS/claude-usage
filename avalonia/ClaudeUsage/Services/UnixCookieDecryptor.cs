using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ClaudeUsage.Services;

/// Shared Chromium cookie decryption for Unix platforms (macOS and Linux).
/// Both use PBKDF2(SHA-1, "saltysalt", 1003 iterations) to derive a 16-byte AES
/// key; the only difference between platforms is how the password is sourced.
internal static partial class UnixCookieDecryptor
{
    internal static byte[] DeriveKey(string password) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            Encoding.UTF8.GetBytes("saltysalt"),
            iterations: 1003,
            HashAlgorithmName.SHA1,
            outputLength: 16);

    internal static string DecryptCookie(byte[] encrypted, byte[] key)
    {
        if (encrypted.Length < 3 || Encoding.ASCII.GetString(encrypted, 0, 3) != "v10")
            return Encoding.UTF8.GetString(encrypted); // unencrypted (legacy)

        var ciphertext = encrypted.AsSpan(3).ToArray();
        if (ciphertext.Length == 0 || ciphertext.Length % 16 != 0)
            throw new InvalidOperationException("invalid ciphertext length");

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = Encoding.ASCII.GetBytes(new string(' ', 16));
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var dec = aes.CreateDecryptor();
        var plain = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        var text = Encoding.UTF8.GetString(plain);

        // Some builds prefix a nonce before the value; recover by pattern.
        var skIdx = text.IndexOf("sk-ant-", StringComparison.Ordinal);
        if (skIdx >= 0)
            return text[skIdx..];

        var uuid = UuidRegex().Match(text);
        if (uuid.Success)
            return uuid.Value;

        return text.TrimEnd('\0');
    }

    [GeneratedRegex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")]
    private static partial Regex UuidRegex();
}
