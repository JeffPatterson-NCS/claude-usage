using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using ClaudeUsage.Models;

namespace ClaudeUsage.Services;

/// Fetches live plan usage from the Claude.ai API using the Claude desktop
/// app's session cookies. Counterpart to api.go.
public sealed class UsageApi
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    public sealed record Result(PlanUsage Usage, RateLimits? Limits);

    /// <param name="includeRateLimits">
    /// Skip on enterprise seats: /rate_limits requires a billing permission
    /// (<c>permission_billing_view</c>/<c>permission_billing_manage</c>/<c>permission_organization_owner</c>)
    /// that NCS IT won't grant on a non-admin seat, and the call would just 403.
    /// </param>
    public static async Task<Result> LoadAsync(bool includeRateLimits)
    {
        // Cookie reading touches the filesystem, SQLite and DPAPI synchronously;
        // push it off the UI thread.
        var cookies = await Task.Run(ClaudeCookies.Read);
        DiagnosticLog.Write(
            $"UsageApi: sessionKey.Length={cookies.SessionKey.Length}, " +
            $"sessionKey.StartsWith(sk-ant)={cookies.SessionKey.StartsWith("sk-ant", StringComparison.Ordinal)}, " +
            $"orgId={cookies.OrgId}");

        var usage = await FetchAsync<PlanUsage>(
            $"https://claude.ai/api/organizations/{cookies.OrgId}/usage", cookies.SessionKey);

        RateLimits? limits = null;
        if (includeRateLimits)
            limits = await FetchAsync<RateLimits>(
                $"https://claude.ai/api/organizations/{cookies.OrgId}/rate_limits", cookies.SessionKey);

        return new Result(usage, limits);
    }

    private static async Task<T> FetchAsync<T>(string url, string sessionKey)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Add("Cookie", $"sessionKey={sessionKey}");
        req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var resp = await Http.SendAsync(req);
        var json = await resp.Content.ReadAsStringAsync();
        DiagnosticLog.Write($"UsageApi: GET {url} -> {(int)resp.StatusCode}; body={json}");

        if (resp.StatusCode == HttpStatusCode.Unauthorized)
            throw new InvalidOperationException("session expired — open the Claude desktop app to refresh");
        if (resp.StatusCode == HttpStatusCode.Forbidden)
            throw new InvalidOperationException($"permission denied — {ExtractApiMessage(json) ?? json}");
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"HTTP {(int)resp.StatusCode}");

        return JsonSerializer.Deserialize<T>(json)
            ?? throw new InvalidOperationException("parsing response: empty result");
    }

    private static string? ExtractApiMessage(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("error").GetProperty("message").GetString();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
