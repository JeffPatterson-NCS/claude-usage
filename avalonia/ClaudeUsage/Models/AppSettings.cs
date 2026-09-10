using System.Text.Json.Serialization;

namespace ClaudeUsage.Models;

/// User-editable local settings, persisted via AppSettingsStore.
///
/// Enterprise NCS seats don't get the billing permission /rate_limits requires,
/// so on that account type we skip the call and fall back to a locally-set plan
/// label and spend cap instead of what the API would otherwise report.
public sealed class AppSettings
{
    [JsonPropertyName("isEnterpriseAccount")] public bool IsEnterpriseAccount { get; set; }
    [JsonPropertyName("planLabel")] public string PlanLabel { get; set; } = "Enterprise (Team)";
    [JsonPropertyName("monthlySpendCapUsd")] public double MonthlySpendCapUsd { get; set; } = 2000;
}
