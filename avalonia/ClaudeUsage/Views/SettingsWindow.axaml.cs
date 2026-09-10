using System.Globalization;
using Avalonia.Controls;
using ClaudeUsage.Models;
using ClaudeUsage.Services;

namespace ClaudeUsage.Views;

/// Editable local settings: enterprise-account toggle, fallback plan label
/// and monthly spend cap used when /rate_limits isn't available.
public partial class SettingsWindow : Window
{
    /// Raised after Save persists new settings, so the caller can refresh.
    public event Action? SettingsSaved;

    public SettingsWindow()
    {
        InitializeComponent();

        var settings = AppSettingsStore.Load();
        EnterpriseCheckBox.IsChecked = settings.IsEnterpriseAccount;
        PlanLabelBox.Text = settings.PlanLabel;
        SpendCapBox.Text = settings.MonthlySpendCapUsd.ToString(CultureInfo.InvariantCulture);

        CancelButton.Click += (_, _) => Close();
        SaveButton.Click += (_, _) => Save();
    }

    private void Save()
    {
        var cap = double.TryParse(SpendCapBox.Text, NumberStyles.Number, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 2000;

        AppSettingsStore.Save(new AppSettings
        {
            IsEnterpriseAccount = EnterpriseCheckBox.IsChecked ?? false,
            PlanLabel = string.IsNullOrWhiteSpace(PlanLabelBox.Text) ? "Team" : PlanLabelBox.Text.Trim(),
            MonthlySpendCapUsd = cap,
        });

        SettingsSaved?.Invoke();
        Close();
    }
}
