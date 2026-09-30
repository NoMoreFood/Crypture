using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Crypture
{
    public partial class VaultHealthWindow : Window
    {
        private readonly string sVaultPath;
        private CancellationTokenSource oCancellation;
        private VaultHealthReport oReport;
        private bool bClosed;

        public VaultHealthWindow(string sPath)
        {
            InitializeComponent();
            Utilities.EnableClipboardTimeout(oDetails);
            sVaultPath = sPath;
            oVaultName.Text = Path.GetFileName(sPath);
            oVaultName.ToolTip = sPath;
        }

        private async void oRunButton_Click(object sender, RoutedEventArgs e)
        {
            if (oCancellation != null || bClosed) return;
            bool bAllowSelfSigned = Properties.Settings.Default.AllowSelfSignedCertificates;
            bool bCheckRevocation = Properties.Settings.Default.PerformCertificateRevocationCheck;
            oPolicy.Text = "Revocation Checks: " + (bCheckRevocation ? "On" : "Off") +
                "    |    Self-Signed Certificates: " + (bAllowSelfSigned ? "Allowed" : "Not Allowed");
            oCancellation = new CancellationTokenSource();
            CancellationToken oToken = oCancellation.Token;
            oReport = null;
            oResults.ItemsSource = null;
            oDetails.Clear();
            oRunButton.IsEnabled = false;
            oCancelButton.IsEnabled = true;
            oIssuesOnly.IsEnabled = false;
            oSummary.Text = "Checking Vault...";
            oProgressText.Text = "Reading saved Vault recipients...";
            Progress<string> oProgress = new Progress<string>(s =>
            {
                if (!bClosed && oCancellation != null && oCancellation.Token == oToken &&
                    !oToken.IsCancellationRequested && oReport == null) oProgressText.Text = s;
            });
            try
            {
                VaultHealthReport oCompleted = await Task.Run(() => VaultHealthCheck.Run(
                    sVaultPath, bAllowSelfSigned, bCheckRevocation, oToken, oProgress));
                oToken.ThrowIfCancellationRequested();
                if (bClosed) return;
                oReport = oCompleted;
                oSummary.Text = oReport.Findings.Count == 0
                    ? "No saved recipients or certificates to check." : oReport.Summary;
                oProgressText.Text = oReport.ItemCount + " saved items checked at " +
                    oReport.CheckedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") + ".";
                ShowResults();
            }
            catch (OperationCanceledException)
            {
                if (bClosed) return;
                oSummary.Text = "Health Check Canceled";
                oProgressText.Text = "The check did not complete. Run it again to obtain a complete report.";
            }
            catch (Exception oError)
            {
                if (bClosed) return;
                oSummary.Text = "Health Check Could Not Complete";
                oProgressText.Text = "No complete report is available.";
                oDetails.Text = oError.GetBaseException().Message;
            }
            finally
            {
                oCancellation.Dispose();
                oCancellation = null;
                if (!bClosed)
                {
                    oRunButton.IsEnabled = true;
                    oCancelButton.IsEnabled = false;
                    oIssuesOnly.IsEnabled = oReport != null;
                }
            }
        }

        private void ShowResults()
        {
            if (oReport == null) return;
            var oFindings = oReport.Findings.Where(f => oIssuesOnly.IsChecked != true ||
                f.Severity >= HealthStatus.Warning).ToList();
            oResults.ItemsSource = oFindings;
            if (oFindings.Count > 0) oResults.SelectedIndex = 0;
            else oDetails.Text = oReport.Findings.Count == 0 ? "The Vault has no saved recipients or certificates." :
                "No errors or warnings were found. Clear Show Only Issues to review passed and informational results.";
        }

        private void oResults_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (oDetails != null)
                oDetails.Text = (oResults.SelectedItem as HealthCheckFinding)?.FullDetails ?? "";
        }

        private void oIssuesOnly_Click(object sender, RoutedEventArgs e)
        {
            ShowResults();
        }

        private void oCancelButton_Click(object sender, RoutedEventArgs e)
        {
            oCancellation?.Cancel();
            oCancelButton.IsEnabled = false;
            oProgressText.Text = "Canceling after the current Windows lookup finishes. You can close this window.";
        }

        private void oCloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void oWindow_Closed(object sender, EventArgs e)
        {
            bClosed = true;
            oCancellation?.Cancel();
        }
    }
}
