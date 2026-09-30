using System;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace Crypture
{
    public partial class TotpPanel : UserControl
    {
        private readonly DispatcherTimer oTimer;
        private TotpSecret oSecret;
        private bool bLoading = true;
        private bool bActive;
        internal Func<DateTimeOffset> Clock { get; set; } = () => DateTimeOffset.UtcNow;
        internal event EventHandler SettingsChanged;

        public TotpPanel()
        {
            InitializeComponent();
            Utilities.EnableClipboardTimeout(oCurrentCode);
            Utilities.EnableClipboardTimeout(oSecretInput);
            Utilities.EnableClipboardTimeout(oImportInput);
            oTimer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(250)
            };
            oTimer.Tick += (s, e) => RefreshCode();
            Loaded += (s, e) => UpdateTimer();
            IsEnabledChanged += (s, e) => UpdateTimer();
            Unloaded += (s, e) => Clear();
            bLoading = false;
        }

        internal void SetActive(bool bEnabled)
        {
            bActive = bEnabled;
            RefreshSecret();
            UpdateTimer();
        }

        private void UpdateTimer()
        {
            if (oTimer == null) return;
            if (bActive && IsLoaded && IsEnabled) oTimer.Start();
            else oTimer.Stop();
            RefreshCode();
        }

        private TotpSecret ReadSecret()
        {
            if (!Int32.TryParse(oPeriod.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int nPeriod))
                throw new InvalidOperationException("Enter a whole number for the rotation period.");
            return new TotpSecret(oSecretInput.Text, oIssuer.Text, oAccount.Text,
                (string)oAlgorithm.SelectedValue, Int32.Parse((string)oDigits.SelectedValue,
                    CultureInfo.InvariantCulture), nPeriod);
        }

        internal string ReadUri()
        {
            using TotpSecret oValue = ReadSecret();
            return oValue.ToUri();
        }

        internal void LoadUri(string sValue)
        {
            using TotpSecret oValue = TotpSecret.Parse(sValue);
            ApplySecret(oValue);
            oSetup.IsExpanded = false;
        }

        private void ApplySecret(TotpSecret oValue)
        {
            bLoading = true;
            try
            {
                oIssuer.Text = oValue.Issuer;
                oAccount.Text = oValue.Account;
                oSecretInput.Text = oValue.GetBase32();
                oAlgorithm.SelectedValue = oValue.Algorithm;
                oDigits.SelectedValue = oValue.Digits.ToString(CultureInfo.InvariantCulture);
                oPeriod.Text = oValue.Period.ToString(CultureInfo.InvariantCulture);
                oImportInput.Clear();
            }
            finally
            {
                bLoading = false;
            }
            RefreshSecret();
            SettingsChanged?.Invoke(this, EventArgs.Empty);
        }

        private void oOptionsChanged(object sender, RoutedEventArgs e)
        {
            if (bLoading) return;
            RefreshSecret();
            SettingsChanged?.Invoke(this, EventArgs.Empty);
        }

        private void RefreshSecret()
        {
            oSecret?.Dispose();
            oSecret = null;
            oValidationMessage.Text = "";
            if (bActive)
            {
                try
                {
                    oSecret = ReadSecret();
                }
                catch (InvalidOperationException oError)
                {
                    oValidationMessage.Text = oError.Message;
                }
            }
            oAccountTitle.Text = String.IsNullOrWhiteSpace(oIssuer.Text) ? oAccount.Text :
                oIssuer.Text + (String.IsNullOrWhiteSpace(oAccount.Text) ? "" : " · " + oAccount.Text);
            RefreshCode();
        }

        internal void RefreshCode()
        {
            if (!bActive || !IsEnabled || oSecret == null)
            {
                oCurrentCode.Clear();
                oRemainingText.Text = "";
                oRemainingProgress.Value = 0;
                oCopyCode.IsEnabled = false;
                oCopySetup.IsEnabled = false;
                return;
            }
            try
            {
                // Recompute from wall-clock time so sleep, resume, and clock corrections do not drift.
                DateTimeOffset oNow = Clock();
                oCurrentCode.Text = oSecret.GetCode(oNow);
                oValidationMessage.Text = "";
                double nRemaining = oSecret.SecondsRemaining(oNow);
                oRemainingProgress.Maximum = oSecret.Period;
                oRemainingProgress.Value = nRemaining;
                oRemainingText.Text = "Next Code in " + Math.Ceiling(nRemaining)
                    .ToString(CultureInfo.InvariantCulture) + " Seconds";
                oCopyCode.IsEnabled = true;
                oCopySetup.IsEnabled = true;
            }
            catch (InvalidOperationException oError)
            {
                oCurrentCode.Clear();
                oCopyCode.IsEnabled = false;
                oCopySetup.IsEnabled = false;
                oRemainingProgress.Value = 0;
                oRemainingText.Text = "";
                oValidationMessage.Text = oError.Message;
            }
        }

        private void oCopyCode_Click(object sender, RoutedEventArgs e)
        {
            RefreshCode();
            if (oCopyCode.IsEnabled)
                Utilities.TryOperation(Window.GetWindow(this), () => App.CopyProtectedText(oCurrentCode.Text));
        }

        private void oCopySetup_Click(object sender, RoutedEventArgs e)
        {
            if (bActive && oSecret != null)
                Utilities.TryOperation(Window.GetWindow(this), () => App.CopyProtectedText(oSecret.ToUri()));
        }

        private void oImport_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(Window.GetWindow(this), () =>
            {
                string sInput = oImportInput.Text.Trim();
                using TotpSecret oValue = TotpSecret.Parse(sInput);
                if (sInput.StartsWith("otpauth:", StringComparison.OrdinalIgnoreCase)) ApplySecret(oValue);
                else
                {
                    oSecretInput.Text = oValue.GetBase32();
                    oImportInput.Clear();
                }
            });
        }

        private void oGenerateSecret_Click(object sender, RoutedEventArgs e)
        {
            oSecretInput.Text = TotpSecret.Generate((string)oAlgorithm.SelectedValue);
        }

        internal void Clear()
        {
            bActive = false;
            oTimer.Stop();
            oSecret?.Dispose();
            oSecret = null;
            bLoading = true;
            oSecretInput.Clear();
            oImportInput.Clear();
            oIssuer.Clear();
            oAccount.Clear();
            bLoading = false;
            oSetup.IsExpanded = true;
            oAccountTitle.Text = "";
            oValidationMessage.Text = "";
            RefreshCode();
        }
    }
}
