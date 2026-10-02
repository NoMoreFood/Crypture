using Microsoft.Win32;
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using ZXing;
using ZXing.Common;

namespace Crypture
{
    public partial class TotpPanel : UserControl
    {
        private readonly DispatcherTimer oTimer;
        private TotpSecret oSecret;
        private bool bLoading = true;
        private bool bActive;
        private bool bHasSetup;
        private int nQrImport;
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
            nQrImport++;
            oSetupFields.IsEnabled = true;
            oQrImportStatus.Text = "";
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
            ApplyDefaults();
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
            bHasSetup = true;
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

        private void ApplyDefaults()
        {
            if (bHasSetup) return;

            // Imported and saved setups keep their protocol settings; only empty setups use these defaults.
            ConfigurationDefaults oDefaults = new ConfigurationDefaults("Totp");
            string sAlgorithm = oDefaults.Choice("Algorithm", "SHA1", "SHA1", "SHA256", "SHA512");
            int nDigits = Int32.Parse(oDefaults.Choice("Digits", "6", "6", "8"), CultureInfo.InvariantCulture);
            int nPeriod = oDefaults.Number("PeriodSeconds", 30, 1, 3600);
            string sIssuer = oDefaults.Text("Issuer", "").Trim();
            string sAccount = oDefaults.Text("Account", "").Trim();
            if (sIssuer.Length > 256 || sAccount.Length > 256 || sIssuer.Contains(':') || sAccount.Contains(':') ||
                sIssuer.Any(Char.IsControl) || sAccount.Any(Char.IsControl))
                throw oDefaults.Error("TotpIssuer and TotpAccount must be at most 256 characters, " +
                    "without colons or control characters.");
            bLoading = true;
            try
            {
                oAlgorithm.SelectedValue = sAlgorithm;
                oDigits.SelectedValue = nDigits.ToString(CultureInfo.InvariantCulture);
                oPeriod.Text = nPeriod.ToString(CultureInfo.InvariantCulture);
                oIssuer.Text = sIssuer;
                oAccount.Text = sAccount;
                bHasSetup = true;
            }
            finally
            {
                bLoading = false;
            }
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

        internal static TotpSecret ReadQrFile(string sPath)
        {
            using FileStream oFile = File.OpenRead(sPath);
            if (oFile.Length > Utilities.MaxItemSize)
                throw new InvalidOperationException("Image files must be no larger than 64 MB.");
            return ReadQrImage(BitmapFrame.Create(oFile, BitmapCreateOptions.IgnoreColorProfile,
                BitmapCacheOption.None));
        }

        internal static TotpSecret ReadQrImage(BitmapSource oImage)
        {
            if (oImage == null || (long)oImage.PixelWidth * oImage.PixelHeight > Utilities.MaxItemSize / 4)
                throw new InvalidOperationException("Choose an image containing a setup QR code, " +
                    "and crop it to the code if the image is too large.");

            // Normalize WPF image formats, including transparency, without external imaging dependencies.
            FormatConvertedBitmap oBitmap = new FormatConvertedBitmap(oImage, PixelFormats.Bgra32, null, 0);
            int nStride = oBitmap.PixelWidth * 4;
            byte[] oPixels = new byte[nStride * oBitmap.PixelHeight];
            try
            {
                oBitmap.CopyPixels(oPixels, nStride, 0);
                RGBLuminanceSource oSource = new RGBLuminanceSource(oPixels, oBitmap.PixelWidth,
                    oBitmap.PixelHeight, RGBLuminanceSource.BitmapFormat.BGRA32);
                BarcodeReaderGeneric oReader = new BarcodeReaderGeneric
                {
                    AutoRotate = true,
                    Options = new DecodingOptions { PossibleFormats = [BarcodeFormat.QR_CODE], TryHarder = true }
                };

                // Scan both polarities and reject ambiguous setups instead of choosing an account silently.
                string[] oLinks = new[] { oSource, oSource.invert() }
                    .SelectMany(s => oReader.DecodeMultiple(s) ?? [])
                    .Select(r => r.Text?.Trim())
                    .Where(s => s != null && s.StartsWith("otpauth:", StringComparison.OrdinalIgnoreCase))
                    .Distinct(StringComparer.Ordinal).ToArray();
                if (oLinks.Length != 1)
                    throw new InvalidOperationException(oLinks.Length == 0
                        ? "No authenticator setup QR code was found. Choose a clear image of a TOTP setup code."
                        : "More than one authenticator setup QR code was found. Crop the image to the code to import.");
                return TotpSecret.Parse(oLinks[0]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oPixels);
            }
        }

        internal async Task ImportQrCodeAsync(Func<TotpSecret> oReadCode)
        {
            if (!bActive || !IsEnabled || !oSetupFields.IsEnabled) return;
            int nImport = ++nQrImport;
            oSetupFields.IsEnabled = false;
            oQrImportStatus.Text = "Reading QR code...";
            try
            {
                // Decode off the dispatcher; locking or changing item type invalidates the pending result.
                using TotpSecret oValue = await Task.Run(oReadCode);
                if (nImport == nQrImport && bActive && IsEnabled) ApplySecret(oValue);
            }
            catch (Exception) when (nImport != nQrImport || !bActive || !IsEnabled) { }
            finally
            {
                if (nImport == nQrImport)
                {
                    oSetupFields.IsEnabled = true;
                    oQrImportStatus.Text = "";
                }
            }
        }

        private async void oImportQrImage_Click(object sender, RoutedEventArgs e)
        {
            if (!bActive || !IsEnabled || !oSetupFields.IsEnabled) return;
            OpenFileDialog oDialog = new OpenFileDialog
            {
                Title = "Import Authenticator QR Code",
                Filter = "Image Files (*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff)|" +
                    "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff|All Files (*.*)|*.*"
            };
            if (oDialog.ShowDialog(Window.GetWindow(this)) != true) return;
            await Utilities.TryOperationAsync(Window.GetWindow(this),
                () => ImportQrCodeAsync(() => ReadQrFile(oDialog.FileName)));
        }

        private async void oPasteQrImage_Click(object sender, RoutedEventArgs e)
        {
            if (!bActive || !IsEnabled || !oSetupFields.IsEnabled) return;
            await Utilities.TryOperationAsync(Window.GetWindow(this), () =>
            {
                // Clipboard access stays on the UI thread; freeze the snapshot before background decoding.
                BitmapSource oImage = Clipboard.GetImage() ?? throw new InvalidOperationException(
                    "Copy an image or screenshot containing a setup QR code first.");
                oImage.Freeze();
                return ImportQrCodeAsync(() => ReadQrImage(oImage));
            });
        }

        private void oGenerateSecret_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(Window.GetWindow(this), () =>
            {
                ApplyDefaults();
                oSecretInput.Text = TotpSecret.Generate((string)oAlgorithm.SelectedValue);
            });
        }

        internal void Clear()
        {
            nQrImport++;
            oSetupFields.IsEnabled = true;
            oQrImportStatus.Text = "";
            bActive = false;
            oTimer.Stop();
            oSecret?.Dispose();
            oSecret = null;
            bHasSetup = false;
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
