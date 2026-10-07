using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;

namespace Crypture
{
    /// <summary>
    /// Interaction logic for CertWizard.xaml
    /// </summary>
    public partial class CertWizard : ThemedWindow
    {
        public string SelectedProvider { get; set; }
        public string SelectedSignature { get; set; }
        public string SelectedHash { get; set; }

        public class EkuOption
        {
            public bool Selected { get; set; } = false;
            public string Name { get; set; } = "";
            public string Oid { get; set; } = "";
        }

        public class ProviderDetails
        {
            public bool IsHardware = false;
            public bool IsLegacy = false;
            public List<string> HashAlgorithmns = new List<string>();
            public List<string> SignatureAlgorithmns = new List<string>();
            public Dictionary<string, int> SignatureMinLengths = new Dictionary<string, int>();
            public Dictionary<string, int> SignatureMaxLengths = new Dictionary<string, int>();
        }

        public Dictionary<string, ProviderDetails> ProviderOptions { get; } = new Dictionary<string, ProviderDetails>();
        public ObservableCollection<EkuOption> KeyUsages { get; } = new ObservableCollection<EkuOption>();
        public ObservableCollection<EkuOption> EnhancedKeyUsages { get; } = new ObservableCollection<EkuOption>();

        private const string DefaultProviderName = "Microsoft Software Key Storage Provider";
        private static readonly object ProviderCacheLock = new object();
        private static Task<ProviderDetails> DefaultProviderCache;
        private static Task<Dictionary<string, ProviderDetails>> AvailableProviderCache;
        private readonly Func<bool, Task<ProviderDetails>> GetDefaultProvider;
        private readonly Func<bool, Task<Dictionary<string, ProviderDetails>>> GetAvailableProviders;
        private bool bUpdatingProviders;
        private bool bLoadingProviders;
        private bool bStarted;
        private bool bClosed;
        private bool bInitializing = true;
        private bool bGenerating;
        private readonly string sDefaultProvider;
        private readonly string sDefaultSignature;
        private readonly string sDefaultHash;
        private readonly int nDefaultKeyLength;
        private readonly X509KeyUsageFlags? oDefaultKeyUsages;

        public CertWizard() : this(GetDefaultProviderAsync, GetAvailableProvidersAsync)
        {
        }

        internal CertWizard(Func<bool, Task<ProviderDetails>> oGetDefaultProvider,
            Func<bool, Task<Dictionary<string, ProviderDetails>>> oGetAvailableProviders)
        {
            GetDefaultProvider = oGetDefaultProvider;
            GetAvailableProviders = oGetAvailableProviders;

            // Validate one configuration snapshot before initializing event-driven controls.
            // Supported key-length input range.
            const int MaximumKeyLengthBits = 16384;

            // Supported certificate validity input ranges.
            const int MaximumValidityDays = 36500;
            const int MaximumValidityYears = 100;
            ConfigurationDefaults oDefaults = new ConfigurationDefaults("CertificateGenerator");
            sDefaultProvider = oDefaults.Text("Provider", DefaultProviderName).Trim();
            sDefaultSignature = oDefaults.Text("KeyAlgorithm", "RSA").Trim().ToUpperInvariant();
            sDefaultHash = oDefaults.Text("HashAlgorithm", "SHA256").Trim().ToUpperInvariant();
            nDefaultKeyLength = oDefaults.Number("KeyLength", CertificateKeyProtection.MinimumRsaKeyBits,
                1, MaximumKeyLengthBits);
            int nStartOffset = oDefaults.Number("StartOffsetDays", 0, -MaximumValidityDays, MaximumValidityDays);
            int nYears = oDefaults.Number("ValidityYears", 3, 0, MaximumValidityYears);
            int nDays = oDefaults.Number("ValidityDays", 0, 0, MaximumValidityDays);
            string sStore = oDefaults.Choice("Store", "CurrentUser", "CurrentUser", "LocalMachine");
            bool bSelfSigned = oDefaults.Flag("SelfSigned", true);
            bool bHardware = oDefaults.Flag("ShowHardwareProviders", true);
            bool bSoftware = oDefaults.Flag("ShowSoftwareProviders", true);
            bool bLegacy = oDefaults.Flag("ShowLegacyProviders", false);
            bool bExportable = oDefaults.Flag("KeyExportable", false);
            bool bPasswordProtect = oDefaults.Flag("PasswordProtectKey", false);
            if (sDefaultProvider.Length == 0 || sDefaultSignature.Length == 0 || sDefaultHash.Length == 0 ||
                nYears + nDays == 0 || !bHardware && !bSoftware ||
                sDefaultSignature == "RSA" && nDefaultKeyLength < CertificateKeyProtection.MinimumRsaKeyBits)
                throw oDefaults.Error("CertificateGenerator defaults need a provider, algorithms, a positive " +
                    "validity period, at least one provider type, and an RSA key length of at least 2048 bits.");
            HashSet<string> oEnhancedUsages;
            try
            {
                string sUsages = oDefaults.Text("KeyUsages", "Automatic").Trim();
                oDefaultKeyUsages = sUsages.Equals("Automatic", StringComparison.OrdinalIgnoreCase) ? null :
                    CertificateUsageFilter.ParseKeyUsages(sUsages, "CertificateGeneratorKeyUsages");
                oEnhancedUsages = CertificateUsageFilter.ParseEnhancedUsages(
                    oDefaults.Text("EnhancedKeyUsages", ""), "CertificateGeneratorEnhancedKeyUsages");
            }
            catch (ConfigurationErrorsException oError)
            {
                throw oDefaults.Error(oError.Message);
            }
            InitializeComponent();

            // Initialize generation choices before providers finish loading.
            oValidFromDatePicker.SelectedDate = DateTime.Today.AddDays(nStartOffset);
            oValidUntilDatePicker.SelectedDate = oValidFromDatePicker.SelectedDate.Value
                .AddYears(nYears).AddDays(nDays);
            oSubjectTextBox.Text = oDefaults.Text("Subject", "");
            oIssuerTextBox.Text = oDefaults.Text("Issuer", "");
            oCertificateSelfSignedRadio.IsChecked = bSelfSigned;
            oCertificateRequestRadio.IsChecked = !bSelfSigned;
            oHardwareCheckbox.IsChecked = bHardware;
            oSoftwareCheckbox.IsChecked = bSoftware;
            oShowLegacyCheckbox.IsChecked = bLegacy;
            oKeyExportableCheckbox.IsChecked = bExportable;
            oPasswordProtectCheckbox.IsChecked = bPasswordProtect;

            // populate extended key usage options
            foreach (Oid oOid in NativeMethods.GetExtendedKeyUsages())
            {
                // skip weird looking or known problematic options
                if (oOid.FriendlyName.StartsWith("sz") ||
                    oOid.FriendlyName.StartsWith("@")) continue;

                // translate into our display structure
                EkuOption oKeyUsage = new EkuOption()
                {
                    Name = oOid.FriendlyName,
                    Oid = oOid.Value,
                    Selected = oEnhancedUsages.Contains(oOid.Value)
                };
                EnhancedKeyUsages.Add(oKeyUsage);
            }

            // Custom EKUs remain visible and editable even when Windows has no friendly name for them.
            foreach (string sOid in oEnhancedUsages.Where(s => !EnhancedKeyUsages.Any(o => o.Oid == s)))
                EnhancedKeyUsages.Add(new EkuOption { Name = sOid, Oid = sOid, Selected = true });

            // populate key usage options
            foreach (string sKeyUsage in Enum.GetNames(typeof(X509KeyUsageFlags)))
            {
                if (sKeyUsage == nameof(X509KeyUsageFlags.None)) continue;
                EkuOption oOpt = new EkuOption();
                oOpt.Name = Regex.Replace(sKeyUsage, "(\\B[A-Z])", " $1");
                oOpt.Oid = sKeyUsage;
                oOpt.Selected = sKeyUsage == nameof(X509KeyUsageFlags.KeyEncipherment);
                KeyUsages.Add(oOpt);
            }

            // set combobox to sort
            oProviderComboBox.Items.SortDescriptions.Add(new SortDescription("", ListSortDirection.Ascending));
            oKeyUsageCombobox.Items.SortDescriptions.Add(new SortDescription("Selected", ListSortDirection.Descending));
            oKeyUsageCombobox.Items.SortDescriptions.Add(new SortDescription("Name", ListSortDirection.Ascending));
            oEnhancedKeyUsageCombobox.Items.SortDescriptions.Add(
                new SortDescription("Selected", ListSortDirection.Descending));
            oEnhancedKeyUsageCombobox.Items.SortDescriptions.Add(
                new SortDescription("Name", ListSortDirection.Ascending));
            oProviderType_Checked(null, null);

            // disable machine store option if user is not an admin
            using (WindowsIdentity oIdentity = WindowsIdentity.GetCurrent())
                oCertificateStoreMachineRadio.IsEnabled = new WindowsPrincipal(oIdentity)
                    .IsInRole(WindowsBuiltInRole.Administrator);
            oCertificateStoreMachineRadio.IsChecked =
                sStore == "LocalMachine" && oCertificateStoreMachineRadio.IsEnabled;
            oCertificateStoreUserRadio.IsChecked = oCertificateStoreMachineRadio.IsChecked != true;
            bInitializing = false;
            UpdateGenerationControls();
        }

        private static dynamic CreateEnrollmentObject(string sClass)
        {
            return Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.C" + sClass, true));
        }

        private static Task<ProviderDetails> GetDefaultProviderAsync(bool bRefresh)
        {
            lock (ProviderCacheLock)
            {
                if (DefaultProviderCache == null || DefaultProviderCache.IsFaulted ||
                    (bRefresh && DefaultProviderCache.IsCompleted))
                    DefaultProviderCache = Task.Run(() =>
                    {
                        dynamic oCsp = CreateEnrollmentObject("CspInformation");
                        try
                        {
                            oCsp.InitializeFromName(DefaultProviderName);
                            return (ProviderDetails)ReadProviderDetails(oCsp);
                        }
                        finally
                        {
                            Marshal.FinalReleaseComObject(oCsp);
                        }
                    });
                return DefaultProviderCache;
            }
        }

        private static Task<Dictionary<string, ProviderDetails>> GetAvailableProvidersAsync(bool bRefresh)
        {
            lock (ProviderCacheLock)
            {
                if (AvailableProviderCache == null || AvailableProviderCache.IsFaulted ||
                    (bRefresh && AvailableProviderCache.IsCompleted))
                    AvailableProviderCache = Task.Run(() =>
                    {
                        // create a list of all csp providers
                        dynamic CspInformations = CreateEnrollmentObject("CspInformations");
                        try
                        {
                            CspInformations.AddAvailableCsps();
                            var oProviders = new Dictionary<string, ProviderDetails>();

                            // enumerate each provider
                            for (int nIndex = 0; nIndex < CspInformations.Count; nIndex++)
                            {
                                dynamic oCsp = CspInformations[nIndex];
                                try
                                {
                                    oProviders.Add(oCsp.Name, ReadProviderDetails(oCsp));
                                }
                                finally
                                {
                                    Marshal.FinalReleaseComObject(oCsp);
                                }
                            }
                            return oProviders;
                        }
                        finally
                        {
                            Marshal.FinalReleaseComObject(CspInformations);
                        }
                    });
                return AvailableProviderCache;
            }
        }

        private static ProviderDetails ReadProviderDetails(dynamic oCsp)
        {
            // CertEnroll algorithm interface identifiers.
            const int HashInterface = 2;
            const int AsymmetricEncryptionInterface = 3;
            const int SecretAgreementInterface = 4;
            const int SignatureInterface = 5;
            // create a structure for display purposes
            ProviderDetails oOpt = new ProviderDetails();
            oOpt.IsHardware = oCsp.IsSmartCard || oCsp.IsHardwareDevice;
            oOpt.IsLegacy = oCsp.LegacyCsp;
            dynamic oAlgorithms = oCsp.CspAlgorithms;
            try
            {
                // populate display structure with algorithmn information
                for (int nIndex = 0; nIndex < oAlgorithms.Count; nIndex++)
                {
                    dynamic oAlg = oAlgorithms[nIndex];
                    try
                    {
                        // special case: eliminate generic ecdsa that does not work
                        if (oAlg.Name.Equals("ECDSA")) continue;
                        if (oAlg.Name.StartsWith("ECDH", StringComparison.Ordinal) &&
                            oAlg.Name != "ECDH_P256" && oAlg.Name != "ECDH_P384" && oAlg.Name != "ECDH_P521") continue;

                        // hash algorithms
                        if (oAlg.Type == HashInterface)
                        {
                            if (oOpt.HashAlgorithmns.Contains(oAlg.Name)) continue;
                            oOpt.HashAlgorithmns.Add(oAlg.Name);
                        }

                        // signature algorithms
                        else if (oAlg.Type == SignatureInterface ||
                            oAlg.Type == AsymmetricEncryptionInterface ||
                            (oAlg.Type == SecretAgreementInterface &&
                                oAlg.Name.StartsWith("ECDH", StringComparison.Ordinal)))
                        {
                            if (oOpt.SignatureAlgorithmns.Contains(oAlg.Name)) continue;
                            oOpt.SignatureAlgorithmns.Add(oAlg.Name);
                            oOpt.SignatureMinLengths.Add(oAlg.Name, oAlg.MinLength);
                            oOpt.SignatureMaxLengths.Add(oAlg.Name, oAlg.MaxLength);
                        }
                    }
                    finally
                    {
                        Marshal.FinalReleaseComObject(oAlg);
                    }
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(oAlgorithms);
            }

            // sort so rsa is near the top
            oOpt.SignatureAlgorithmns = oOpt.SignatureAlgorithmns.
                OrderBy(x => x.Contains("_")).ThenBy(x => x).ToList();
            return oOpt;
        }

        private async void oWizardWindow_Loaded(object sender, RoutedEventArgs e)
        {
            if (bStarted) return;
            bStarted = true;
            await LoadProvidersAsync(false);
        }

        private void oWizardWindow_Closed(object sender, EventArgs e)
        {
            bClosed = true;
        }

        private async void oRefreshProvidersButton_Click(object sender, RoutedEventArgs e)
        {
            await LoadProvidersAsync(true);
        }

        private async Task LoadProvidersAsync(bool bRefresh)
        {
            if (bLoadingProviders || bClosed) return;
            bLoadingProviders = true;
            oRefreshProvidersButton.IsEnabled = false;
            oProviderStatus.Text = "Loading default provider...";
            oProviderStatus.ToolTip = null;
            try
            {
                if (sDefaultProvider == DefaultProviderName)
                {
                    ProviderDetails oDefault = await GetDefaultProvider(bRefresh);
                    if (bClosed) return;
                    if (bRefresh) ProviderOptions.Clear();
                    ProviderOptions[DefaultProviderName] = oDefault;
                    oProviderType_Checked(null, null);
                    oProviderStatus.Text = "Loading providers; you can continue.";
                }

                Dictionary<string, ProviderDetails> oProviders = await GetAvailableProviders(bRefresh);
                if (bClosed) return;
                if (bRefresh && sDefaultProvider != DefaultProviderName) ProviderOptions.Clear();
                foreach (var oProvider in oProviders)
                {
                    if (!ProviderOptions.ContainsKey(oProvider.Key)) ProviderOptions[oProvider.Key] = oProvider.Value;
                }
                oProviderType_Checked(null, null);
                oProviderStatus.Text = oProviderComboBox.SelectedItem == null
                    ? "No providers match the current filters." : "Ready.";
            }
            catch (Exception oError)
            {
                if (bClosed) return;
                oProviderStatus.Text = ProviderOptions.Count == 0
                    ? "Could not load providers. Try Refresh."
                    : "Other providers unavailable. Try Refresh.";
                oProviderStatus.ToolTip = oError.GetBaseException().Message;
            }
            finally
            {
                bLoadingProviders = false;
                if (!bClosed) oRefreshProvidersButton.IsEnabled = !bGenerating;
            }
        }

        private void oProviderComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (bUpdatingProviders || oSignatureComboBox == null || oHashComboBox == null ||
                oGenerateButton == null) return;
            oGenerateButton.IsEnabled = false;
            SelectedProvider = oProviderComboBox.SelectedItem as string;
            ProviderDetails oProvider;
            if (SelectedProvider == null || !ProviderOptions.TryGetValue(SelectedProvider, out oProvider))
            {
                oSignatureComboBox.ItemsSource = null;
                oHashComboBox.ItemsSource = null;
                UpdateGenerationControls();
                return;
            }
            oSignatureComboBox.ItemsSource = oProvider.SignatureAlgorithmns;
            oHashComboBox.ItemsSource = oProvider.HashAlgorithmns;
            oSignatureComboBox.SelectedItem = oProvider.SignatureAlgorithmns.Contains(sDefaultSignature)
                ? sDefaultSignature : oProvider.SignatureAlgorithmns.Contains("RSA")
                ? "RSA" : oProvider.SignatureAlgorithmns.FirstOrDefault();
            oHashComboBox.SelectedItem = oProvider.HashAlgorithmns.Contains(sDefaultHash)
                ? sDefaultHash : oProvider.HashAlgorithmns.Contains("SHA256")
                ? "SHA256" : oProvider.HashAlgorithmns.FirstOrDefault();
            UpdateGenerationControls();
        }

        private void oProviderType_Checked(object sender, RoutedEventArgs e)
        {
            if (oSoftwareCheckbox == null || oHardwareCheckbox == null || oShowLegacyCheckbox == null ||
                oGenerateButton == null) return;

            string sPrevious = SelectedProvider;
            string[] oNames = ProviderOptions.Where(p =>
                (oShowLegacyCheckbox.IsChecked == true || !p.Value.IsLegacy) &&
                (p.Value.IsHardware && oHardwareCheckbox.IsChecked == true ||
                !p.Value.IsHardware && oSoftwareCheckbox.IsChecked == true)).Select(p => p.Key).ToArray();
            bUpdatingProviders = true;
            try
            {
                oProviderComboBox.ItemsSource = oNames;
                oProviderComboBox.SelectedItem = oNames.Contains(sPrevious) ? sPrevious
                    : oNames.Contains(sDefaultProvider) ? sDefaultProvider
                    : oNames.Contains(DefaultProviderName) ? DefaultProviderName : oNames.FirstOrDefault();
            }
            finally
            {
                bUpdatingProviders = false;
            }
            string sSelected = oProviderComboBox.SelectedItem as string;
            if (sSelected != SelectedProvider || sSelected == null ||
                oSignatureComboBox.ItemsSource != ProviderOptions[sSelected].SignatureAlgorithmns)
                oProviderComboBox_SelectionChanged(null, null);
            if (bStarted && !bLoadingProviders && oProviderStatus.ToolTip == null)
                oProviderStatus.Text = sSelected == null ? "No providers match the current filters." : "Ready.";
            UpdateGenerationControls();
        }

        private void oSignatureComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // default values
            oKeyLengthTextBox.IsEnabled = false;
            oKeyLengthHintLabel.Content = "";
            oKeyLengthTextBox.Text = "";

            // sanity check
            SelectedSignature = oSignatureComboBox.SelectedItem as string;
            if (SelectedProvider == null || SelectedSignature == null ||
                !ProviderOptions[SelectedProvider].SignatureMinLengths.ContainsKey(SelectedSignature))
            {
                UpdateGenerationControls();
                return;
            }

            bool bAgreement = SelectedSignature.StartsWith("ECDH", StringComparison.Ordinal);
            bool bSigning = SelectedSignature.StartsWith("ECDSA", StringComparison.Ordinal);
            X509KeyUsageFlags oUsages = oDefaultKeyUsages ?? (bAgreement ? X509KeyUsageFlags.KeyAgreement
                : bSigning ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.KeyEncipherment);
            foreach (EkuOption oUsage in KeyUsages)
                oUsage.Selected = oUsage.Oid != nameof(X509KeyUsageFlags.None) &&
                    (oUsages & Enum.Parse<X509KeyUsageFlags>(oUsage.Oid)) != 0;
            oKeyUsageCombobox.Items.Refresh();

            // get potential key lengths
            int MinLength = ProviderOptions[SelectedProvider].SignatureMinLengths[SelectedSignature];
            int MaxLength = ProviderOptions[SelectedProvider].SignatureMaxLengths[SelectedSignature];
            if (SelectedSignature == "RSA") MinLength = Math.Max(MinLength, CertificateKeyProtection.MinimumRsaKeyBits);
            if (MaxLength < MinLength)
            {
                oKeyLengthHintLabel.Content = "No supported key lengths";
                UpdateGenerationControls();
                return;
            }

            if (MinLength == MaxLength && MaxLength != 0)
            {
                oKeyLengthHintLabel.Content = "Fixed at " + MinLength + " bits";
                oKeyLengthTextBox.Text = MinLength.ToString();
            }
            else
            {
                oKeyLengthHintLabel.Content = MinLength + " to " + MaxLength + " bits";
                oKeyLengthTextBox.IsEnabled = true;
                oKeyLengthTextBox.Text = Math.Max(MinLength, Math.Min(MaxLength,
                    SelectedSignature == "RSA" ? Math.Max(CertificateKeyProtection.MinimumRsaKeyBits,
                        nDefaultKeyLength) : nDefaultKeyLength))
                    .ToString(CultureInfo.InvariantCulture);
            }
            UpdateGenerationControls();
        }

        private void oGenerationOptionsChanged(object sender, RoutedEventArgs e)
        {
            UpdateGenerationControls();
        }

        private void UpdateGenerationControls()
        {
            if (bInitializing || bClosed) return;

            // Keep issuer and dates inactive for requests without moving the form.
            bool bSelfSigned = oCertificateSelfSignedRadio.IsChecked == true;
            oValidFromDatePicker.IsEnabled = oValidUntilDatePicker.IsEnabled = oIssuerTextBox.IsEnabled = bSelfSigned;
            oGenerationHelp.Text = bSelfSigned
                ? "Create installs a certificate in the selected Windows Personal store."
                : "Create saves a .csr request for a certificate authority. " +
                    "Install the issued certificate on this computer.";
            oValidityHelp.Text = bSelfSigned ? "The certificate expires on the end date."
                : "The certificate authority sets the issuer and validity dates.";
            bool bSigning = SelectedSignature?.StartsWith("ECDSA", StringComparison.Ordinal) == true;
            oAlgorithmHelp.Text = bSigning ? "ECDSA certificates sign data; they cannot encrypt Crypture items."
                : SelectedSignature?.StartsWith("ECDH", StringComparison.Ordinal) == true
                ? "ECDH uses Key Agreement to encrypt Crypture items."
                : SelectedSignature == "RSA" ? "RSA uses Key Encipherment to encrypt Crypture items."
                : "Choose key usages that match how the certificate will be used.";
            oAlgorithmHelp.SetResourceReference(TextBlock.ForegroundProperty,
                bSigning ? "Crypture.WarningBrush" : "Crypture.MutedBrush");
            oKeySummary.Text = SelectedProvider == null ? "Choose a provider on Advanced."
                : SelectedSignature + ", " + oKeyLengthTextBox.Text + " bits, " + oHashComboBox.SelectedItem +
                    Environment.NewLine + SelectedProvider;

            // Explain the first incomplete choice before Windows begins creating a key.
            string sIssue = GenerationIssue(out _);
            oGenerateButton.IsEnabled = !bGenerating && sIssue == null;
            oGenerateButton.ToolTip = sIssue ?? (bSelfSigned ? "Create and install the certificate."
                : "Choose where to save the certificate request.");
            oGenerationNotice.Text = bGenerating ? "Creating " + (bSelfSigned ? "certificate..." : "request...")
                : sIssue ?? (bSelfSigned ? "Ready to create the certificate." : "Ready to save the request.");
            oGenerationNotice.SetResourceReference(TextBlock.ForegroundProperty,
                sIssue == null || bGenerating ? "Crypture.MutedBrush" : "Crypture.WarningBrush");
        }

        private string GenerationIssue(out int nKeyLength)
        {
            nKeyLength = 0;
            if (String.IsNullOrWhiteSpace(oSubjectTextBox.Text)) return "Enter a certificate name.";
            if (SelectedProvider == null ||
                !ProviderOptions.TryGetValue(SelectedProvider, out ProviderDetails oProvider))
                return "Choose a provider on Advanced.";
            if (SelectedSignature == null || !oProvider.SignatureAlgorithmns.Contains(SelectedSignature))
                return "Choose a key algorithm on Advanced.";
            SelectedHash = oHashComboBox.SelectedItem as string;
            if (SelectedHash == null || !oProvider.HashAlgorithmns.Contains(SelectedHash))
                return "Choose a hash algorithm on Advanced.";
            int nMinimum = oProvider.SignatureMinLengths[SelectedSignature];
            if (SelectedSignature == "RSA") nMinimum = Math.Max(nMinimum, CertificateKeyProtection.MinimumRsaKeyBits);
            int nMaximum = oProvider.SignatureMaxLengths[SelectedSignature];
            if (nMaximum < nMinimum) return "Choose a provider with a supported key length.";
            if (!Int32.TryParse(oKeyLengthTextBox.Text, out nKeyLength) ||
                nKeyLength < nMinimum || nKeyLength > nMaximum)
                return "Enter a key length from " + nMinimum + " to " + nMaximum + " bits on Advanced.";
            if (oCertificateSelfSignedRadio.IsChecked != true) return null;
            if (!oValidFromDatePicker.SelectedDate.HasValue || !oValidUntilDatePicker.SelectedDate.HasValue ||
                oValidUntilDatePicker.SelectedDate <= oValidFromDatePicker.SelectedDate)
                return "Choose an end date after the start date.";
            if (!String.IsNullOrWhiteSpace(oIssuerTextBox.Text) &&
                !String.Equals(oSubjectTextBox.Text.Trim(), oIssuerTextBox.Text.Trim(), StringComparison.Ordinal))
                return "Leave the issuer blank or match the certificate name on Advanced.";
            return null;
        }

        private void oCloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async void oGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            if (bGenerating) return;
            bGenerating = true;
            Cursor oPreviousCursor = Mouse.OverrideCursor;
            oWizardTabs.IsEnabled = oCloseButton.IsEnabled = oRefreshProvidersButton.IsEnabled = false;
            UpdateGenerationControls();
            try
            {
                // Paint progress before a provider starts creating its Windows key.
                Mouse.OverrideCursor = Cursors.Wait;
                await Dispatcher.Yield(DispatcherPriority.Background);
                if (bClosed) return;
                Utilities.TryOperation(this, () =>
                {
                    string sIssue = GenerationIssue(out int nKeyLength);
                    if (sIssue != null) throw new InvalidOperationException(sIssue);
                    bool bSelfSigned = oCertificateSelfSignedRadio.IsChecked == true;

                    string sRequestPath = null;
                    if (!bSelfSigned)
                    {
                        // ask the user where to store the file
                        SaveFileDialog oSaveDialog = new SaveFileDialog
                        {
                            Title = "Save Certificate Request",
                            Filter = "Certificate Request (*.csr)|*.csr|All Files (*.*)|*.*",
                            DefaultExt = ".csr", AddExtension = true, ValidateNames = true
                        };
                        if (oSaveDialog.ShowDialog(this) != true) return;
                        sRequestPath = oSaveDialog.FileName;
                    }

                    dynamic oProviderInfo = CreateEnrollmentObject("CspInformation");
                    oProviderInfo.InitializeFromName(SelectedProvider);

                    // create DN for subject and issuer
                    dynamic oSubjectDistinguishedName = CreateEnrollmentObject("X500DistinguishedName");
                    oSubjectDistinguishedName.Encode("CN=\"" + oSubjectTextBox.Text.Trim().Replace("\"", "\"\"") + "\"",
                        0);

                    // create a new private key for the certificate
                    dynamic oPrivateKey = CreateEnrollmentObject("X509PrivateKey");
                    bool bCreated = false;
                    bool bSaved = false;
                    try
                    {
                        oPrivateKey.ProviderName = SelectedProvider;
                        oPrivateKey.Algorithm = oProviderInfo.CspAlgorithms.ItemByName[SelectedSignature]
                            .GetAlgorithmOid(0, 0);
                        oPrivateKey.MachineContext = oCertificateStoreMachineRadio.IsChecked == true;
                        oPrivateKey.Length = nKeyLength;

                        // CertEnroll key specification and usage flags.
                        const int KeyExchangeSpecification = 1;
                        const int DecryptKeyUsage = 1;
                        const int SigningKeyUsage = 2;
                        const int KeyAgreementUsage = 4;
                        if (SelectedSignature == "RSA")
                        {
                            oPrivateKey.KeySpec = KeyExchangeSpecification;
                            oPrivateKey.KeyUsage = DecryptKeyUsage | SigningKeyUsage;
                        }
                        else if (SelectedSignature.StartsWith("ECDH", StringComparison.Ordinal))
                        {
                            oPrivateKey.KeyUsage = SigningKeyUsage | KeyAgreementUsage;
                        }

                        // CertEnroll key protection and export policy flags.
                        const int ProtectKeyUi = 1;
                        const int AllowKeyExport = 1;
                        const int AllowPlaintextKeyExport = 2;
                        oPrivateKey.KeyProtection = oPasswordProtectCheckbox.IsChecked == true ? ProtectKeyUi : 0;
                        oPrivateKey.ExportPolicy = oKeyExportableCheckbox.IsChecked == true
                            ? AllowKeyExport | AllowPlaintextKeyExport : 0;
                        oPrivateKey.Create();
                        bCreated = true;

                        // set the signature mechanism for the certificate
                        dynamic oHash = oProviderInfo.CspAlgorithms.ItemByName[SelectedHash].GetAlgorithmOid(
                            0, 0);

                        // CertEnroll distinguishes user and machine enrollment contexts.
                        const int UserEnrollmentContext = 1;
                        const int MachineEnrollmentContext = 2;
                        int oContext = oPrivateKey.MachineContext ? MachineEnrollmentContext : UserEnrollmentContext;

                        // create a certificate request with the requested info
                        dynamic oCertRequestInfo;
                        if (bSelfSigned)
                        {
                            dynamic oCertificate = CreateEnrollmentObject("X509CertificateRequestCertificate");
                            oCertificate.InitializeFromPrivateKey(oContext, oPrivateKey, "");
                            oCertificate.Issuer = oSubjectDistinguishedName;
                            oCertificate.NotBefore = oValidFromDatePicker.SelectedDate.Value;
                            oCertificate.NotAfter = oValidUntilDatePicker.SelectedDate.Value;
                            oCertRequestInfo = oCertificate;
                        }
                        else
                        {
                            oCertRequestInfo = CreateEnrollmentObject("X509CertificateRequestPkcs10");
                            oCertRequestInfo.InitializeFromPrivateKey(oContext, oPrivateKey, "");
                        }
                        oCertRequestInfo.Subject = oSubjectDistinguishedName;
                        oCertRequestInfo.HashAlgorithm = oHash;

                        X509KeyUsageFlags oUsage = X509KeyUsageFlags.None;
                        foreach (EkuOption oOption in KeyUsages.Where(k => k.Selected))
                            oUsage |= (X509KeyUsageFlags)Enum.Parse(typeof(X509KeyUsageFlags), oOption.Oid);
                        if (oUsage != X509KeyUsageFlags.None)
                        {
                            dynamic oKeyUsage = CreateEnrollmentObject("X509ExtensionKeyUsage");
                            oKeyUsage.InitializeEncode((int)oUsage);
                            oCertRequestInfo.X509Extensions.Add(oKeyUsage);
                        }

                        // translate the list to a list that the enrollment will understand key a list of key
                        // usages to use
                        if (EnhancedKeyUsages.Any(k => k.Selected))
                        {
                            dynamic oKeyUsagesToAdd = CreateEnrollmentObject("ObjectIds");
                            foreach (EkuOption oKeyUsage in EnhancedKeyUsages.Where(k => k.Selected))
                            {
                                dynamic oOID = CreateEnrollmentObject("ObjectId");
                                oOID.InitializeFromValue(oKeyUsage.Oid);
                                oKeyUsagesToAdd.Add(oOID);
                            }
                            dynamic oKeyUsageList = CreateEnrollmentObject("X509ExtensionEnhancedKeyUsage");
                            oKeyUsageList.InitializeEncode(oKeyUsagesToAdd);
                            oCertRequestInfo.X509Extensions.Add(oKeyUsageList);
                        }

                        // create an enrollment request
                        oCertRequestInfo.Encode();
                        dynamic oEnrollRequest = CreateEnrollmentObject("X509Enrollment");
                        oEnrollRequest.InitializeFromRequest(oCertRequestInfo);

                        // install certificate into selected certificate store
                        if (bSelfSigned)
                        {
                            // Accept the locally issued certificate response.
                            const int AllowUntrustedCertificate = 2;

                            // Decode the response as Base64.
                            const int Base64Encoding = 1;
                            string sCertRequestString = oEnrollRequest.CreateRequest();
                            oEnrollRequest.InstallResponse(
                                AllowUntrustedCertificate,
                                sCertRequestString, Base64Encoding, "");
                        }
                        // produce request file
                        else
                        {
                            const int Base64RequestHeaderEncoding = 3;
                            string sCertRequestString = oEnrollRequest.CreateRequest(
                                Base64RequestHeaderEncoding);
                            System.IO.File.WriteAllText(sRequestPath, sCertRequestString, Encoding.ASCII);
                        }
                        bSaved = true;
                    }
                    finally
                    {
                        if (bCreated && !bSaved) oPrivateKey.Delete();
                        else if (bCreated) oPrivateKey.Close();
                        Marshal.FinalReleaseComObject(oPrivateKey);
                    }

                    // note to the user the create was successful
                    string sStore = oCertificateStoreMachineRadio.IsChecked == true ? "computer" : "current user's";
                    string sNextStep = SelectedSignature != "RSA" &&
                        !SelectedSignature.StartsWith("ECDH", StringComparison.Ordinal)
                        ? "This certificate cannot encrypt Crypture items."
                        : CryptureEntities.Storage.IsSqlServer
                        ? "Publish the public certificate to your Active Directory account, " +
                            "then enroll it in the Vault."
                        : "In Crypture, open Certificates and choose Store to add it to your Vault.";
                    Popup.Show(this, bSelfSigned ? "Certificate created in the " + sStore + " Personal store. " +
                        sNextStep
                        : "Certificate request saved. Send the .csr file to your certificate authority, then install " +
                            "the issued certificate on this computer. The private key remains in the " + sStore +
                            " Windows key store.",
                        bSelfSigned ? "Certificate Created" : "Request Saved",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                });
            }
            finally
            {
                bGenerating = false;
                Mouse.OverrideCursor = oPreviousCursor;
                if (!bClosed)
                {
                    oWizardTabs.IsEnabled = oCloseButton.IsEnabled = true;
                    oRefreshProvidersButton.IsEnabled = !bLoadingProviders;
                    UpdateGenerationControls();
                }
            }
        }
    }
}
