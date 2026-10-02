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

namespace Crypture
{
    /// <summary>
    /// Interaction logic for CertWizard.xaml
    /// </summary>
    public partial class CertWizard : Window
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
            ConfigurationDefaults oDefaults = new ConfigurationDefaults("CertificateGenerator");
            sDefaultProvider = oDefaults.Text("Provider", DefaultProviderName).Trim();
            sDefaultSignature = oDefaults.Text("KeyAlgorithm", "RSA").Trim().ToUpperInvariant();
            sDefaultHash = oDefaults.Text("HashAlgorithm", "SHA256").Trim().ToUpperInvariant();
            nDefaultKeyLength = oDefaults.Number("KeyLength", 2048, 1, 16384);
            int nStartOffset = oDefaults.Number("StartOffsetDays", 0, -36500, 36500);
            int nYears = oDefaults.Number("ValidityYears", 3, 0, 100);
            int nDays = oDefaults.Number("ValidityDays", 0, 0, 36500);
            string sStore = oDefaults.Choice("Store", "CurrentUser", "CurrentUser", "LocalMachine");
            bool bSelfSigned = oDefaults.Flag("SelfSigned", true);
            bool bHardware = oDefaults.Flag("ShowHardwareProviders", true);
            bool bSoftware = oDefaults.Flag("ShowSoftwareProviders", true);
            bool bLegacy = oDefaults.Flag("ShowLegacyProviders", false);
            bool bExportable = oDefaults.Flag("KeyExportable", false);
            bool bPasswordProtect = oDefaults.Flag("PasswordProtectKey", false);
            if (sDefaultProvider.Length == 0 || sDefaultSignature.Length == 0 || sDefaultHash.Length == 0 ||
                nYears + nDays == 0 || !bHardware && !bSoftware ||
                sDefaultSignature == "RSA" && nDefaultKeyLength < 2048)
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
                EkuOption oOpt = new EkuOption();
                oOpt.Name = Regex.Replace(sKeyUsage, "(\\B[A-Z])", " $1");
                oOpt.Oid = sKeyUsage;
                oOpt.Selected = sKeyUsage == nameof(X509KeyUsageFlags.KeyEncipherment);
                KeyUsages.Add(oOpt);
            }

            // set combobox to sort
            oProviderComboBox.Items.SortDescriptions.Add(new SortDescription("", ListSortDirection.Ascending));
            oKeyUsageCombobox.Items.SortDescriptions.Add(new SortDescription("Name", ListSortDirection.Ascending));
            oEnhancedKeyUsageCombobox.Items.SortDescriptions.Add(new SortDescription("Name", ListSortDirection.Ascending));
            oProviderType_Checked(null, null);

            // disable machine store option if user is not an admin
            using (WindowsIdentity oIdentity = WindowsIdentity.GetCurrent())
                oCertificateStoreMachineRadio.IsEnabled = new WindowsPrincipal(oIdentity)
                    .IsInRole(WindowsBuiltInRole.Administrator);
            oCertificateStoreMachineRadio.IsChecked =
                sStore == "LocalMachine" && oCertificateStoreMachineRadio.IsEnabled;
            oCertificateStoreUserRadio.IsChecked = oCertificateStoreMachineRadio.IsChecked != true;
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
                        if (oAlg.Type == 2)
                        {
                            if (oOpt.HashAlgorithmns.Contains(oAlg.Name)) continue;
                            oOpt.HashAlgorithmns.Add(oAlg.Name);
                        }

                        // signature algorithms
                        else if (oAlg.Type == 5 ||
                            oAlg.Type == 3 ||
                            (oAlg.Type == 4 &&
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
                    oProviderStatus.Text = "Loading other providers; you can use the selected provider now.";
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
                    ? "Could not load providers. Refresh to retry."
                    : "Additional providers could not be loaded. Refresh to retry.";
                oProviderStatus.ToolTip = oError.GetBaseException().Message;
            }
            finally
            {
                bLoadingProviders = false;
                if (!bClosed) oRefreshProvidersButton.IsEnabled = true;
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
            oGenerateButton.IsEnabled = oSignatureComboBox.SelectedItem != null && oHashComboBox.SelectedItem != null;
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
                !ProviderOptions[SelectedProvider].SignatureMinLengths.ContainsKey(SelectedSignature)) return;

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

            if (MinLength == MaxLength && MaxLength != 0)
            {
                oKeyLengthHintLabel.Content = "Note: Static Length";
                oKeyLengthTextBox.Text = MinLength.ToString();
            }
            else
            {
                oKeyLengthHintLabel.Content = String.Format(
                    "Minimum Length: {0}, Maximum Length: {1}",
                    MinLength.ToString(), MaxLength.ToString());
                oKeyLengthTextBox.IsEnabled = true;
                oKeyLengthTextBox.Text = Math.Max(MinLength, Math.Min(MaxLength,
                    SelectedSignature == "RSA" ? Math.Max(2048, nDefaultKeyLength) : nDefaultKeyLength))
                    .ToString(CultureInfo.InvariantCulture);
            }
        }

        private void oGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                ProviderDetails oProvider;
                int nKeyLength;
                SelectedHash = oHashComboBox.SelectedItem as string;
                bool bSelfSigned = oCertificateSelfSignedRadio.IsChecked == true;
                if (SelectedProvider == null || !ProviderOptions.TryGetValue(SelectedProvider, out oProvider) ||
                    SelectedSignature == null || !oProvider.SignatureAlgorithmns.Contains(SelectedSignature) ||
                    SelectedHash == null || !oProvider.HashAlgorithmns.Contains(SelectedHash) ||
                    !Int32.TryParse(oKeyLengthTextBox.Text, out nKeyLength) ||
                    nKeyLength < oProvider.SignatureMinLengths[SelectedSignature] ||
                    nKeyLength > oProvider.SignatureMaxLengths[SelectedSignature] ||
                    (SelectedSignature == "RSA" && nKeyLength < 2048) ||
                    String.IsNullOrWhiteSpace(oSubjectTextBox.Text) ||
                    (bSelfSigned && (!oValidFromDatePicker.SelectedDate.HasValue ||
                        !oValidUntilDatePicker.SelectedDate.HasValue ||
                        oValidUntilDatePicker.SelectedDate <= oValidFromDatePicker.SelectedDate)))
                    throw new InvalidOperationException("Select a provider, algorithms, a supported key length, " +
                        "a subject name, and a valid date range. RSA keys must be at least 2048 bits.");

                if (bSelfSigned && !String.IsNullOrWhiteSpace(oIssuerTextBox.Text) &&
                    !String.Equals(oSubjectTextBox.Text.Trim(), oIssuerTextBox.Text.Trim(), StringComparison.Ordinal))
                    throw new InvalidOperationException("For a self-signed certificate, " +
                        "leave the issuer blank or use the subject name.");

                string sRequestPath = null;
                if (!bSelfSigned)
                {
                    // ask the user where to store the file
                    SaveFileDialog oSaveDialog = new SaveFileDialog
                    {
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
                    oPrivateKey.Algorithm = oProviderInfo.CspAlgorithms.ItemByName[SelectedSignature].GetAlgorithmOid(
                        0, 0);
                    oPrivateKey.MachineContext = oCertificateStoreMachineRadio.IsChecked == true;
                    oPrivateKey.Length = nKeyLength;
                    if (SelectedSignature == "RSA")
                    {
                        oPrivateKey.KeySpec = 1;
                        oPrivateKey.KeyUsage = 3;
                    }
                    else if (SelectedSignature.StartsWith("ECDH", StringComparison.Ordinal))
                    {
                        oPrivateKey.KeyUsage = 6;
                    }
                    oPrivateKey.KeyProtection = oPasswordProtectCheckbox.IsChecked == true ? 1 : 0;
                    oPrivateKey.ExportPolicy = oKeyExportableCheckbox.IsChecked == true ? 3 : 0;
                    oPrivateKey.Create();
                    bCreated = true;

                    // set the signature mechanism for the certificate
                    dynamic oHash = oProviderInfo.CspAlgorithms.ItemByName[SelectedHash].GetAlgorithmOid(
                        0, 0);
                    int oContext = oPrivateKey.MachineContext ? 2 : 1;

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
                        string sCertRequestString = oEnrollRequest.CreateRequest();
                        oEnrollRequest.InstallResponse(
                            2,
                            sCertRequestString, 1, "");
                    }
                    // produce request file
                    else
                    {
                        string sCertRequestString = oEnrollRequest.CreateRequest(
                            3);
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
                MessageBox.Show(this, bSelfSigned ? "Certificate successfully created."
                    : "Certificate request saved. The private key remains in the selected Windows key store.",
                    "Creation Successful", MessageBoxButton.OK, MessageBoxImage.Information);
            });
        }
    }
}
