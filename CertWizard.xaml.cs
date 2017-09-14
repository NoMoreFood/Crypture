using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using CertEnroll = CERTENROLLLib;

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

        public CertWizard()
        {
            InitializeComponent();

            // create a list of all csp providers
            CertEnroll.CCspInformations CspInformations = new CertEnroll.CCspInformations();
            CspInformations.AddAvailableCsps();

            // enumerate each provider
            foreach (CertEnroll.ICspInformation oCsp in CspInformations)
            {
                // create a structure for display purposes
                ProviderDetails oOpt = new ProviderDetails();
                oOpt.IsHardware = oCsp.IsSmartCard || oCsp.IsHardwareDevice;
                oOpt.IsLegacy = oCsp.LegacyCsp;
                ProviderOptions.Add(oCsp.Name, oOpt);

                // populate display structure with algorithmn information
                foreach (CertEnroll.ICspAlgorithm oAlg in oCsp.CspAlgorithms)
                {
                    // special case: eliminate generic ecdsa that does not work
                    if (oAlg.Name.Equals("ECDSA")) continue;

                    // hash algorithms
                    if (oAlg.Type == CertEnroll.AlgorithmType.XCN_BCRYPT_HASH_INTERFACE)
                    {
                        if (oOpt.HashAlgorithmns.Contains(oAlg.Name)) continue;
                        oOpt.HashAlgorithmns.Add(oAlg.Name);
                    }

                    // signature algorithms
                    else if (oAlg.Type == CertEnroll.AlgorithmType.XCN_BCRYPT_SIGNATURE_INTERFACE ||
                        oAlg.Type == CertEnroll.AlgorithmType.XCN_BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE)
                    {
                        if (oOpt.SignatureAlgorithmns.Contains(oAlg.Name)) continue;
                        oOpt.SignatureAlgorithmns.Add(oAlg.Name);
                        oOpt.SignatureMinLengths.Add(oAlg.Name, oAlg.MinLength);
                        oOpt.SignatureMaxLengths.Add(oAlg.Name, oAlg.MaxLength);
                    }
                }

                // sort so rsa is near the top
                oOpt.SignatureAlgorithmns = oOpt.SignatureAlgorithmns.
                    OrderBy(x => x.Contains("_")).ThenBy(x => x).ToList();
            }

            // set default values
            oValidFromDatePicker.SelectedDate = DateTime.Now;
            oValidUntilDatePicker.SelectedDate = DateTime.Now.AddYears(3);

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
                    Oid = oOid.Value
                };
                EnhancedKeyUsages.Add(oKeyUsage);
            }

            // populate key usage options
            foreach (string sKeyUsage in Enum.GetNames(typeof(X509KeyUsageFlags)))
            {
                EkuOption oOpt = new EkuOption();
                oOpt.Name = Regex.Replace(sKeyUsage, "(\\B[A-Z])", " $1");
                oOpt.Oid = sKeyUsage;
                KeyUsages.Add(oOpt);
            }

            // set combobox to sort
            oProviderComboBox.Items.SortDescriptions.Add(new SortDescription("", ListSortDirection.Ascending));
            oKeyUsageCombobox.Items.SortDescriptions.Add(new SortDescription("Name", ListSortDirection.Ascending));
            oEnhancedKeyUsageCombobox.Items.SortDescriptions.Add(new SortDescription("Name", ListSortDirection.Ascending));
            oProviderType_Checked(null, null);

            // disable machine store option if user is not an admin
            oCertificateStoreMachineRadio.IsEnabled = 
                new WindowsPrincipal(WindowsIdentity.GetCurrent())
                    .IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void oProviderComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (SelectedProvider == null) return;
            oSignatureComboBox.ItemsSource = ProviderOptions[SelectedProvider].SignatureAlgorithmns;
            oHashComboBox.ItemsSource = ProviderOptions[SelectedProvider].HashAlgorithmns;
            oSignatureComboBox_SelectionChanged(null, null);
        }

        private void oProviderType_Checked(object sender, RoutedEventArgs e)
        {
            if (oSoftwareCheckbox == null || oHardwareCheckbox == null || oShowLegacyCheckbox == null) return;

            oProviderComboBox.ItemsSource = ProviderOptions.Where(p =>
                ((oShowLegacyCheckbox.IsChecked.Value) ? true : !p.Value.IsLegacy) &&
                (p.Value.IsHardware && oHardwareCheckbox.IsChecked.Value ||
                !p.Value.IsHardware && oSoftwareCheckbox.IsChecked.Value)).Select(p => p.Key);
        }

        private void oSignatureComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // default values
            oKeyLengthTextBox.IsEnabled = false;
            oKeyLengthHintLabel.Content = "";
            oKeyLengthTextBox.Text = "";

            // sanity check
            if (SelectedSignature == null) return;

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
            }
        }

        private void oGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            CertEnroll.CCspInformation oProviderInfo = new CertEnroll.CCspInformation();
            oProviderInfo.InitializeFromName(SelectedProvider);

            // create DN for subject and issuer
            CertEnroll.CX500DistinguishedName oSubjectDistinguishedName = new CertEnroll.CX500DistinguishedName();
            oSubjectDistinguishedName.Encode("CN=" + oSubjectTextBox.Text,
                CertEnroll.X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create CN for subject and issuer
            CertEnroll.CX500DistinguishedName oIssuerDistinguishedName = new CertEnroll.CX500DistinguishedName();
            oIssuerDistinguishedName.Encode("CN=" + oIssuerTextBox.Text,
                CertEnroll.X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create a new private key for the certificate
            CertEnroll.IX509PrivateKey oPrivateKey = (CertEnroll.IX509PrivateKey)Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.CX509PrivateKey"));
            try
            {
                oPrivateKey.ProviderName = (string)oProviderComboBox.SelectedValue;
                oPrivateKey.Algorithm = oProviderInfo.CspAlgorithms.ItemByName[
                oSignatureComboBox.SelectedValue.ToString()].GetAlgorithmOid(0, CertEnroll.AlgorithmFlags.AlgorithmFlagsNone);
                oPrivateKey.MachineContext = oCertificateStoreMachineRadio.IsChecked.Value;
                oPrivateKey.Length = Convert.ToInt32(oKeyLengthTextBox.Text);
                oPrivateKey.KeyProtection = (oPasswordProtectCheckbox.IsChecked.Value) ?
                CertEnroll.X509PrivateKeyProtection.XCN_NCRYPT_UI_PROTECT_KEY_FLAG : CertEnroll.X509PrivateKeyProtection.XCN_NCRYPT_UI_NO_PROTECTION_FLAG;
                oPrivateKey.ExportPolicy = (oKeyExportableCheckbox.IsChecked.Value) ?
                    (CertEnroll.X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
                    CertEnroll.X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG) :
                    CertEnroll.X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_NONE;
                oPrivateKey.Create();
            }
            catch (Exception eError)
            {
                // note to the user the creation failed
                MessageBox.Show(this, "Certificate private key could not be constructed. This is often " +
                    "due to an invalid set of parameters being selected that is not supported by the " + 
                    "cryptographic provider.  The specific error message returned is below: " +
                    Environment.NewLine + Environment.NewLine + eError.Message,
                    "Creation Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // set the signature mechanism for the certificate
            CertEnroll.CObjectId oHash = oProviderInfo.CspAlgorithms.ItemByName[SelectedHash].GetAlgorithmOid(0, CertEnroll.AlgorithmFlags.AlgorithmFlagsNone);

            // create a certificate request with the requested info
            CertEnroll.CX509CertificateRequestCertificate oCertRequestInfo = new CertEnroll.CX509CertificateRequestCertificate();
            oCertRequestInfo.InitializeFromPrivateKey(CertEnroll.X509CertificateEnrollmentContext.ContextUser, oPrivateKey, "");
            oCertRequestInfo.Subject = oSubjectDistinguishedName;
            oCertRequestInfo.Issuer = oIssuerDistinguishedName;
            oCertRequestInfo.NotBefore = oValidFromDatePicker.SelectedDate.Value;
            oCertRequestInfo.NotAfter = oValidUntilDatePicker.SelectedDate.Value;
            oCertRequestInfo.HashAlgorithm = oHash;

            // translate the list to a list that the enrollment will understand key a list of key
            // usages to use
            if (EnhancedKeyUsages.Where(k => k.Selected).Count() > 0)
            {
                CertEnroll.CObjectIds oKeyUsagesToAdd = new CertEnroll.CObjectIds();
                foreach (EkuOption oKeyUsage in EnhancedKeyUsages.Where(k => k.Selected))
                {
                    CertEnroll.CObjectId oOID = new CertEnroll.CObjectId();
                    oOID.InitializeFromValue(oKeyUsage.Oid);
                    oKeyUsagesToAdd.Add(oOID);
                }
                CertEnroll.CX509ExtensionEnhancedKeyUsage oKeyUsageList = new CertEnroll.CX509ExtensionEnhancedKeyUsage();
                oKeyUsageList.InitializeEncode(oKeyUsagesToAdd);
                oCertRequestInfo.X509Extensions.Add((CertEnroll.CX509Extension)oKeyUsageList);
            }

            // create an enrollment request
            oCertRequestInfo.Encode();
            CertEnroll.CX509Enrollment oEnrollRequest = new CertEnroll.CX509Enrollment();
            oEnrollRequest.InitializeFromRequest(oCertRequestInfo);
            

            // install certificate into selected certificate store
            if (oCertificateSelfSignedRadio.IsChecked.Value)
            {
                string sCertRequestString = oEnrollRequest.CreateRequest();
                oEnrollRequest.InstallResponse(CertEnroll.InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                    sCertRequestString, CertEnroll.EncodingType.XCN_CRYPT_STRING_BASE64, "");
            }

            // produce request file
            else
            {
                // ask the user where to store the file
                SaveFileDialog oSaveDialog = new SaveFileDialog()
                {
                    Filter = "Certificate Request (*.csr)|*.csr|All Files (*.*)|*.*",
                    AddExtension = true,
                    ValidateNames = true
                };
                if (!oSaveDialog.ShowDialog(this).Value) return;

                // write the file
                string sCertRequestString = oEnrollRequest.CreateRequest(CertEnroll.EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER);
                System.IO.File.WriteAllText(oSaveDialog.FileName, 
                    sCertRequestString, Encoding.ASCII);
            }

            // note to the user the create was successful
            MessageBox.Show(this, "Certificate successfully created.", 
                "Creation Successful", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}