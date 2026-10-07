using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestCertificateCreator()
    {
        const string sSoftware = "Microsoft Software Key Storage Provider";
        CertWizard.ProviderDetails oSoftware = new CertWizard.ProviderDetails
        {
            SignatureAlgorithmns = ["RSA", "ECDH_P384", "ECDSA_P384"],
            HashAlgorithmns = ["SHA256", "SHA384"],
            SignatureMinLengths = new() { ["RSA"] = 1024, ["ECDH_P384"] = 384, ["ECDSA_P384"] = 384 },
            SignatureMaxLengths = new() { ["RSA"] = 16384, ["ECDH_P384"] = 384, ["ECDSA_P384"] = 384 }
        };
        var oDefault = new TaskCompletionSource<CertWizard.ProviderDetails>();
        var oAvailable = new TaskCompletionSource<Dictionary<string, CertWizard.ProviderDetails>>();
        CertWizard oWizard = new CertWizard(_ => oDefault.Task, _ => oAvailable.Task)
        {
            Width = 560, Left = -20000, Top = -20000, WindowStartupLocation = WindowStartupLocation.Manual,
            ShowActivated = false, ShowInTaskbar = false
        };
        string sCertificateName = "Crypture.Creator.Tests-" + Guid.NewGuid().ToString("N");
        try
        {
            TextBox oName = (TextBox)oWizard.FindName("oSubjectTextBox");
            TextBox oIssuer = (TextBox)oWizard.FindName("oIssuerTextBox");
            TextBox oLength = (TextBox)oWizard.FindName("oKeyLengthTextBox");
            Button oCreate = (Button)oWizard.FindName("oGenerateButton");
            TabControl oTabs = (TabControl)oWizard.FindName("oWizardTabs");
            TextBlock oNotice = (TextBlock)oWizard.FindName("oGenerationNotice");
            DatePicker oFrom = (DatePicker)oWizard.FindName("oValidFromDatePicker");
            DatePicker oUntil = (DatePicker)oWizard.FindName("oValidUntilDatePicker");
            RadioButton oSelfSigned = (RadioButton)oWizard.FindName("oCertificateSelfSignedRadio");
            ComboBox oAlgorithm = (ComboBox)oWizard.FindName("oSignatureComboBox");
            FrameworkElement oRoot = (FrameworkElement)oWizard.Content;
            oSelfSigned.IsChecked = true;
            ((RadioButton)oWizard.FindName("oCertificateStoreUserRadio")).IsChecked = true;
            ((CheckBox)oWizard.FindName("oKeyExportableCheckbox")).IsChecked = false;
            ((CheckBox)oWizard.FindName("oPasswordProtectCheckbox")).IsChecked = false;
            oName.Clear();
            oIssuer.Clear();
            oFrom.SelectedDate = DateTime.Today;
            oUntil.SelectedDate = DateTime.Today.AddYears(1);
            oWizard.Show();
            PumpUntil(() => oWizard.IsLoaded);
            oWizard.UpdateLayout();
            Point oCreatePosition = oCreate.TranslatePoint(new Point(), oRoot);
            Check(!oCreate.IsEnabled && oNotice.Text.Contains("name"),
                "Certificate creation explains its required name before providers finish loading");

            // A usable default remains available while other devices are still being discovered.
            oDefault.SetResult(oSoftware);
            PumpUntil(() => oWizard.SelectedProvider == sSoftware);
            oName.Text = sCertificateName;
            Check(oCreate.IsEnabled && !((Button)oWizard.FindName("oRefreshProvidersButton")).IsEnabled,
                "Certificate creation can use the default provider during background device discovery");
            oAvailable.SetResult(new() { [sSoftware] = oSoftware });
            PumpUntil(() => ((TextBlock)oWizard.FindName("oProviderStatus")).Text == "Ready.");
            oWizard.UpdateLayout();
            Check((oCreate.TranslatePoint(new Point(), oRoot) - oCreatePosition).Length < 0.1,
                "Provider discovery and readiness preserve the certificate action position");
            Check(((Label)oWizard.FindName("oKeyLengthHintLabel")).Content.ToString().Contains("2048"),
                "RSA key-length guidance matches Crypture's accepted minimum");
            Check(((CertWizard.EkuOption)((ListBox)oWizard.FindName("oKeyUsageCombobox")).Items[0]).Selected,
                "The active certificate usage is visible at the top of its list");

            // Exercise editable fields and mode switches rather than calling the validation helper directly.
            oLength.Text = "1024";
            Check(!oCreate.IsEnabled && oNotice.Text.Contains("2048"),
                "An undersized RSA key disables creation and identifies the accepted range");
            oLength.Text = "2048";
            oUntil.SelectedDate = oFrom.SelectedDate;
            Check(!oCreate.IsEnabled && oNotice.Text.Contains("end date"),
                "Self-signed creation identifies an invalid date range before creating a key");
            ((RadioButton)oWizard.FindName("oCertificateRequestRadio")).IsChecked = true;
            oIssuer.Text = "Chosen by the certificate authority";
            Check(oCreate.IsEnabled && !oFrom.IsEnabled && !oUntil.IsEnabled && !oIssuer.IsEnabled &&
                ((TextBlock)oWizard.FindName("oGenerationHelp")).Text.Contains(".csr"),
                "Request mode explains its file output and disables issuer and dates that the CA controls");
            oSelfSigned.IsChecked = true;
            oUntil.SelectedDate = DateTime.Today.AddYears(1);
            Check(!oCreate.IsEnabled && oNotice.Text.Contains("issuer"),
                "Self-signed creation explains a mismatched configured issuer");
            oIssuer.Clear();
            Check(oCreate.IsEnabled, "Correcting certificate input restores creation immediately");

            // Keep the action row visible and key-setting rows stable at the minimum width and enlarged text.
            foreach (bool bDark in new[] { false, true })
            foreach (double nFontSize in new[] { 12d, 18d, 24d })
            {
                App.ApplyTheme(bDark);
                oWizard.FontSize = nFontSize;
                foreach (int nTab in new[] { 0, 1, 2 })
                {
                    oTabs.SelectedIndex = nTab;
                    oWizard.UpdateLayout();
                    Rect oBounds = oCreate.TransformToAncestor(oRoot).TransformBounds(new Rect(oCreate.RenderSize));
                    Check(oCreate.IsVisible && oBounds.Left >= 0 && oBounds.Right <= oRoot.ActualWidth &&
                        oBounds.Bottom <= oRoot.ActualHeight,
                        "Certificate action remains visible on tab " + nTab + ", font " + nFontSize +
                            ", dark " + bDark);
                }
                ComboBox oHash = (ComboBox)oWizard.FindName("oHashComboBox");
                oAlgorithm.SelectedItem = "RSA";
                oWizard.UpdateLayout();
                Point oHashPosition = oHash.TranslatePoint(new Point(), oRoot);
                oAlgorithm.SelectedItem = "ECDH_P384";
                oWizard.UpdateLayout();
                Check(!oLength.IsEnabled && oLength.Text == "384" &&
                    (oHash.TranslatePoint(new Point(), oRoot) - oHashPosition).Length < 0.1,
                    "Fixed and editable key lengths preserve advanced field positions, font " + nFontSize);
            }
            oAlgorithm.SelectedItem = "ECDSA_P384";
            Check(((TextBlock)oWizard.FindName("oAlgorithmHelp")).Text.Contains("cannot encrypt"),
                "Signing-only algorithms explain that they cannot protect Crypture items");
            ((CheckBox)oWizard.FindName("oSoftwareCheckbox")).IsChecked = false;
            ((CheckBox)oWizard.FindName("oHardwareCheckbox")).IsChecked = false;
            Check(!oCreate.IsEnabled && oNotice.Text.Contains("provider"),
                "Empty provider filters explain why certificate creation is unavailable");
            ((CheckBox)oWizard.FindName("oSoftwareCheckbox")).IsChecked = true;
            oAlgorithm.SelectedItem = "RSA";
            ((ComboBox)oWizard.FindName("oHashComboBox")).SelectedItem = "SHA256";
            oLength.Text = "2048";
            oWizard.FontSize = 12;
            App.ApplyTheme(false);

            // Create an isolated real Windows certificate and dismiss only this creator's result popup.
            string sResultTitle = null;
            DispatcherTimer oDismiss = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(25) };
            oDismiss.Tick += (s, e) =>
            {
                Popup oResult = Application.Current.Windows.OfType<Popup>()
                    .FirstOrDefault(w => ReferenceEquals(w.Owner, oWizard));
                if (oResult == null) return;
                sResultTitle = oResult.Title;
                oResult.DialogResult = true;
            };
            oDismiss.Start();
            try
            {
                oCreate.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Check(!oCreate.IsEnabled && !oTabs.IsEnabled && oNotice.Text.Contains("Creating"),
                    "Certificate creation paints a busy state and prevents repeated submissions");
                PumpUntil(() => oTabs.IsEnabled);
            }
            finally { oDismiss.Stop(); }
            using X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            oStore.Open(OpenFlags.ReadOnly);
            using X509Certificate2 oCreated = oStore.Certificates.SingleOrDefault(c =>
                c.GetNameInfo(X509NameType.SimpleName, false) == sCertificateName);
            Check(sResultTitle == "Certificate Created" && oCreated?.HasPrivateKey == true &&
                oCreated.Subject == oCreated.Issuer && oCreate.IsEnabled,
                "The creator installs a self-signed certificate and restores its controls after success");
            using RSA oPublicKey = oCreated.GetRSAPublicKey();
            using RSA oPrivateKey = oCreated.GetRSAPrivateKey();
            byte[] oPayload = [1, 2, 3, 4];
            Check(oPrivateKey.Decrypt(oPublicKey.Encrypt(oPayload, RSAEncryptionPadding.OaepSHA256),
                RSAEncryptionPadding.OaepSHA256).SequenceEqual(oPayload),
                "A certificate created through the form has a usable Windows encryption key");
        }
        finally
        {
            oWizard.Close();
            App.ApplyTheme(false);
            using X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            oStore.Open(OpenFlags.ReadWrite);
            foreach (X509Certificate2 oCreated in oStore.Certificates.Where(c =>
                c.GetNameInfo(X509NameType.SimpleName, false) == sCertificateName))
            {
                using (oCreated)
                using (RSA oPrivateKey = oCreated.GetRSAPrivateKey())
                {
                    oStore.Remove(oCreated);
                    if (oPrivateKey is RSACng oCng) oCng.Key.Delete();
                }
            }
        }
    }
}
