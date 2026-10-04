using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Ribbon;
using System.Xml.Linq;
using Crypture;

internal static partial class RegressionTests
{
    private static int RunConfiguredStartup()
    {
        // Exercise the actual Application startup in a process with no cached configuration or WPF state.
        App oApp = new App { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        oApp.InitializeComponent();
        var oSettings = Crypture.Properties.Settings.Default;
        string sOriginalLastVault = oSettings.LastVault;
        StringCollection oOriginalRecent = oSettings.RecentVaults;
        string sExpectedVault = Environment.GetEnvironmentVariable("CRYPTURE_TEST_STARTUP_VAULT");
        int nExpectedLimit = sExpectedVault == null ? 2 : 0;
        oSettings.LastVault = sExpectedVault ?? "";
        oSettings.RecentVaults = sExpectedVault == null ? new StringCollection() :
            new StringCollection { Path.Combine(Path.GetTempPath(), "missing-startup-vault.cryptdb") };
        bool bPassed = false;
        EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent,
            new RoutedEventHandler((s, e) =>
            {
                if (s is not ItemBrowser oBrowser || e.OriginalSource != oBrowser) return;
                oBrowser.Left = oBrowser.Top = -20000;
                oBrowser.ShowInTaskbar = false;
            }));
        oApp.Dispatcher.BeginInvoke(new Action(() =>
        {
            try
            {
                ItemBrowser oBrowser = (ItemBrowser)oApp.MainWindow;
                Check(oBrowser.IsLoaded && ((CheckBox)oBrowser.FindName("oHideAccessible")).IsChecked == true &&
                    ((Ribbon)oBrowser.FindName("ribbon")).IsMinimized &&
                    ItemBrowser.RecentVaultLimit == nExpectedLimit &&
                    ClipboardExpiration.Timeout == TimeSpan.FromSeconds(2) &&
                    App.PrivacyIdleTimeout == TimeSpan.FromMinutes(1) &&
                    ((System.Windows.Threading.DispatcherTimer)typeof(App).GetField("oPrivacyTimer",
                        BindingFlags.Instance | BindingFlags.NonPublic).GetValue(oApp)).IsEnabled,
                    "Fresh application startup uses configured browser, clipboard, and idle defaults");
                if (sExpectedVault != null)
                    Check(CryptureEntities.Storage.DisplayName == sExpectedVault &&
                        oSettings.LastVault == sExpectedVault && oSettings.RecentVaults.Count == 0,
                        "Startup opens the saved Vault without retaining recent history");
                bPassed = true;
            }
            catch (Exception oError) { Console.Error.WriteLine(oError); }
            finally
            {
                oSettings.LastVault = sOriginalLastVault;
                oSettings.RecentVaults = oOriginalRecent;
                oApp.MainWindow?.Close();
                oApp.Shutdown(bPassed ? 0 : 1);
            }
        }), System.Windows.Threading.DispatcherPriority.ContextIdle);
        return oApp.Run();
    }

    private static void TestConfigurationDefaults(string sDirectory)
    {
        string sPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginal = File.ReadAllBytes(sPath);
        string sConnection = CryptureEntities.ConnectionString;
        var oSettings = Crypture.Properties.Settings.Default;
        StringCollection oRecent = oSettings.RecentVaults;
        string sLastVault = oSettings.LastVault;
        StringCollection oAutomatic = oSettings.AutomaticallyAddedCertificatesList;
        bool bCertificateProtection = oSettings.EnableCertificateProtection;
        bool bFileUpload = oSettings.ShowItemFileUpload;
        bool bSelfSigned = oSettings.AllowSelfSignedCertificates;
        bool bRevocation = oSettings.PerformCertificateRevocationCheck;
        List<Window> oWindows = [];

        void Configure(params (string Key, string Value)[] oValues)
        {
            XDocument oConfig = XDocument.Parse(Encoding.UTF8.GetString(oOriginal).TrimStart('\uFEFF'));
            XElement oAppSettings = oConfig.Root.Element("appSettings");
            foreach (var oValue in oValues)
            {
                oAppSettings.Elements("add").Where(e => (string)e.Attribute("key") == oValue.Key).Remove();
                if (oValue.Value != null) oAppSettings.Add(new XElement("add",
                    new XAttribute("key", oValue.Key), new XAttribute("value", oValue.Value)));
            }
            oConfig.Save(sPath);
        }

        T Keep<T>(T oWindow) where T : Window
        {
            oWindows.Add(oWindow);
            return oWindow;
        }

        void Invalid(Action oAction, string sSetting)
        {
            try { oAction(); }
            catch (InvalidOperationException oError)
            {
                Check(oError.GetBaseException().Message.Contains(sPath) && oError.Message.Contains(sSetting),
                    "Invalid configuration identifies its file and setting: " + sSetting);
                return;
            }
            throw new Exception("Invalid configuration was accepted: " + sSetting);
        }

        try
        {
            // New-item controls honor config while persisted items retain their own access rules.
            string sVault = Path.Combine(sDirectory, "configured-defaults.cryptdb");
            DatabaseOperations.CreateDatabase(sVault,
                File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
            CryptureEntities.DatabasePath = sVault;
            oSettings["AutomaticallyAddedCertificatesList"] = new StringCollection();
            Configure(("NewItemLabel", "Team & Operations"), ("NewItemType", "Totp"),
                ("NewItemProtectionMode", "CertificateBased"), ("NewItemWindowsScope", "LocalMachine"),
                ("NewItemRequireAllPrincipals", "True"), ("NewItemIncludeCurrentUser", "False"),
                ("NewItemIncludeOwnCertificates", "False"), ("TotpAlgorithm", "SHA256"), ("TotpDigits", "8"),
                ("TotpPeriodSeconds", "60"), ("TotpIssuer", "Team & Operations"), ("TotpAccount", "team@example.com"));
            ItemEditor oEditor = Keep(new ItemEditor());
            PumpUntil(() => oEditor.CertificateLoading.IsCompleted);
            Check(oEditor.ThisItem.Label == "Team & Operations" && oEditor.ThisItem.ItemType == "totp" &&
                ((ComboBox)oEditor.FindName("oProtectionMode")).SelectedIndex == 1 &&
                ((ComboBox)oEditor.FindName("oPrincipalScope")).SelectedIndex == 2 &&
                ((ComboBox)oEditor.FindName("oPrincipalMatch")).SelectedIndex == 1 &&
                ((ListBox)oEditor.FindName("oPrincipalList")).Items.Count == 0 && oEditor.UserListSelected.Count == 0,
                "New-item defaults initialize label, type, encryption, scope, match rule, and recipients");
            TotpPanel oPanel = (TotpPanel)oEditor.FindName("oTotpPanel");
            ((TextBox)oPanel.FindName("oSecretInput")).Text = RfcTotpSecret;
            using (TotpSecret oValue = TotpSecret.Parse(oPanel.ReadUri()))
                Check(oValue.Algorithm == "SHA256" && oValue.Digits == 8 && oValue.Period == 60 &&
                    oValue.Issuer == "Team & Operations" && oValue.Account == "team@example.com",
                    "All authenticator defaults flow through the real setup controls into the saved URI");
            ((ComboBox)oPanel.FindName("oAlgorithm")).SelectedValue = "SHA512";
            using (TotpSecret oValue = TotpSecret.Parse(oPanel.ReadUri()))
                Check(oValue.Algorithm == "SHA512", "User edits override authenticator defaults within a setup");
            oPanel.LoadUri("otpauth://totp/Imported?secret=" + RfcTotpSecret);
            using (TotpSecret oValue = TotpSecret.Parse(oPanel.ReadUri()))
                Check(oValue.Algorithm == "SHA1" && oValue.Digits == 6 && oValue.Period == 30 &&
                    oValue.Issuer == "" && oValue.Account == "Imported",
                    "Imported links retain protocol defaults even when application defaults differ");
            oPanel.Clear();
            Configure(("TotpPeriodSeconds", "90"));
            oPanel.SetActive(true);
            Check(((TextBox)oPanel.FindName("oPeriod")).Text == "90",
                "Clearing an authenticator applies current defaults to the next empty setup");

            DatabaseOperations.SaveItem(new Item { Label = "Saved text", ItemType = "text" },
                Encoding.Unicode.GetBytes("Saved contents"), [], PrincipalProtection.LocalUserDescriptor);
            Item oStored;
            using (CryptureEntities oContext = new CryptureEntities())
                oStored = DatabaseOperations.LoadItem(oContext.Items.Single().ItemId);
            Configure(("NewItemType", "Invalid"), ("TotpAlgorithm", "Invalid"));
            ItemEditor oSaved = Keep(new ItemEditor(oStored));
            Check(oSaved.ThisItem.Label == "Saved text" && oSaved.ThisItem.ItemType == "text" &&
                ((ComboBox)oSaved.FindName("oProtectionMode")).SelectedIndex == 0 &&
                ((ComboBox)oSaved.FindName("oPrincipalScope")).SelectedIndex == 1,
                "Saved items open with their stored settings despite invalid unused new-item defaults");
            oPanel.LoadUri("otpauth://totp/Saved?secret=" + RfcTotpSecret + "&algorithm=SHA512&digits=8&period=45");
            using (TotpSecret oValue = TotpSecret.Parse(oPanel.ReadUri()))
                Check(oValue.Algorithm == "SHA512" && oValue.Period == 45,
                    "Saved authenticator settings remain usable despite invalid unused defaults");
            Invalid(() => Keep(new ItemEditor()), "NewItemType");

            // Defaults never bypass feature availability or administrator-required certificates.
            Configure(("NewItemProtectionMode", "CertificateBased"), ("NewItemWindowsScope", "Domain"));
            oSettings["EnableCertificateProtection"] = false;
            ItemEditor oFallback = Keep(new ItemEditor());
            Check(((ComboBox)oFallback.FindName("oProtectionMode")).SelectedIndex == 0 &&
                ((ComboBox)oFallback.FindName("oPrincipalScope")).SelectedIndex ==
                    (PrincipalProtection.IsDomainJoined ? 0 : 1),
                "Unavailable encryption and domain defaults select usable Windows protection");
            oSettings["EnableCertificateProtection"] = bCertificateProtection;
            using (RSA oKey = new RSACng(2048))
            using (X509Certificate2 oCert = Certificate(oKey, "Required default recipient",
                DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1)))
            {
                User oUser = new User { Certificate = oCert.RawData };
                using (CryptureEntities oContext = new CryptureEntities())
                {
                    oContext.Users.Add(oUser);
                    oContext.SaveChanges();
                }
                oSettings["AutomaticallyAddedCertificatesList"] = new StringCollection
                    { Convert.ToBase64String(oCert.RawData) };
                Configure(("NewItemProtectionMode", "UserBased"), ("NewItemIncludeOwnCertificates", "False"));
                ItemEditor oRequired = Keep(new ItemEditor());
                PumpUntil(() => oRequired.CertificateLoading.IsCompleted);
                Check(((ComboBox)oRequired.FindName("oProtectionMode")).SelectedIndex == 1 &&
                    oRequired.UserListSelected.Any(u => u.UserId == oUser.UserId),
                    "Required recipients retain certificate encryption and selection despite conflicting defaults");
            }
            oSettings["AutomaticallyAddedCertificatesList"] = new StringCollection();

            // Check own-certificate defaults against a real persisted Windows private key.
            CngKeyCreationParameters oKeyOptions = new CngKeyCreationParameters
            {
                KeyUsage = CngKeyUsages.Decryption | CngKeyUsages.Signing
            };
            oKeyOptions.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
            using (CngKey oKey = CngKey.Create(CngAlgorithm.Rsa,
                "Crypture.DefaultsTest-" + Guid.NewGuid().ToString("N"), oKeyOptions))
            using (RSA oRsa = new RSACng(oKey))
            using (X509Certificate2 oCert = Certificate(oRsa, "Own default recipient",
                DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1)))
            using (X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                oStore.Open(OpenFlags.ReadWrite);
                try
                {
                    oStore.Add(oCert);
                    oSettings.AllowSelfSignedCertificates = true;
                    oSettings.PerformCertificateRevocationCheck = false;
                    User oUser = new User { Certificate = oCert.RawData };
                    using (CryptureEntities oContext = new CryptureEntities())
                    {
                        oContext.Users.Add(oUser);
                        oContext.SaveChanges();
                    }
                    foreach (bool bInclude in new[] { true, false })
                    {
                        Configure(("NewItemIncludeOwnCertificates", bInclude.ToString()));
                        ItemEditor oOwn = Keep(new ItemEditor());
                        PumpUntil(() => oOwn.CertificateLoading.IsCompleted);
                        Check(oOwn.UserListSelected.Any(u => u.UserId == oUser.UserId) == bInclude,
                            "Own-certificate default controls asynchronous private-key selection: " + bInclude);
                    }
                }
                finally
                {
                    oStore.Remove(oCert);
                    oKey.Delete();
                    oSettings.AllowSelfSignedCertificates = bSelfSigned;
                    oSettings.PerformCertificateRevocationCheck = bRevocation;
                }
            }
            Configure(("NewItemType", "File"));
            ItemEditor oFile = Keep(new ItemEditor());
            PumpUntil(() => oFile.CertificateLoading.IsCompleted);
            Check(((ComboBox)oFile.FindName("oItemTypeSelector")).SelectedIndex == 3 &&
                !((RibbonButton)oFile.FindName("oSaveItemButton")).IsEnabled &&
                ((Label)oFile.FindName("oDownloadTextBox")).Content.Equals("Choose File Attachment..."),
                "A new file draft requests an attachment and cannot save an empty payload");
            ((ComboBox)oFile.FindName("oItemTypeSelector")).SelectedIndex = 0;
            Check(oFile.ThisItem.ItemType == "text",
                "A file draft can switch to a text secret before attaching a file");
            oSettings["ShowItemFileUpload"] = false;
            ItemEditor oNoUpload = Keep(new ItemEditor());
            Check(oNoUpload.ThisItem.ItemType == "text", "Disabled file uploads override the file-item default");
            oSettings["ShowItemFileUpload"] = bFileUpload;
            Configure(("NewItemType", "RichText"));
            ItemEditor oRichDefault = Keep(new ItemEditor());
            Check(oRichDefault.ThisItem.ItemType == "richtext" &&
                ((ComboBox)oRichDefault.FindName("oItemTypeSelector")).SelectedIndex == 1 &&
                ((RichTextBox)oRichDefault.FindName("oRichItemData")).Visibility == Visibility.Visible,
                "Rich text can be the configured new-item format");

            // Provider discovery applies configured choices to actual controls after asynchronous loading.
            const string sSoftware = "Microsoft Software Key Storage Provider";
            const string sHardware = "Test Hardware Provider";
            CertWizard.ProviderDetails oSoftware = new CertWizard.ProviderDetails
            {
                SignatureAlgorithmns = ["RSA", "ECDH_P384"], HashAlgorithmns = ["SHA256", "SHA384"],
                SignatureMinLengths = new() { ["RSA"] = 1024, ["ECDH_P384"] = 384 },
                SignatureMaxLengths = new() { ["RSA"] = 16384, ["ECDH_P384"] = 384 }
            };
            CertWizard.ProviderDetails oHardware = new CertWizard.ProviderDetails
            {
                IsHardware = true, IsLegacy = true,
                SignatureAlgorithmns = ["RSA", "ECDH_P384"], HashAlgorithmns = ["SHA256", "SHA384"],
                SignatureMinLengths = oSoftware.SignatureMinLengths,
                SignatureMaxLengths = oSoftware.SignatureMaxLengths
            };
            CertWizard Wizard()
            {
                var oLoaded = new TaskCompletionSource<Dictionary<string, CertWizard.ProviderDetails>>();
                CertWizard oWizard = Keep(new CertWizard(_ => Task.FromResult(oSoftware), _ => oLoaded.Task));
                Task oLoad = (Task)typeof(CertWizard).GetMethod("LoadProvidersAsync",
                    BindingFlags.Instance | BindingFlags.NonPublic).Invoke(oWizard, [false]);
                oLoaded.SetResult(new() { [sSoftware] = oSoftware, [sHardware] = oHardware });
                PumpUntil(() => oLoad.IsCompleted);
                oLoad.GetAwaiter().GetResult();
                return oWizard;
            }

            Configure(("CertificateGeneratorProvider", sHardware), ("CertificateGeneratorKeyAlgorithm", "RSA"),
                ("CertificateGeneratorKeyLength", "4096"), ("CertificateGeneratorHashAlgorithm", "SHA384"),
                ("CertificateGeneratorSubject", "Team Certificate"), ("CertificateGeneratorIssuer", "Team Issuer"),
                ("CertificateGeneratorStartOffsetDays", "-2"), ("CertificateGeneratorValidityYears", "0"),
                ("CertificateGeneratorValidityDays", "90"), ("CertificateGeneratorSelfSigned", "False"),
                ("CertificateGeneratorStore", "LocalMachine"), ("CertificateGeneratorShowHardwareProviders", "True"),
                ("CertificateGeneratorShowSoftwareProviders", "False"),
                ("CertificateGeneratorShowLegacyProviders", "True"),
                ("CertificateGeneratorKeyExportable", "True"), ("CertificateGeneratorPasswordProtectKey", "True"),
                ("CertificateGeneratorKeyUsages", "DigitalSignature;KeyEncipherment"),
                ("CertificateGeneratorEnhancedKeyUsages", "1.3.6.1.5.5.7.3.2;1.3.6.1.4.1.55555.1"));
            CertWizard oWizard = Wizard();
            Check(oWizard.SelectedProvider == sHardware && oWizard.SelectedSignature == "RSA" &&
                ((TextBox)oWizard.FindName("oKeyLengthTextBox")).Text == "4096" &&
                (string)((ComboBox)oWizard.FindName("oHashComboBox")).SelectedItem == "SHA384",
                "Asynchronous provider loading honors configured provider, algorithms, and key length");
            Check(((TextBox)oWizard.FindName("oSubjectTextBox")).Text == "Team Certificate" &&
                ((TextBox)oWizard.FindName("oIssuerTextBox")).Text == "Team Issuer" &&
                ((DatePicker)oWizard.FindName("oValidFromDatePicker")).SelectedDate == DateTime.Today.AddDays(-2) &&
                ((DatePicker)oWizard.FindName("oValidUntilDatePicker")).SelectedDate == DateTime.Today.AddDays(88) &&
                ((RadioButton)oWizard.FindName("oCertificateRequestRadio")).IsChecked == true,
                "Certificate identity, validity offsets and duration, and request mode use configured defaults");
            RadioButton oMachine = (RadioButton)oWizard.FindName("oCertificateStoreMachineRadio");
            Check(oMachine.IsChecked == oMachine.IsEnabled &&
                ((RadioButton)oWizard.FindName("oCertificateStoreUserRadio")).IsChecked == !oMachine.IsEnabled &&
                ((CheckBox)oWizard.FindName("oHardwareCheckbox")).IsChecked == true &&
                ((CheckBox)oWizard.FindName("oSoftwareCheckbox")).IsChecked == false &&
                ((CheckBox)oWizard.FindName("oShowLegacyCheckbox")).IsChecked == true &&
                ((CheckBox)oWizard.FindName("oKeyExportableCheckbox")).IsChecked == true &&
                ((CheckBox)oWizard.FindName("oPasswordProtectCheckbox")).IsChecked == true,
                "Certificate filters and key flags apply while the Computer store still requires elevation");
            Check(oWizard.KeyUsages.Where(u => u.Selected).Select(u => u.Oid).ToHashSet().SetEquals(
                ["DigitalSignature", "KeyEncipherment"]) &&
                oWizard.EnhancedKeyUsages.Where(u => u.Selected).Select(u => u.Oid).ToHashSet().SetEquals(
                    ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.55555.1"]),
                "Configured key usages and custom EKU OIDs are selected and editable");
            ((ComboBox)oWizard.FindName("oSignatureComboBox")).SelectedItem = "ECDH_P384";
            Check(((TextBox)oWizard.FindName("oKeyLengthTextBox")).Text == "384" &&
                oWizard.KeyUsages.Count(u => u.Selected) == 2,
                "Fixed curve lengths remain valid and explicit usages survive algorithm changes");

            Configure(("CertificateGeneratorKeyAlgorithm", "ECDH_P384"));
            CertWizard oEcdh = Wizard();
            Check(oEcdh.SelectedSignature == "ECDH_P384" &&
                oEcdh.KeyUsages.Single(u => u.Selected).Oid == "KeyAgreement",
                "Automatic certificate usages follow the configured key algorithm");
            Configure(("CertificateGeneratorProvider", "Unavailable"),
                ("CertificateGeneratorKeyAlgorithm", "Unavailable"), ("CertificateGeneratorHashAlgorithm", "Unavailable"));
            CertWizard oAvailable = Wizard();
            Check(oAvailable.SelectedProvider == sSoftware && oAvailable.SelectedSignature == "RSA" &&
                (string)((ComboBox)oAvailable.FindName("oHashComboBox")).SelectedItem == "SHA256",
                "Unavailable certificate preferences fall back to available provider capabilities");
            Configure(("CertificateGeneratorKeyLength", "1024"));
            Invalid(() => Wizard(), "CertificateGenerator");
            Configure(("CertificateGeneratorKeyUsages", "InvalidUsage"));
            Invalid(() => Wizard(), "CertificateGeneratorKeyUsages");
            Configure(("CertificateGeneratorEnhancedKeyUsages", "1.2.bad"));
            Invalid(() => Wizard(), "CertificateGeneratorEnhancedKeyUsages");

            // Browser, report, and clipboard behavior use the same adjacent defaults.
            Configure(("HideMissingCertificateKeys", "True"), ("RibbonMinimized", "True"),
                ("HideSqlServerOption", "True"),
                ("HealthCheckShowOnlyIssues", "True"), ("RecentVaultLimit", "2"),
                ("ClipboardTimeoutSeconds", "2"), ("AutoConcealIdleMinutes", "1"));
            ItemBrowser oBrowser = Keep(new ItemBrowser());
            VaultHealthWindow oHealth = Keep(new VaultHealthWindow(sVault));
            oSettings.RecentVaults = new StringCollection();
            oSettings.LastVault = "";
            oBrowser.WindowStartupLocation = WindowStartupLocation.Manual;
            oBrowser.Left = oBrowser.Top = -20000;
            oBrowser.ShowActivated = oBrowser.ShowInTaskbar = false;
            oBrowser.Show();
            oBrowser.UpdateLayout();
            Check(((CheckBox)oBrowser.FindName("oHideAccessible")).IsChecked == true,
                "The browser filter initializes from configuration");
            Check(((CheckBox)oHealth.FindName("oIssuesOnly")).IsChecked == true,
                "The health report filter initializes from configuration");
            Check(((Ribbon)oBrowser.FindName("ribbon")).IsMinimized,
                "The browser ribbon initializes from configuration");
            Check(((RibbonButton)oBrowser.FindName("oSqlServerButton")).Visibility == Visibility.Collapsed,
                "Configuration hides the SQL Server ribbon option");
            SqlServerVaultDialog oSqlDialog = Keep(new SqlServerVaultDialog());
            CheckBox oCreateSql = (CheckBox)oSqlDialog.FindName("oCreateDatabase");
            Border oEscrowPanel = (Border)oSqlDialog.FindName("oEscrowPanel");
            Check(oEscrowPanel.Visibility == Visibility.Collapsed,
                "SQL Server connection keeps creation-only escrow choices hidden");
            oCreateSql.IsChecked = true;
            Check(oEscrowPanel.Visibility == Visibility.Visible &&
                ((Button)oSqlDialog.FindName("oConnect")).Content.ToString() == "Create",
                "SQL Server creation prompts for the escrow identity");
            oSqlDialog.WindowStartupLocation = WindowStartupLocation.Manual;
            oSqlDialog.Left = oSqlDialog.Top = -20000;
            oSqlDialog.ShowActivated = oSqlDialog.ShowInTaskbar = false;
            oSqlDialog.Show();
            oSqlDialog.UpdateLayout();
            Grid oSqlLayout = (Grid)oSqlDialog.Content;
            Button oSqlCreate = (Button)oSqlDialog.FindName("oConnect");
            double nEscrowBottom = oEscrowPanel.TransformToAncestor(oSqlLayout)
                .Transform(new Point(0, oEscrowPanel.ActualHeight)).Y;
            double nButtonTop = oSqlCreate.TransformToAncestor(oSqlLayout).Transform(new Point()).Y;
            Check(oEscrowPanel.ActualHeight > 90 && nEscrowBottom < nButtonTop &&
                nButtonTop + oSqlCreate.ActualHeight <= oSqlLayout.ActualHeight,
                "SQL Server escrow controls fit above the action buttons");
            var oStart = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            oStart.Environment["CRYPTURE_TEST_DEFAULTS_STARTUP"] = "1";
            using (var oProcess = System.Diagnostics.Process.Start(oStart))
            {
                var oOutput = oProcess.StandardOutput.ReadToEndAsync();
                var oErrors = oProcess.StandardError.ReadToEndAsync();
                if (!oProcess.WaitForExit(15000))
                {
                    oProcess.Kill(true);
                    throw new TimeoutException("The configured startup check did not finish.");
                }
                Check(oProcess.ExitCode == 0, "Configured defaults work through actual application startup: " +
                    oOutput.GetAwaiter().GetResult().Trim() + oErrors.GetAwaiter().GetResult().Trim());
            }
            for (int nIndex = 0; nIndex < 3; nIndex++)
                oBrowser.RememberRecentVault(Path.Combine(sDirectory, "configured-" + nIndex + ".cryptdb"));
            Check(oSettings.RecentVaults.Count == 2 &&
                oSettings.RecentVaults[0].EndsWith("configured-2.cryptdb") &&
                !oSettings.RecentVaults.Cast<string>().Any(s => s.EndsWith("configured-0.cryptdb")),
                "Configured history limit evicts the oldest Vaults in the real browser");
            DateTime oNow = DateTime.UtcNow;
            uint nSequence = 1;
            int nClears = 0;
            using (ClipboardExpiration oExpiration = new ClipboardExpiration(() => nSequence,
                nExpected => { if (nSequence == nExpected) nClears++; return true; }, () => oNow))
            {
                oExpiration.TrackCopy();
                oNow = oNow.AddSeconds(1);
                oExpiration.ClearExpired();
                Check(nClears == 0, "Configured clipboard timeout preserves a copy before its deadline");
                oNow = oNow.AddSeconds(1);
                oExpiration.ClearExpired();
                Check(nClears == 1, "Configured clipboard timeout clears the unchanged copy at its deadline");
                Configure(("ClipboardTimeoutSeconds", "4"));
                oExpiration.TrackCopy();
                oNow = oNow.AddSeconds(2);
                oExpiration.ClearExpired();
                Check(nClears == 1, "The next copy observes a changed timeout without restarting");
                nSequence++;
                oNow = oNow.AddSeconds(2);
                oExpiration.ClearExpired();
                Check(nClears == 1, "Configured expiration still preserves another application's newer copy");
            }
            Configure(("HideMissingCertificateKeys", "True"), ("RibbonMinimized", "True"),
                ("RecentVaultLimit", "0"), ("ClipboardTimeoutSeconds", "2"),
                ("AutoConcealIdleMinutes", "1"));
            oBrowser.RememberRecentVault(sVault);
            Check(oSettings.RecentVaults.Count == 0 && oSettings.LastVault == sVault,
                "A zero history limit still remembers the last Vault for startup");
            oStart.Environment["CRYPTURE_TEST_STARTUP_VAULT"] = sVault;
            using (var oProcess = System.Diagnostics.Process.Start(oStart))
            {
                var oOutput = oProcess.StandardOutput.ReadToEndAsync();
                var oErrors = oProcess.StandardError.ReadToEndAsync();
                if (!oProcess.WaitForExit(15000))
                {
                    oProcess.Kill(true);
                    throw new TimeoutException("The last-Vault startup check did not finish.");
                }
                Check(oProcess.ExitCode == 0, "Startup reopens the last Vault with recent history disabled: " +
                    oOutput.GetAwaiter().GetResult().Trim() + oErrors.GetAwaiter().GetResult().Trim());
            }
            Configure(("ClipboardTimeoutSeconds", "0"));
            Invalid(() => { _ = ClipboardExpiration.Timeout; }, "ClipboardTimeoutSeconds");
            Configure(("AutoConcealIdleMinutes", "0"));
            Check(App.PrivacyIdleTimeout == TimeSpan.Zero, "Zero disables idle concealment");
            Configure(("AutoConcealIdleMinutes", "1441"));
            Invalid(() => { _ = App.PrivacyIdleTimeout; }, "AutoConcealIdleMinutes");
            Configure(("RecentVaultLimit", "invalid"));
            Invalid(() => Keep(new ItemBrowser()), "RecentVaultLimit");
            Configure(("HideMissingCertificateKeys", "yes"));
            Invalid(() => Keep(new ItemBrowser()), "HideMissingCertificateKeys");
            Configure(("HideSqlServerOption", "yes"));
            Invalid(() => Keep(new ItemBrowser()), "HideSqlServerOption");
            Configure(("TotpDigits", "7"));
            oPanel.Clear();
            oPanel.SetActive(true);
            Check(((TextBlock)oPanel.FindName("oValidationMessage")).Text.Contains("TotpDigits"),
                "Invalid authenticator defaults appear in the setup panel");
            Configure(("TotpPeriodSeconds", "3601"));
            Invalid(() => oPanel.ReadUri(), "TotpPeriodSeconds");
            Configure(("TotpAccount", "invalid:account"));
            Invalid(() => oPanel.ReadUri(), "TotpAccount");

            File.Delete(sPath);
            ItemEditor oBuiltIn = Keep(new ItemEditor());
            CertWizard oBuiltInWizard = Wizard();
            Check(oBuiltIn.ThisItem.Label == "My New Item" && oBuiltIn.ThisItem.ItemType == "text" &&
                ((TextBox)oBuiltInWizard.FindName("oKeyLengthTextBox")).Text == "2048" &&
                ((DatePicker)oBuiltInWizard.FindName("oValidUntilDatePicker")).SelectedDate ==
                    DateTime.Today.AddYears(3) &&
                ClipboardExpiration.Timeout == TimeSpan.FromMinutes(5) &&
                App.PrivacyIdleTimeout == TimeSpan.FromMinutes(10) && ItemBrowser.RecentVaultLimit == 10 &&
                !File.Exists(sPath), "Missing configuration retains built-in defaults without creating a file");
        }
        finally
        {
            File.WriteAllBytes(sPath, oOriginal);
            oSettings["EnableCertificateProtection"] = bCertificateProtection;
            oSettings["ShowItemFileUpload"] = bFileUpload;
            oSettings["AutomaticallyAddedCertificatesList"] = oAutomatic;
            oSettings.AllowSelfSignedCertificates = bSelfSigned;
            oSettings.PerformCertificateRevocationCheck = bRevocation;
            oSettings.RecentVaults = oRecent;
            oSettings.LastVault = sLastVault;
            foreach (Window oWindow in oWindows)
            {
                if (oWindow is ItemEditor)
                    typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                        .SetValue(oWindow, false);
                oWindow.Close();
            }
            oSettings.Save();
            CryptureEntities.ConnectionString = sConnection;
        }
    }
}
