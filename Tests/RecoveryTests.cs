using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Crypture;

internal static partial class RegressionTests
{
    private static void SetRecoveryConfig(string sDescriptor, string sCertificate)
    {
        string sPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        string sConfig = File.ReadAllText(sPath);
        string sDescriptorValue = SecurityElement.Escape(sDescriptor ?? "")
            .Replace("\t", "&#x9;").Replace("\r", "&#xD;").Replace("\n", "&#xA;");
        string sSection = "<appSettings><add key=\"RecoveryProtectionDescriptor\" value=\"" +
            sDescriptorValue + "\"/><add key=\"RecoveryCertificateBase64\" value=\"" +
            SecurityElement.Escape(sCertificate ?? "") + "\"/></appSettings>";
        if (!sConfig.Contains("<appSettings>")) throw new Exception("The test configuration lacks appSettings.");
        File.WriteAllText(sPath, Regex.Replace(sConfig, @"<appSettings>.*?</appSettings>",
            m => sSection, RegexOptions.Singleline), new UTF8Encoding(false));
    }

    private static void TestRecovery(string sDirectory, X509Certificate2 oPrimaryCert, X509Certificate2 oRecoveryCert)
    {
        string sConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginalConfig = File.ReadAllBytes(sConfigPath);
        string sPreviousConnection = CryptureEntities.ConnectionString;
        bool bSelfSigned = Crypture.Properties.Settings.Default.AllowSelfSignedCertificates;
        bool bRevocation = Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck;
        byte[] oPlain = Encoding.Unicode.GetBytes("Emergency recovery works across both protection modes.");
        string sCertificate = Convert.ToBase64String(oRecoveryCert.RawData);
        string sPath = Path.Combine(sDirectory, "recovery.cryptdb");
        try
        {
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = true;
            Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = false;

            // Exercise configured aliases and native policies through Windows descriptor validation.
            ProtectionPrincipal oUser = new ProtectionPrincipal(CertificateOperations.CurrentUserSid);
            ProtectionPrincipal oGroup = new ProtectionPrincipal("S-1-5-32-545");
            string sAny = PrincipalProtection.CreateDescriptor(new[] { oUser, oGroup }, false);
            string sAll = PrincipalProtection.CreateDescriptor(new[] { oUser, oGroup }, true);
            string sMixed = "SID=" + oUser.Sid + " AND SID=" + oGroup.Sid + " OR SID=S-1-1-0";
            string sLocalMixed = "SID=" + oUser.Sid + " OR LOCAL=user";
            foreach (var (sConfigured, sExpected) in new[]
            {
                (oUser.Name + " OR SID=" + oGroup.Sid, sAny),
                ("SID=" + oGroup.Sid + " OR " + oUser.Name, sAny),
                (oUser.Name + " AND SID=" + oGroup.Sid, sAll),
                ("SID=" + oGroup.Sid + "  AND  SID=" + oUser.Name, sAll),
                ("SID=" + oUser.Sid + "  OR  SID=" + oGroup.Sid, sAny),
                ("SID=" + oUser.Sid + "\tOR\tSID=" + oGroup.Sid, sAny),
                ("SID=" + oUser.Sid + "\nOR\nSID=" + oGroup.Sid, sAny),
                ("SID=" + oUser.Sid + " OR SID=\\53-1-5-32-545", sAny),
                (sMixed, sMixed),
                ("SID=" + oUser.Name + " AND SID=" + oGroup.Sid + " OR SID=S-1-1-0", sMixed),
                (sLocalMixed, sLocalMixed),
                ("LOCAL=user OR " + oUser.Name, "LOCAL=user OR SID=" + oUser.Sid),
                ("SDDL=O:SYG:SYD:(A;;CCDC;;;WD)", "SDDL=O:SYG:SYD:(A;;CCDC;;;WD)"),
                ("WEBCREDENTIALS=foo\\  OR LOCAL=user", "WEBCREDENTIALS=foo\\  OR LOCAL=user")
            })
            {
                SetRecoveryConfig(sConfigured, null);
                RecoveryPolicy oPolicy = RecoveryPolicy.Read();
                Check(oPolicy.Descriptor == sConfigured &&
                    PrincipalProtection.ResolveRecoveryDescriptor(oPolicy.Descriptor) == sExpected,
                    "Configured recovery retains native rules and resolves principal terms: " + sConfigured);
            }
            SetRecoveryConfig(null, null);
            Check(!RecoveryPolicy.Read().IsEnabled, "Empty adjacent recovery settings preserve normal protection");
            DatabaseOperations.CreateDatabase(sPath,
                File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SQLite.sql")));
            CryptureEntities.DatabasePath = sPath;
            User oPrimary = new User { Certificate = oPrimaryCert.RawData };
            using (CryptureEntities oContext = new CryptureEntities())
            {
                oContext.Users.Add(oPrimary);
                oContext.SaveChanges();
            }
            DatabaseOperations.SaveItem(new Item { Label = "Certificate Item", ItemType = "text" },
                oPlain, new[] { oPrimary });
            Item oCertificateItem;
            using (CryptureEntities oContext = new CryptureEntities())
                oCertificateItem = LoadItem(oContext.Items.Single().ItemId);

            // Existing items report missing coverage until the user can unlock and save them.
            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, null);
            VaultHealthReport oReport = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(oReport.Findings.Any(f => f.Kind == "Emergency Recovery" && f.Severity == HealthStatus.Warning),
                "Health check reports old items that lack the configured recovery access");
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = LoadItem(oCertificateItem.ItemId);
            Check(oCertificateItem.Cipher.CipherParams == ItemCryptography.RecoveryFormat &&
                oCertificateItem.Cipher.ProtectionDescriptor == null,
                "Adding Windows recovery preserves the primary certificate protection mode");
            Check(ItemCryptography.Decrypt(oCertificateItem).SequenceEqual(oPlain),
                "Windows recovery decrypts a certificate item without its certificate private key");
            Check(ItemCryptography.Decrypt(oCertificateItem, oCertificateItem.Instances.Single(), oPrimaryCert)
                .SequenceEqual(oPlain), "Primary certificate still decrypts after Windows recovery is added");
            oReport = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(!oReport.Findings.Any(f => f.Severity == HealthStatus.Error || f.Kind == "Emergency Recovery"),
                "Health check accepts saved recovery envelopes and recognizes current coverage");

            // Native boolean policies retain their expression in saved envelopes and health reports.
            const string NativeRecovery = "LOCAL=user AND LOCAL=machine OR LOCAL=user";
            SetRecoveryConfig(NativeRecovery, null);
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = LoadItem(oCertificateItem.ItemId);
            Check(RecoveryProtection.ReadWindowsKeys(oCertificateItem.Cipher).Single().Key == NativeRecovery &&
                ItemCryptography.Decrypt(oCertificateItem).SequenceEqual(oPlain),
                "Native mixed recovery expressions survive a saved Windows key round trip");
            oReport = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(!oReport.Findings.Any(f => f.Severity == HealthStatus.Error || f.Kind == "Emergency Recovery"),
                "Health check matches a saved native mixed recovery policy");
            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, null);
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = LoadItem(oCertificateItem.ItemId);

            DatabaseOperations.SaveItem(new Item { Label = "Windows Item", ItemType = "text" },
                oPlain, null, PrincipalProtection.LocalMachineDescriptor);
            Item oWindowsItem;
            using (CryptureEntities oContext = new CryptureEntities())
                oWindowsItem = LoadItem(
                    oContext.Items.Single(i => i.Label == "Windows Item").ItemId);
            Check(RecoveryProtection.ReadWindowsKeys(oWindowsItem.Cipher).Count == 2 &&
                ItemCryptography.Decrypt(oWindowsItem).SequenceEqual(oPlain),
                "Windows recovery is independent of the original Windows scope");

            // A public recovery certificate is enforced even when the caller supplies no certificate recipients.
            SetRecoveryConfig(null, sCertificate);
            TestConcurrentRecoveryEnrollment(sDirectory, oRecoveryCert);
            DatabaseOperations.SaveItem(oWindowsItem, oPlain, null, PrincipalProtection.LocalMachineDescriptor);
            oWindowsItem = LoadItem(oWindowsItem.ItemId);
            Check(oWindowsItem.Instances.Count == 1 && ItemCryptography.Decrypt(oWindowsItem,
                oWindowsItem.Instances.Single(), oRecoveryCert).SequenceEqual(oPlain),
                "Configured recovery certificate decrypts a Windows item independently");
            Check(ItemCryptography.Decrypt(oWindowsItem).SequenceEqual(oPlain),
                "Original Windows access remains usable with certificate recovery");
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = LoadItem(oCertificateItem.ItemId);
            Instance oRecoveryInstance = oCertificateItem.Instances.Single(i => i.UserId != oPrimary.UserId);
            Check(oCertificateItem.Instances.Count == 2 &&
                ItemCryptography.Decrypt(oCertificateItem, oRecoveryInstance, oRecoveryCert).SequenceEqual(oPlain),
                "Configured recovery certificate also decrypts certificate items");
            Reject(() => DatabaseOperations.RemoveCertificate(oRecoveryInstance.UserId),
                "Configured recovery certificate cannot be removed from the Vault");

            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, sCertificate);
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = LoadItem(oCertificateItem.ItemId);
            Check(ItemCryptography.Decrypt(oCertificateItem).SequenceEqual(oPlain) &&
                ItemCryptography.Decrypt(oCertificateItem,
                    oCertificateItem.Instances.Single(i => i.UserId != oPrimary.UserId),
                        oRecoveryCert).SequenceEqual(oPlain),
                "Both recovery settings grant independent access to a certificate item");
            DatabaseOperations.SaveItem(oWindowsItem, oPlain, null, PrincipalProtection.LocalMachineDescriptor);
            oWindowsItem = LoadItem(oWindowsItem.ItemId);
            Check(RecoveryProtection.ReadWindowsKeys(oWindowsItem.Cipher).Count == 2 &&
                oWindowsItem.Instances.Count == 1 && ItemCryptography.Decrypt(oWindowsItem,
                oWindowsItem.Instances.Single(), oRecoveryCert).SequenceEqual(oPlain),
                "Both recovery settings grant independent access to a Windows item");
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = LoadItem(oCertificateItem.ItemId);
            using (CryptureEntities oContext = new CryptureEntities())
                Check(oContext.Users.Count() == 2 && oCertificateItem.Instances.Count == 2,
                    "Repeated saves deduplicate the automatic recovery certificate");
            TestRecoveryTampering(oCertificateItem, oPrimaryCert);

            string sBackup = Path.Combine(sDirectory, "recovery-backup.cryptdb");
            DatabaseOperations.BackupDatabase(sPath, sBackup);
            SetRecoveryConfig(null, null);
            CryptureEntities.DatabasePath = sBackup;
            Item oBackup = LoadItem(oCertificateItem.ItemId);
            Check(ItemCryptography.Decrypt(oBackup).SequenceEqual(oPlain),
                "Vault backups retain recovery access after the adjacent configuration is removed");
            CryptureEntities.DatabasePath = sPath;
            Check(ItemCryptography.Decrypt(LoadItem(oWindowsItem.ItemId),
                oWindowsItem.Instances.Single(), oRecoveryCert).SequenceEqual(oPlain),
                "Recovery certificate access is stored in the Vault, independent of current configuration");

            // Bad policies and unavailable providers fail without modifying an existing item or its recipients.
            string sMissingAccount = Environment.MachineName + "\\CryptureMissing-" + Guid.NewGuid().ToString("N");
            SetRecoveryConfig(sMissingAccount, null);
            Check(RecoveryPolicy.Read().Descriptor == sMissingAccount,
                "Configured recovery names are not looked up until encryption");
            Reject(() => DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary }),
                "An unresolved recovery name blocks saving");
            Item oPreserved = LoadItem(oCertificateItem.ItemId);
            Check(oPreserved.ModifiedDate == oCertificateItem.ModifiedDate &&
                oPreserved.Cipher.CipherText.SequenceEqual(oCertificateItem.Cipher.CipherText) &&
                oPreserved.Cipher.ProtectedKey.SequenceEqual(oCertificateItem.Cipher.ProtectedKey) &&
                oPreserved.Instances.Count == oCertificateItem.Instances.Count &&
                ItemCryptography.Decrypt(oPreserved).SequenceEqual(oPlain),
                "Failed name resolution preserves saved content, recipients, and recovery access");
            foreach (string sInvalid in new[] { "not base64", Convert.ToBase64String(new byte[] { 1, 2, 3 }) })
            {
                SetRecoveryConfig(null, sInvalid);
                Reject(() => DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary }),
                    "Invalid recovery certificate blocks saving");
                Item oUnchanged = LoadItem(oCertificateItem.ItemId);
                Check(oUnchanged.ModifiedDate == oCertificateItem.ModifiedDate &&
                    oUnchanged.Cipher.CipherText.SequenceEqual(oCertificateItem.Cipher.CipherText) &&
                    oUnchanged.Cipher.ProtectedKey.SequenceEqual(oCertificateItem.Cipher.ProtectedKey) &&
                    oUnchanged.Instances.Count == oCertificateItem.Instances.Count,
                    "Rejected recovery config preserves the saved item and recipients");
            }
            SetRecoveryConfig("LOCAL=not-a-scope", null);
            Reject(() => DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary }),
                "Invalid Windows recovery rule blocks saving without a fallback scope");
            Check(ItemCryptography.Decrypt(LoadItem(oCertificateItem.ItemId)).SequenceEqual(oPlain),
                "Invalid configuration does not prevent decryption through the saved recovery policy");
            using (RSA oKey = new RSACng(2048))
            using (X509Certificate2 oExpired = Certificate(oKey, "Expired Recovery", DateTimeOffset.Now.AddDays(-3),
                DateTimeOffset.Now.AddDays(-1)))
            {
                SetRecoveryConfig(null, Convert.ToBase64String(oExpired.RawData));
                Reject(() => DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary }),
                    "Expired recovery certificate blocks new saves");
            }
            if (!PrincipalProtection.IsDomainJoined)
            {
                using (RSA oKey = new RSACng(2048))
                using (X509Certificate2 oNew = Certificate(oKey, "New Recovery", DateTimeOffset.Now.AddDays(-1),
                    DateTimeOffset.Now.AddDays(1)))
                {
                    SetRecoveryConfig("SID=" + CertificateOperations.CurrentUserSid,
                        Convert.ToBase64String(oNew.RawData));
                    Reject(() => DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary }),
                        "Unavailable domain recovery fails instead of silently saving without it");
                    using (CryptureEntities oContext = new CryptureEntities())
                        Check(oContext.Users.Count() == 2 &&
                            oContext.Instances.Count(i => i.ItemId == oCertificateItem.ItemId) == 2,
                            "Failed recovery wrapping rolls back the inserted certificate and all recipient changes");
                }
            }
            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, Convert.ToBase64String(oPrimaryCert.RawData));
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = LoadItem(oCertificateItem.ItemId);
            Check(oCertificateItem.Instances.Count == 1,
                "Recovery certificate matching a primary recipient is not duplicated");

            // Retain primary certificate recipients while allowing optional recovery removal from Windows items.
            SetRecoveryConfig(null, null);
            User oOptionalRecovery;
            using (CryptureEntities oContext = new CryptureEntities())
                oOptionalRecovery = oContext.Users.Single(u => u.UserId == oRecoveryInstance.UserId);
            DatabaseOperations.SaveItem(new Item { Label = "Certificate-only removal guard", ItemType = "text" },
                oPlain, new[] { oOptionalRecovery });
            Reject(() => DatabaseOperations.RemoveCertificate(oOptionalRecovery.UserId),
                "A Windows item does not waive another item's last certificate recipient guard");
            using (CryptureEntities oContext = new CryptureEntities())
            {
                oContext.Items.Remove(oContext.Items.Single(i => i.Label == "Certificate-only removal guard"));
                oContext.SaveChanges();
            }
            DatabaseOperations.RemoveCertificate(oOptionalRecovery.UserId);
            oWindowsItem = LoadItem(oWindowsItem.ItemId);
            Check(oWindowsItem.Instances.Count == 0 && ItemCryptography.Decrypt(oWindowsItem).SequenceEqual(oPlain),
                "Removing an optional recovery certificate preserves primary Windows decryption");
            using (CryptureEntities oContext = new CryptureEntities())
                Check(!oContext.Users.Any(u => u.UserId == oOptionalRecovery.UserId),
                    "The optional recovery certificate is removed from the Vault");
            Reject(() => DatabaseOperations.RemoveCertificate(oPrimary.UserId),
                "Windows recovery does not waive a certificate item's last primary recipient guard");

            // Exercise real group authorization when the opt-in domain test environment is available.
            string sDomainSids = Environment.GetEnvironmentVariable("CRYPTURE_TEST_DOMAIN_SIDS");
            if (PrincipalProtection.IsDomainJoined && !String.IsNullOrWhiteSpace(sDomainSids))
            {
                ProtectionPrincipal[] oDomainPrincipals = sDomainSids.Split(';')
                    .Select(ProtectionPrincipal.Resolve).ToArray();
                string sDomainPolicy = PrincipalProtection.CreateDescriptor(oDomainPrincipals, false);
                SetRecoveryConfig(String.Join(" OR ", oDomainPrincipals.Select((p, i) =>
                    i == 0 ? p.Name : "SID=" + p.Sid)), sCertificate);
                DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
                oCertificateItem = LoadItem(oCertificateItem.ItemId);
                Check(RecoveryProtection.ReadWindowsKeys(oCertificateItem.Cipher).Single().Key == sDomainPolicy &&
                    ItemCryptography.Decrypt(oCertificateItem).SequenceEqual(oPlain),
                    "Named domain recovery saves SIDs and decrypts without any certificate private key");
                DatabaseOperations.SaveItem(oWindowsItem, oPlain, new[] { oPrimary },
                    PrincipalProtection.LocalMachineDescriptor);
                oWindowsItem = LoadItem(oWindowsItem.ItemId);
                var oEnvelopes = RecoveryProtection.ReadWindowsKeys(oWindowsItem.Cipher);
                Check(oEnvelopes[1].Key == sDomainPolicy,
                    "Named domain recovery stores its resolved SID policy independently of the primary scope");
                byte[] oPrimaryKeys = null, oDomainKeys = null;
                try
                {
                    oPrimaryKeys = PrincipalProtection.Unprotect(oEnvelopes[0].Value);
                    oDomainKeys = PrincipalProtection.Unprotect(oEnvelopes[1].Value);
                    Check(oPrimaryKeys.SequenceEqual(oDomainKeys),
                        "Domain recovery principals unwrap the original Windows item's exact encryption keys");
                }
                finally
                {
                    if (oPrimaryKeys != null) Array.Clear(oPrimaryKeys, 0, oPrimaryKeys.Length);
                    if (oDomainKeys != null) Array.Clear(oDomainKeys, 0, oDomainKeys.Length);
                }
                SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, sCertificate);
                DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            }
            else Console.WriteLine("SKIP: Cross-mode domain recovery requires CRYPTURE_TEST_DOMAIN_SIDS and AD.");
        }
        finally
        {
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            CryptureEntities.ConnectionString = sPreviousConnection;
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = bSelfSigned;
            Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = bRevocation;
        }
    }

    private static void TestConcurrentRecoveryEnrollment(string sDirectory, X509Certificate2 oRecoveryCert)
    {
        IVaultStorage oPrevious = CryptureEntities.Storage;
        SqliteVaultStorage oStorage = new SqliteVaultStorage(Path.Combine(sDirectory, "recovery-enrollment.cryptdb"));
        byte[] oPlain = Encoding.UTF8.GetBytes("Concurrent recovery enrollment");
        try
        {
            // Independent saves can prepare the same missing recovery certificate before either transaction commits.
            oStorage.Create();
            CryptureEntities.Storage = oStorage;
            using ManualResetEventSlim oStart = new ManualResetEventSlim();
            Task[] oSaves = Enumerable.Range(0, 4).Select(n => Task.Run(() =>
            {
                oStart.Wait();
                DatabaseOperations.SaveItem(new Item { Label = "Recovery " + n, ItemType = "text" },
                    oPlain, null, PrincipalProtection.LocalUserDescriptor);
            })).ToArray();
            oStart.Set();
            Task.WaitAll(oSaves);
            using CryptureEntities oContent = new CryptureEntities();
            Check(oContent.Users.Count() == 1 && oContent.Items.Count() == oSaves.Length,
                "Concurrent saves enroll a missing recovery certificate once");
            foreach (long nId in oContent.Items.Select(i => i.ItemId).ToArray())
            {
                Item oSaved = LoadItem(nId);
                Check(ItemCryptography.Decrypt(oSaved, oSaved.Instances.Single(), oRecoveryCert)
                    .SequenceEqual(oPlain) && ItemCryptography.Decrypt(oSaved).SequenceEqual(oPlain),
                    "Concurrent recovery enrollment preserves certificate signatures and Windows access");
            }
        }
        finally
        {
            CryptureEntities.Storage = oPrevious;
        }
    }

    private static void TestRecoveryNotice(string sDirectory)
    {
        string sConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginalConfig = File.ReadAllBytes(sConfigPath);
        string sConnection = CryptureEntities.ConnectionString;
        bool bOriginalDark = App.IsDarkMode;
        ItemEditor oEditor = null;

        void CheckDetails(string sExpected, string sName)
        {
            Exception oFailure = null;
            Application.Current.Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() =>
            {
                Popup oDialog = Application.Current.Windows.OfType<Popup>().Single();
                try
                {
                    TextBox oMessage = (TextBox)oDialog.FindName("oMessage");
                    PumpUntil(() => oMessage.Text != "Loading recovery details...");
                    Check(oDialog.Owner == oEditor && oDialog.Title == "Emergency Recovery" &&
                        oMessage.Text.Contains(sExpected), sName);
                    SavePopupImage(oDialog, sExpected == "RecoveryCertificateBase64"
                        ? "recovery-error" : "recovery-group");
                }
                catch (Exception oError) { oFailure = oError; }
                finally { oDialog.Close(); }
            }));
            ((Hyperlink)oEditor.FindName("oRecoveryDetailsLink"))
                .RaiseEvent(new RoutedEventArgs(Hyperlink.ClickEvent));
            if (oFailure != null) throw oFailure;
        }

        try
        {
            string sVault = Path.Combine(sDirectory, "recovery-notice.cryptdb");
            DatabaseOperations.CreateDatabase(sVault, File.ReadAllText(Path.Combine(AppContext.BaseDirectory,
                "SQLite.sql")));
            CryptureEntities.DatabasePath = sVault;
            ProtectionPrincipal oGroup = new ProtectionPrincipal("S-1-5-32-545");
            foreach (string sDescriptor in new[] { oGroup.Name, "SID=" + oGroup.Name })
            {
                SetRecoveryConfig(sDescriptor, null);
                oEditor = CreateEditor();
                oEditor.Left = oEditor.Top = -20000;
                oEditor.WindowStartupLocation = WindowStartupLocation.Manual;
                oEditor.ShowActivated = oEditor.ShowInTaskbar = false;
                oEditor.Show();
                PumpUntil(() => oEditor.IsLoaded && oEditor.CertificateLoading.IsCompleted);
                TextBlock oNotice = (TextBlock)oEditor.FindName("oRecoveryNotice");
                StackPanel oPane = (StackPanel)oNotice.Parent;
                Check(oNotice.IsVisible && oPane.Children[oPane.Children.Count - 1] == oNotice &&
                    new TextRange(oNotice.ContentStart, oNotice.ContentEnd).Text.Length < 60,
                    "Emergency recovery is a concise notice at the end of the editor pane");
                CheckDetails("Windows: " + oGroup.Name,
                    "Recovery dialog displays the configured group name: " + sDescriptor);

                // Saved policy metadata is displayed without opening any protected keys.
                oEditor.ThisItem.Cipher = new Cipher
                {
                    CipherParams = ItemCryptography.RecoveryFormat,
                    ProtectedKey = TestRecoveryEnvelope("SID=" + oGroup.Sid)
                };
                oEditor.SetEditingControls(true);
                CheckDetails("Saved Windows: " + oGroup.Name,
                    "Recovery dialog displays a saved group SID as its Windows name");
                foreach (bool bDark in new[] { false, true })
                foreach (double nFontSize in new[] { 12d, 18d, 24d })
                foreach (int nMode in new[] { 0, 1 })
                {
                    App.ApplyTheme(bDark);
                    oEditor.FontSize = nFontSize;
                    oEditor.Width = oEditor.MinWidth;
                    oEditor.Height = oEditor.MinHeight;
                    ((ComboBox)oEditor.FindName("oProtectionMode")).SelectedIndex = nMode;
                    oEditor.UpdateLayout();
                    oNotice.BringIntoView();
                    oEditor.UpdateLayout();
                    Border oEncryption = oPane.Children.OfType<Border>().Single();
                    Rect oNoticeBounds = oNotice.TransformToAncestor(oPane)
                        .TransformBounds(new Rect(oNotice.RenderSize));
                    Rect oEncryptionBounds = oEncryption.TransformToAncestor(oPane)
                        .TransformBounds(new Rect(oEncryption.RenderSize));
                    ScrollViewer oScroll = (ScrollViewer)oPane.Parent;
                    Rect oVisibleBounds = oNotice.TransformToAncestor(oScroll)
                        .TransformBounds(new Rect(oNotice.RenderSize));
                    Check(oNoticeBounds.Top >= oEncryptionBounds.Bottom + 8 && oNoticeBounds.Left >= 0 &&
                        oNoticeBounds.Right <= oPane.ActualWidth + 1 && oNotice.ActualHeight <= nFontSize * 3 &&
                        oVisibleBounds.Top >= 0 && oVisibleBounds.Bottom <= oScroll.ActualHeight + 1,
                        "Recovery notice fits below encryption controls, mode " + nMode +
                        ", font " + nFontSize + ", dark " + bDark);

                    string sRenderDirectory = Environment.GetEnvironmentVariable("CRYPTURE_TEST_RENDER_DIR");
                    if (String.IsNullOrWhiteSpace(sRenderDirectory)) continue;
                    Directory.CreateDirectory(sRenderDirectory);
                    FrameworkElement oContent = (FrameworkElement)oEditor.Content;
                    RenderTargetBitmap oRender = new RenderTargetBitmap((int)oContent.ActualWidth,
                        (int)oContent.ActualHeight, 96, 96, PixelFormats.Pbgra32);
                    DrawingVisual oVisual = new DrawingVisual();
                    using (DrawingContext oDrawing = oVisual.RenderOpen())
                    {
                        Rect oBounds = new Rect(oContent.RenderSize);
                        oDrawing.DrawRectangle(oEditor.Background, null, oBounds);
                        oDrawing.DrawRectangle(new VisualBrush(oContent), null, oBounds);
                    }
                    oRender.Render(oVisual);
                    PngBitmapEncoder oEncoder = new PngBitmapEncoder();
                    oEncoder.Frames.Add(BitmapFrame.Create(oRender));
                    using FileStream oFile = File.Create(Path.Combine(sRenderDirectory,
                        "recovery-editor-" + bDark + "-" + nFontSize + "-" + nMode + ".png"));
                    oEncoder.Save(oFile);
                }

                SetRecoveryConfig(oGroup.Name + " S-1-1-0", null);
                CheckDetails("Windows: " + oGroup.Name + " S-1-1-0",
                    "Configured group names retain SID-like text without being rewritten");

                // Configuration errors retain their details while the footer stays short.
                SetRecoveryConfig(null, "not base64");
                oEditor.SetEditingControls(true);
                Check(oNotice.IsVisible && ((Run)oEditor.FindName("oRecoverySummary")).Text ==
                    "Recovery settings need attention. ", "Invalid recovery settings keep a concise warning");
                CheckDetails("RecoveryCertificateBase64", "Recovery details explain invalid configuration");
                SetRecoveryConfig(null, null);
                oEditor.ThisItem.Cipher = null;
                oEditor.SetEditingControls(true);
                Check(oNotice.Visibility == Visibility.Collapsed,
                    "Recovery notice is hidden when no configured or saved recovery exists");
                oEditor.bHasChanges = false;
                oEditor.Close();
                oEditor = null;
            }
        }
        finally
        {
            if (oEditor != null)
            {
                oEditor.bHasChanges = false;
                oEditor.Close();
            }
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            CryptureEntities.ConnectionString = sConnection;
            App.ApplyTheme(bOriginalDark);
        }
    }

    private static void TestRecoveryTampering(Item oItem, X509Certificate2 oCert)
    {
        Instance oInstance = oItem.Instances.Single(i => i.User.Certificate.SequenceEqual(oCert.RawData));
        byte[] oEnvelope = oItem.Cipher.ProtectedKey.ToArray();
        oItem.Cipher.ProtectedKey[oItem.Cipher.ProtectedKey.Length - 1] ^= 1;
        Reject(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
            "Certificate path authenticates the complete recovery key envelope");
        oItem.Cipher.ProtectedKey = oEnvelope;
        string sLabel = oItem.Label;
        oItem.Label += " changed";
        Reject(() => ItemCryptography.Decrypt(oItem), "Windows recovery authenticates the item label");
        Reject(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
            "Certificate recovery authenticates the item label");
        oItem.Label = sLabel;
        oInstance.CipherKey[oInstance.CipherKey.Length - 1] ^= 1;
        Reject(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
            "Recipient key tampering cannot bypass recovery integrity");
        oInstance.CipherKey[oInstance.CipherKey.Length - 1] ^= 1;
        oItem.Cipher.ProtectedKey = new byte[] { 1, 0, 0, 0, 2, 0, 0, 0, 255, 255, 255, 127 };
        Reject(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
            "Recovery rejects oversized descriptor lengths");
        oItem.Cipher.ProtectedKey = oEnvelope.Take(8).ToArray();
        Reject(() => ItemCryptography.Decrypt(oItem), "Recovery rejects truncated envelopes");
        oItem.Cipher.ProtectedKey = oEnvelope.Concat(new byte[] { 0 }).ToArray();
        Reject(() => ItemCryptography.Decrypt(oItem), "Recovery rejects trailing envelope data");
        oItem.Cipher.ProtectedKey = oEnvelope;
    }
}
