using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using Crypture;

internal static partial class RegressionTests
{
    private static void SetRecoveryConfig(string sDescriptor, string sCertificate)
    {
        string sPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        string sConfig = File.ReadAllText(sPath);
        string sSection = "<appSettings><add key=\"RecoveryProtectionDescriptor\" value=\"" +
            SecurityElement.Escape(sDescriptor ?? "") + "\"/><add key=\"RecoveryCertificateBase64\" value=\"" +
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
                oCertificateItem = DatabaseOperations.LoadItem(oContext.Items.Single().ItemId);

            // Existing items report missing coverage until the user can unlock and save them.
            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, null);
            VaultHealthReport oReport = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(oReport.Findings.Any(f => f.Kind == "Emergency Recovery" && f.Severity == HealthStatus.Warning),
                "Health check reports old items that lack the configured recovery access");
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = DatabaseOperations.LoadItem(oCertificateItem.ItemId);
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

            DatabaseOperations.SaveItem(new Item { Label = "Windows Item", ItemType = "text" },
                oPlain, null, PrincipalProtection.LocalMachineDescriptor);
            Item oWindowsItem;
            using (CryptureEntities oContext = new CryptureEntities())
                oWindowsItem = DatabaseOperations.LoadItem(
                    oContext.Items.Single(i => i.Label == "Windows Item").ItemId);
            Check(RecoveryProtection.ReadWindowsKeys(oWindowsItem.Cipher).Count == 2 &&
                ItemCryptography.Decrypt(oWindowsItem).SequenceEqual(oPlain),
                "Windows recovery is independent of the original Windows scope");

            // A public recovery certificate is enforced even when the caller supplies no certificate recipients.
            SetRecoveryConfig(null, sCertificate);
            DatabaseOperations.SaveItem(oWindowsItem, oPlain, null, PrincipalProtection.LocalMachineDescriptor);
            oWindowsItem = DatabaseOperations.LoadItem(oWindowsItem.ItemId);
            Check(oWindowsItem.Instances.Count == 1 && ItemCryptography.Decrypt(oWindowsItem,
                oWindowsItem.Instances.Single(), oRecoveryCert).SequenceEqual(oPlain),
                "Configured recovery certificate decrypts a Windows item independently");
            Check(ItemCryptography.Decrypt(oWindowsItem).SequenceEqual(oPlain),
                "Original Windows access remains usable with certificate recovery");
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = DatabaseOperations.LoadItem(oCertificateItem.ItemId);
            Instance oRecoveryInstance = oCertificateItem.Instances.Single(i => i.UserId != oPrimary.UserId);
            Check(oCertificateItem.Instances.Count == 2 &&
                ItemCryptography.Decrypt(oCertificateItem, oRecoveryInstance, oRecoveryCert).SequenceEqual(oPlain),
                "Configured recovery certificate also decrypts certificate items");
            Reject(() => DatabaseOperations.RemoveCertificate(oRecoveryInstance.UserId),
                "Configured recovery certificate cannot be removed from the Vault");

            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, sCertificate);
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = DatabaseOperations.LoadItem(oCertificateItem.ItemId);
            Check(ItemCryptography.Decrypt(oCertificateItem).SequenceEqual(oPlain) &&
                ItemCryptography.Decrypt(oCertificateItem,
                    oCertificateItem.Instances.Single(i => i.UserId != oPrimary.UserId),
                        oRecoveryCert).SequenceEqual(oPlain),
                "Both recovery settings grant independent access to a certificate item");
            DatabaseOperations.SaveItem(oWindowsItem, oPlain, null, PrincipalProtection.LocalMachineDescriptor);
            oWindowsItem = DatabaseOperations.LoadItem(oWindowsItem.ItemId);
            Check(RecoveryProtection.ReadWindowsKeys(oWindowsItem.Cipher).Count == 2 &&
                oWindowsItem.Instances.Count == 1 && ItemCryptography.Decrypt(oWindowsItem,
                oWindowsItem.Instances.Single(), oRecoveryCert).SequenceEqual(oPlain),
                "Both recovery settings grant independent access to a Windows item");
            DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
            oCertificateItem = DatabaseOperations.LoadItem(oCertificateItem.ItemId);
            using (CryptureEntities oContext = new CryptureEntities())
                Check(oContext.Users.Count() == 2 && oCertificateItem.Instances.Count == 2,
                    "Repeated saves deduplicate the automatic recovery certificate");
            TestRecoveryTampering(oCertificateItem, oPrimaryCert);

            string sBackup = Path.Combine(sDirectory, "recovery-backup.cryptdb");
            DatabaseOperations.BackupDatabase(sPath, sBackup);
            SetRecoveryConfig(null, null);
            CryptureEntities.DatabasePath = sBackup;
            Item oBackup = DatabaseOperations.LoadItem(oCertificateItem.ItemId);
            Check(ItemCryptography.Decrypt(oBackup).SequenceEqual(oPlain),
                "Vault backups retain recovery access after the adjacent configuration is removed");
            CryptureEntities.DatabasePath = sPath;
            Check(ItemCryptography.Decrypt(DatabaseOperations.LoadItem(oWindowsItem.ItemId),
                oWindowsItem.Instances.Single(), oRecoveryCert).SequenceEqual(oPlain),
                "Recovery certificate access is stored in the Vault, independent of current configuration");

            // Bad policies and unavailable providers fail without modifying an existing item or its recipients.
            foreach (string sInvalid in new[] { "not base64", Convert.ToBase64String(new byte[] { 1, 2, 3 }) })
            {
                SetRecoveryConfig(null, sInvalid);
                Reject(() => DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary }),
                    "Invalid recovery certificate blocks saving");
                Item oUnchanged = DatabaseOperations.LoadItem(oCertificateItem.ItemId);
                Check(oUnchanged.ModifiedDate == oCertificateItem.ModifiedDate &&
                    oUnchanged.Cipher.CipherText.SequenceEqual(oCertificateItem.Cipher.CipherText) &&
                    oUnchanged.Cipher.ProtectedKey.SequenceEqual(oCertificateItem.Cipher.ProtectedKey) &&
                    oUnchanged.Instances.Count == oCertificateItem.Instances.Count,
                    "Rejected recovery config preserves the saved item and recipients");
            }
            SetRecoveryConfig("LOCAL=not-a-scope", null);
            Reject(() => DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary }),
                "Invalid Windows recovery rule blocks saving without a fallback scope");
            Check(ItemCryptography.Decrypt(DatabaseOperations.LoadItem(oCertificateItem.ItemId)).SequenceEqual(oPlain),
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
            oCertificateItem = DatabaseOperations.LoadItem(oCertificateItem.ItemId);
            Check(oCertificateItem.Instances.Count == 1,
                "Recovery certificate matching a primary recipient is not duplicated");

            // Exercise real group authorization when the opt-in domain test environment is available.
            string sDomainSids = Environment.GetEnvironmentVariable("CRYPTURE_TEST_DOMAIN_SIDS");
            if (PrincipalProtection.IsDomainJoined && !String.IsNullOrWhiteSpace(sDomainSids))
            {
                string sDomainPolicy = PrincipalProtection.CreateDescriptor(
                    sDomainSids.Split(';').Select(ProtectionPrincipal.Resolve), false);
                SetRecoveryConfig(sDomainPolicy, sCertificate);
                DatabaseOperations.SaveItem(oCertificateItem, oPlain, new[] { oPrimary });
                oCertificateItem = DatabaseOperations.LoadItem(oCertificateItem.ItemId);
                Check(ItemCryptography.Decrypt(oCertificateItem).SequenceEqual(oPlain),
                    "Domain recovery principals decrypt a certificate item without any certificate private key");
                DatabaseOperations.SaveItem(oWindowsItem, oPlain, new[] { oPrimary },
                    PrincipalProtection.LocalMachineDescriptor);
                oWindowsItem = DatabaseOperations.LoadItem(oWindowsItem.ItemId);
                var oEnvelopes = RecoveryProtection.ReadWindowsKeys(oWindowsItem.Cipher);
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

    private static void TestRecoveryEditor(string sDirectory)
    {
        string sConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginalConfig = File.ReadAllBytes(sConfigPath);
        string sConnection = CryptureEntities.ConnectionString;
        try
        {
            CryptureEntities.DatabasePath = Path.Combine(sDirectory, "recovery.cryptdb");
            Item oItem;
            using (CryptureEntities oContext = new CryptureEntities())
                oItem = DatabaseOperations.LoadItem(oContext.Items.Single(i => i.Label == "Certificate Item").ItemId);
            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, null);
            ItemEditor oEditor = new ItemEditor(oItem);
            Check(((ComboBox)oEditor.FindName("oProtectionMode")).SelectedIndex == 1 &&
                ((TextBlock)oEditor.FindName("oRecoveryNotice")).Visibility == Visibility.Visible,
                "Certificate editor displays independent Windows emergency recovery");
            typeof(ItemEditor).GetMethod("oLoadItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oEditor, new object[] { null, null });
            PumpUntil(() => !(bool)typeof(ItemEditor).GetField("bBusy", BindingFlags.Instance | BindingFlags.NonPublic)
                .GetValue(oEditor));
            Check(((TextBox)oEditor.FindName("oItemData")).Text.Contains("Emergency recovery works") &&
                ((ComboBox)oEditor.FindName("oProtectionMode")).SelectedIndex == 1,
                "Certificate item decrypts automatically through Windows recovery while keeping its primary mode");
            RenderWindow(oEditor, "editor-emergency-recovery.png");
            oEditor.Close();
            SetRecoveryConfig(null, "invalid base64");
            oEditor = new ItemEditor(oItem);
            Check(((TextBlock)oEditor.FindName("oRecoveryNotice")).Text.Contains("invalid"),
                "Invalid configuration is shown without blocking access to existing items");
            oEditor.Close();
        }
        finally
        {
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            CryptureEntities.ConnectionString = sConnection;
        }
    }
}
