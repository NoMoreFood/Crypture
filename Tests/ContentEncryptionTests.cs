using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using Crypture;

internal static partial class RegressionTests
{
    private static void SetContentEncryptionConfig(string sSuite)
    {
        string sPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        XDocument oConfig = XDocument.Load(sPath, LoadOptions.PreserveWhitespace);
        XElement oSettings = oConfig.Root.Element("appSettings");
        oSettings.Elements("add").Where(e => (string)e.Attribute("key") == "ContentEncryptionSuite").Remove();
        if (sSuite != null)
            oSettings.Add(new XElement("add", new XAttribute("key", "ContentEncryptionSuite"),
                new XAttribute("value", sSuite)));
        oConfig.Save(sPath, SaveOptions.DisableFormatting);
    }

    private static void TestContentEncryptionSuites(string sDirectory, X509Certificate2 oCert,
        X509Certificate2 oOtherCert)
    {
        string sConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginalConfig = File.ReadAllBytes(sConfigPath);
        string sPreviousConnection = CryptureEntities.ConnectionString;
        bool bSelfSigned = Crypture.Properties.Settings.Default.AllowSelfSignedCertificates;
        bool bRevocation = Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck;
        string sPath = Path.Combine(sDirectory, "content-suites.cryptdb");
        byte[] oPlain = Encoding.Unicode.GetBytes("Content suite and recipient policy are independent. \u2603");
        try
        {
            // Exercise the actual save boundary and adjacent configuration using a mixed-suite Vault.
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = true;
            Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = false;
            SetRecoveryConfig(null, null);
            DatabaseOperations.CreateDatabase(sPath,
                File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
            CryptureEntities.DatabasePath = sPath;
            User oUser = new User { Certificate = oCert.RawData };
            User oOtherUser = new User { Certificate = oOtherCert.RawData };
            using (CryptureEntities oContext = new CryptureEntities())
            {
                oContext.Users.AddRange(oUser, oOtherUser);
                oContext.SaveChanges();
            }
            User[] oUsers = { oUser, oOtherUser };
            List<long> oIds = new List<long>();
            foreach (ContentEncryptionSuite nSuite in Enum.GetValues<ContentEncryptionSuite>())
            {
                foreach (string sScope in new[] { null, PrincipalProtection.LocalUserDescriptor,
                    PrincipalProtection.LocalMachineDescriptor })
                foreach (bool bRecovery in new[] { false, true })
                {
                    SetRecoveryConfig(bRecovery ? PrincipalProtection.LocalUserDescriptor : null,
                        bRecovery ? Convert.ToBase64String(oOtherCert.RawData) : null);
                    SetContentEncryptionConfig(nSuite.ToString());
                    string sLabel = nSuite + " / " + sScope + " / " + bRecovery;
                    DatabaseOperations.SaveItem(new Item { Label = sLabel, ItemType = "text" },
                        oPlain, sScope == null ? oUsers : null, sScope);
                    long nId;
                    using (CryptureEntities oContext = new CryptureEntities())
                        nId = oContext.Items.Single(i => i.Label == sLabel).ItemId;
                    oIds.Add(nId);
                    Item oStored = DatabaseOperations.LoadItem(nId);
                    Check(oStored.Cipher.ContentSuite == (long)nSuite &&
                        oStored.Cipher.CipherVector.Length == (nSuite == ContentEncryptionSuite.Aes256Gcm ? 12 : 16) &&
                        (nSuite == ContentEncryptionSuite.Aes256Gcm ? oStored.Cipher.AuthenticationTag?.Length == 16
                            : oStored.Cipher.AuthenticationTag == null),
                        sLabel + " persists the suite, nonce, and content tag");

                    // Reads use the saved suite even when the deployment setting is unusable for new saves.
                    SetContentEncryptionConfig("UnknownSuite");
                    if (sScope != null || bRecovery)
                        Check(ItemCryptography.Decrypt(oStored).SequenceEqual(oPlain), sLabel + " Windows access");
                    foreach (Instance oInstance in oStored.Instances)
                        Check(ItemCryptography.Decrypt(oStored, oInstance,
                            oInstance.UserId == oUser.UserId ? oCert : oOtherCert).SequenceEqual(oPlain),
                            sLabel + " certificate access for recipient " + oInstance.UserId);
                    if (bRecovery) TestRecoveryTampering(oStored, oOtherCert);
                }

                // Empty and unaligned payloads exercise GCM lengths and CBC padding through native providers.
                foreach (int nLength in new[] { 0, 1, 15, 16, 17, 8193 })
                {
                    byte[] oInput = Enumerable.Range(0, nLength).Select(i => (byte)i).ToArray();
                    foreach (bool bWindows in new[] { false, true })
                    {
                        Item oItem = new Item { Label = "Boundary payload", ItemType = "text" };
                        ItemCryptography.Encrypt(oItem, oInput, bWindows ? null : oUsers,
                            bWindows ? PrincipalProtection.LocalUserDescriptor : null, nContentSuite: nSuite);
                        byte[] oResult = bWindows ? ItemCryptography.Decrypt(oItem) :
                            ItemCryptography.Decrypt(oItem, oItem.Instances.First(), oCert);
                        Check(oResult.SequenceEqual(oInput), nSuite + " " + nLength + " bytes, Windows=" + bWindows);
                    }
                }
                TestContentSuiteTampering(nSuite, oUsers, oCert, oOtherCert);

                // The maximum permitted plaintext remains readable for either content suite.
                byte[] oMaximum = new byte[Utilities.MaxItemSize];
                oMaximum[0] = 1;
                oMaximum[^1] = 255;
                Item oLimitItem = new Item { Label = "Size limit", ItemType = "text" };
                ItemCryptography.Encrypt(oLimitItem, oMaximum, null,
                    PrincipalProtection.LocalUserDescriptor, nContentSuite: nSuite);
                Check(ItemCryptography.Decrypt(oLimitItem).SequenceEqual(oMaximum),
                    nSuite + " maximum-size round trip");
                Reject(() => ItemCryptography.Encrypt(oLimitItem, new byte[Utilities.MaxItemSize + 1], null,
                    PrincipalProtection.LocalUserDescriptor, nContentSuite: nSuite),
                    nSuite + " rejects plaintext over the size limit");
            }

            // Invalid configuration must not change an existing item or insert a new one.
            Item oExisting = DatabaseOperations.LoadItem(oIds[0]);
            byte[] oBefore = File.ReadAllBytes(sPath);
            foreach (string sBadSuite in new[] { "", "UnknownSuite", "1", "-1", "Aes256Gcm,Aes256CbcHmacSha256" })
            {
                SetContentEncryptionConfig(sBadSuite);
                Reject(() => DatabaseOperations.SaveItem(oExisting, oPlain, oUsers),
                    "Invalid content suite rejects updates: " + sBadSuite);
                Reject(() => DatabaseOperations.SaveItem(new Item { Label = "Rejected", ItemType = "text" },
                    oPlain, oUsers), "Invalid content suite rejects inserts: " + sBadSuite);
                Check(File.ReadAllBytes(sPath).SequenceEqual(oBefore), "Rejected suite preserves the complete Vault");
            }

            // A missing setting defaults to GCM, and an explicit setting applies when an item is next saved.
            SetRecoveryConfig(null, null);
            SetContentEncryptionConfig(null);
            DatabaseOperations.SaveItem(oExisting, oPlain, oUsers);
            oExisting = DatabaseOperations.LoadItem(oExisting.ItemId);
            Check(oExisting.Cipher.ContentSuite == (long)ContentEncryptionSuite.Aes256Gcm &&
                ItemCryptography.Decrypt(oExisting, oExisting.Instances.First(), oCert).SequenceEqual(oPlain),
                "Missing suite setting saves with AES-256-GCM");
            SetContentEncryptionConfig(nameof(ContentEncryptionSuite.Aes256CbcHmacSha256));
            DatabaseOperations.SaveItem(oExisting, oPlain, oUsers);
            oExisting = DatabaseOperations.LoadItem(oExisting.ItemId);
            Check(oExisting.Cipher.ContentSuite == (long)ContentEncryptionSuite.Aes256CbcHmacSha256 &&
                oExisting.Cipher.AuthenticationTag == null &&
                ItemCryptography.Decrypt(oExisting, oExisting.Instances.First(), oCert).SequenceEqual(oPlain),
                "Changing the configured suite rewrites the selected item on save");
            SetContentEncryptionConfig(nameof(ContentEncryptionSuite.Aes256Gcm));
            DatabaseOperations.SaveItem(oExisting, oPlain, oUsers);
            oExisting = DatabaseOperations.LoadItem(oExisting.ItemId);

            // Configuration removal also leaves a mixed-suite backup independently readable.
            string sBackupPath = Path.Combine(sDirectory, "content-suites-backup.cryptdb");
            DatabaseOperations.BackupDatabase(sPath, sBackupPath);
            File.Delete(sConfigPath);
            CryptureEntities.DatabasePath = sBackupPath;
            foreach (long nId in oIds)
            {
                Item oStored = DatabaseOperations.LoadItem(nId);
                byte[] oResult = ItemCryptography.UsesWindowsProtection(oStored.Cipher)
                    ? ItemCryptography.Decrypt(oStored)
                    : ItemCryptography.Decrypt(oStored, oStored.Instances.First(i => i.UserId == oUser.UserId), oCert);
                Check(oResult.SequenceEqual(oPlain),
                    "Mixed-suite backup reads without configuration: " + oStored.Label);
            }
            CryptureEntities.DatabasePath = sPath;
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            SetRecoveryConfig(null, null);
            SetContentEncryptionConfig(nameof(ContentEncryptionSuite.Aes256Gcm));

            // Concurrent changes to suite metadata or the GCM tag must not be overwritten by a stale editor.
            using (CryptureEntities oContext = new CryptureEntities())
                oContext.Database.ExecuteSqlRaw("UPDATE Cipher SET ContentSuite = 99 WHERE ItemId = {0}",
                    oExisting.ItemId);
            Reject(() => DatabaseOperations.SaveItem(oExisting, oPlain, oUsers), "Reject concurrent suite changes");
            Item oUnsupported = DatabaseOperations.LoadItem(oExisting.ItemId);
            Check(oUnsupported.Cipher.ContentSuite == 99, "Rejected stale save preserves the competing suite change");
            RejectCryptography(() => ItemCryptography.Decrypt(oUnsupported, oUnsupported.Instances.First(), oCert),
                "Reject unsupported suites loaded from the Vault");
            VaultHealthReport oReport = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(oReport.Findings.Any(f => f.Recipient == oExisting.Label && f.Severity == HealthStatus.Error &&
                f.Details.Contains("content encryption suite")), "Health check identifies unsupported content suites");
            using (CryptureEntities oContext = new CryptureEntities())
                oContext.Database.ExecuteSqlRaw(
                    "UPDATE Cipher SET ContentSuite = {0}, AuthenticationTag = zeroblob(16) WHERE ItemId = {1}",
                    (long)ContentEncryptionSuite.Aes256Gcm, oExisting.ItemId);
            Reject(() => DatabaseOperations.SaveItem(oExisting, oPlain, oUsers), "Reject concurrent GCM tag changes");
            using (CryptureEntities oContext = new CryptureEntities())
                oContext.Database.ExecuteSqlRaw("UPDATE Cipher SET AuthenticationTag = {0} WHERE ItemId = {1}",
                    oExisting.Cipher.AuthenticationTag, oExisting.ItemId);
            oReport = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(!oReport.Findings.Any(f => f.Severity == HealthStatus.Error),
                "Health check accepts both supported content suites in one Vault");
        }
        finally
        {
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            CryptureEntities.ConnectionString = sPreviousConnection;
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = bSelfSigned;
            Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = bRevocation;
        }
    }

    private static void TestContentSuiteTampering(ContentEncryptionSuite nSuite, User[] oUsers,
        X509Certificate2 oCert, X509Certificate2 oOtherCert)
    {
        byte[] oPlain = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        Item oItem = new Item { Label = "Authenticated content", ItemType = "text" };
        ItemCryptography.Encrypt(oItem, oPlain, oUsers, PrincipalProtection.LocalUserDescriptor,
            PrincipalProtection.LocalMachineDescriptor, nSuite);
        Cipher oCipher = oItem.Cipher;
        Instance oFirst = oItem.Instances.First();
        Instance oSecond = oItem.Instances.Last();
        Func<byte[]>[] oReaders =
        {
            () => ItemCryptography.Decrypt(oItem),
            () => ItemCryptography.Decrypt(oItem, oFirst, oCert),
            () => ItemCryptography.Decrypt(oItem, oSecond, oOtherCert)
        };
        void Tamper(Action oChange, Action oRestore, string sName)
        {
            try
            {
                oChange();
                foreach (Func<byte[]> oRead in oReaders)
                    RejectCryptography(() => oRead(), nSuite + " rejects " + sName);
            }
            finally
            {
                oRestore();
            }
        }

        // Every access path must authenticate the same content and access policy.
        Tamper(() => oCipher.CipherText[0] ^= 1, () => oCipher.CipherText[0] ^= 1, "altered ciphertext");
        Tamper(() => oCipher.CipherVector[0] ^= 1, () => oCipher.CipherVector[0] ^= 1, "altered nonce");
        Tamper(() => oItem.Label += "!", () => oItem.Label = "Authenticated content", "altered label");
        Tamper(() => oItem.ItemType = ".bin", () => oItem.ItemType = "text", "altered item type");
        Tamper(() => oCipher.ContentSuite = 99, () => oCipher.ContentSuite = (long)nSuite, "unknown suite");
        Tamper(() => oCipher.ContentSuite = null, () => oCipher.ContentSuite = (long)nSuite, "removed suite");
        Tamper(() => oCipher.ProtectedKey[^1] ^= 1, () => oCipher.ProtectedKey[^1] ^= 1, "altered recovery envelope");
        Tamper(() => oCipher.ProtectionDescriptor = PrincipalProtection.LocalMachineDescriptor,
            () => oCipher.ProtectionDescriptor = PrincipalProtection.LocalUserDescriptor, "altered Windows scope");

        byte[] oNonce = oCipher.CipherVector;
        byte[] oTag = oCipher.AuthenticationTag;
        foreach (byte[] oBadNonce in new[] { null, Array.Empty<byte>(), new byte[oNonce.Length - 1],
            new byte[oNonce.Length + 1] })
            Tamper(() => oCipher.CipherVector = oBadNonce, () => oCipher.CipherVector = oNonce, "malformed nonce");
        if (nSuite == ContentEncryptionSuite.Aes256Gcm)
        {
            Tamper(() => oTag[0] ^= 1, () => oTag[0] ^= 1, "altered GCM tag");
            foreach (byte[] oBadTag in new[] { null, Array.Empty<byte>(), new byte[15], new byte[17] })
                Tamper(() => oCipher.AuthenticationTag = oBadTag, () => oCipher.AuthenticationTag = oTag,
                    "malformed GCM tag");
        }
        else
            Tamper(() => oCipher.AuthenticationTag = new byte[16], () => oCipher.AuthenticationTag = null,
                "unexpected GCM tag on CBC content");

        // Even plausible lengths cannot turn a record into another authenticated suite.
        bool bGcm = nSuite == ContentEncryptionSuite.Aes256Gcm;
        Tamper(() =>
        {
            oCipher.ContentSuite = (long)(bGcm
                ? ContentEncryptionSuite.Aes256CbcHmacSha256 : ContentEncryptionSuite.Aes256Gcm);
            oCipher.CipherVector = new byte[bGcm ? 16 : 12];
            oCipher.AuthenticationTag = bGcm ? null : new byte[16];
        }, () =>
        {
            oCipher.ContentSuite = (long)nSuite;
            oCipher.CipherVector = oNonce;
            oCipher.AuthenticationTag = oTag;
        }, "suite substitution with plausible lengths");

        // Saving again must rotate both keys and the nonce, regardless of how many recipients share the item.
        foreach (Func<byte[]> oRead in oReaders)
            Check(oRead().SequenceEqual(oPlain), nSuite + " remains readable after restoring tampered metadata");
        byte[] oKeys = CertificateKeyProtection.Unwrap(oCert, oFirst.CipherKey);
        byte[] oNewKeys = null;
        try
        {
            ItemCryptography.Encrypt(oItem, oPlain, oUsers, PrincipalProtection.LocalUserDescriptor,
                PrincipalProtection.LocalMachineDescriptor, nSuite);
            oNewKeys = CertificateKeyProtection.Unwrap(oCert, oItem.Instances.First().CipherKey);
            Check(!oKeys.AsSpan(0, 32).SequenceEqual(oNewKeys.AsSpan(0, 32)) &&
                !oKeys.AsSpan(32, 32).SequenceEqual(oNewKeys.AsSpan(32, 32)) &&
                !oNonce.SequenceEqual(oItem.Cipher.CipherVector), nSuite + " generates fresh content keys and nonce");
        }
        finally
        {
            Array.Clear(oKeys);
            if (oNewKeys != null) Array.Clear(oNewKeys);
        }
    }
}
