using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Crypture;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

internal static partial class RegressionTests
{
    private static void TestSqlServerBackend(string sDirectory, X509Certificate2 oCert,
        X509Certificate2 oOtherCert)
    {
        TestSqlServerDirectoryBinding();
        string sServerConnection = Environment.GetEnvironmentVariable("CRYPTURE_TEST_SQLSERVER");
        if (String.IsNullOrWhiteSpace(sServerConnection)) return;
        string sDatabase = "CryptureTest_" + Guid.NewGuid().ToString("N");
        SqlConnectionStringBuilder oBuilder = new SqlConnectionStringBuilder(sServerConnection)
        {
            InitialCatalog = sDatabase, Pooling = false
        };
        IVaultStorage oPreviousStorage = CryptureEntities.Storage;
        SqlServerVaultStorage oStorage = new SqlServerVaultStorage(oBuilder.ConnectionString);
        string sBackup = Path.Combine(sDirectory, sDatabase + ".bak");
        bool bOriginalSelfSigned = Crypture.Properties.Settings.Default.AllowSelfSignedCertificates;
        try
        {
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = true;
            TestSqlServerCertificateCreation(sServerConnection, oOtherCert, oCert);
            string sCurrentSid = WindowsIdentity.GetCurrent().User.Value;
            SqlConnectionStringBuilder oLogin = new SqlConnectionStringBuilder(oBuilder.ConnectionString)
            {
                IntegratedSecurity = false, UserID = "crypture-test", Password = "transient-secret"
            };
            Reject(() => new SqlServerVaultStorage(oLogin.ConnectionString),
                "SQL Server Vaults reject password authentication");

            // Exercise the same encrypted item and recipient operations used by the desktop editor.
            Reject(() => oStorage.Create(), "SQL Server creation requires an escrow identity");
            oStorage.EscrowChoice = SqlServerEscrowChoice.ForPrincipal(sCurrentSid,
                "Windows: " + sCurrentSid);
            oStorage.Create();
            oStorage.Validate();
            Reject(() => oStorage.Create(), "SQL Server refuses to overwrite an existing Vault");
            CryptureEntities.Storage = oStorage;
            Check(oStorage.Escrow?.Descriptor == "SID=" + sCurrentSid,
                "SQL Server creation saves the selected Windows escrow identity");
            User[] oUsers = { new User { Certificate = oCert.RawData, Sid = sCurrentSid },
                new User { Certificate = oOtherCert.RawData, Sid = sCurrentSid } };
            foreach (User oUser in oUsers)
                oUser.UserId = EnrollTestCertificate(oStorage, oUser.Certificate, oUser.Sid);
            using (CryptureEntities oContext = new CryptureEntities())
            {
                Check(oContext.Users.Count() == 2, "SQL Server saves recipient certificates");
            }
            TestSqlServerEscrow(oStorage, oUsers[0]);
            byte[] oPlainText = Encoding.UTF8.GetBytes("SQL Server encrypted item round trip");
            DatabaseOperations.SaveItem(new Item { Label = "SQL Server item", ItemType = "text",
                ModifiedBy = oUsers[0].UserId }, oPlainText, oUsers);
            long nItemId;
            using (CryptureEntities oContext = new CryptureEntities())
                nItemId = oContext.Items.Single(i => i.Label == "SQL Server item").ItemId;
            Item oLoaded = DatabaseOperations.LoadItem(nItemId);
            Check(oLoaded.RowVersion?.Length == 8 && oLoaded.Instances.Count == 2 &&
                ItemCryptography.Decrypt(oLoaded, oLoaded.Instances.First(i => i.UserId == oUsers[0].UserId),
                    oCert).SequenceEqual(oPlainText), "SQL Server loads and decrypts item with recipients");
            TestSqlServerRecipientSecurity(oStorage, nItemId, sCurrentSid, oUsers[1].UserId);
            Item oStale = DatabaseOperations.LoadItem(nItemId);
            DatabaseOperations.SaveItem(oLoaded, Encoding.UTF8.GetBytes("second revision"), oUsers);
            Reject(() => DatabaseOperations.SaveItem(oStale, oPlainText, oUsers),
                "SQL Server rejects a stale item edit");
            Item[] oCompeting = { DatabaseOperations.LoadItem(nItemId), DatabaseOperations.LoadItem(nItemId) };
            using ManualResetEventSlim oStart = new ManualResetEventSlim();
            Task<Exception>[] oSaves = oCompeting.Select((oItem, nIndex) => Task.Run(() =>
            {
                oStart.Wait();
                try
                {
                    DatabaseOperations.SaveItem(oItem, Encoding.UTF8.GetBytes("competing " + nIndex), oUsers);
                    return null;
                }
                catch (Exception oError) { return oError; }
            })).ToArray();
            oStart.Set();
            Task.WaitAll(oSaves);
            Check(oSaves.Count(t => t.Result == null) == 1 &&
                oSaves.Count(t => t.Result != null) == 1,
                "Competing SQL Server saves commit one item revision");
            Check(oSaves.Single(t => t.Result != null).Result is InvalidOperationException oConflict &&
                oConflict.Message.StartsWith("This item changed", StringComparison.Ordinal),
                "A competing SQL Server edit reports a readable conflict");
            DatabaseOperations.SavePasswordOptions(new PasswordOptions { MinimumLength = 26,
                MaximumLength = 32 });
            Check(DatabaseOperations.LoadPasswordOptions().MinimumLength == 26,
                "SQL Server retains password generator settings");
            VaultHealthReport oReport = VaultHealthCheck.Run(oStorage, false, false, CancellationToken.None);
            Check(oReport.ItemCount == 1, "SQL Server health check reads the Vault");
            Reject(() => DatabaseOperations.RemoveCertificate(oUsers[1].UserId),
                "SQL Server blocks removal of a certificate still used by an item");
            DatabaseOperations.SaveItem(DatabaseOperations.LoadItem(nItemId),
                Encoding.UTF8.GetBytes("remaining recipient"), new[] { oUsers[0] });
            DatabaseOperations.RemoveCertificate(oUsers[1].UserId);
            Check(DatabaseOperations.LoadItem(nItemId).Instances.Count == 1,
                "SQL Server removes an alternate certificate recipient");
            Reject(() => DatabaseOperations.RemoveCertificate(oUsers[0].UserId),
                "SQL Server blocks deletion of the last recipient");
            oStorage.Backup(sBackup);
            Check(File.Exists(sBackup) && new FileInfo(sBackup).Length > 0,
                "SQL Server creates a server-side backup");
            DatabaseOperations.DeleteItem(nItemId);
            using (CryptureEntities oContext = new CryptureEntities())
                Check(!oContext.Ciphers.Any() && !oContext.Instances.Any(),
                    "SQL Server cascades item deletion to encrypted records");
            TestSqlServerUpgrade(oStorage, oUsers[0]);
        }
        finally
        {
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = bOriginalSelfSigned;
            CryptureEntities.Storage = oPreviousStorage;
            SqlConnectionStringBuilder oMaster = new SqlConnectionStringBuilder(oBuilder.ConnectionString)
            {
                InitialCatalog = "master"
            };
            using (SqlConnection oConnection = new SqlConnection(oMaster.ConnectionString))
            {
                oConnection.Open();
                using SqlCommand oCommand = new SqlCommand("IF DB_ID(@name) IS NOT NULL BEGIN " +
                    "ALTER DATABASE [" + sDatabase + "] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; " +
                    "DROP DATABASE [" + sDatabase + "]; END", oConnection);
                oCommand.Parameters.AddWithValue("@name", sDatabase);
                oCommand.ExecuteNonQuery();
            }
            if (File.Exists(sBackup)) File.Delete(sBackup);
        }
    }

    private static void TestSqlServerCertificateCreation(string sServerConnection,
        X509Certificate2 oEscrowCertificate, X509Certificate2 oPrimaryCertificate)
    {
        string sDatabase = "CryptureEscrowTest_" + Guid.NewGuid().ToString("N");
        SqlConnectionStringBuilder oBuilder = new SqlConnectionStringBuilder(sServerConnection)
        {
            InitialCatalog = sDatabase, Pooling = false
        };
        IVaultStorage oPreviousStorage = CryptureEntities.Storage;
        SqlServerVaultStorage oStorage = new SqlServerVaultStorage(oBuilder.ConnectionString)
        {
            EscrowChoice = SqlServerEscrowChoice.ForCertificate(oEscrowCertificate.RawData,
                "S-1-5-21-1-2-3-5555", "Certificate: Independent escrow")
        };
        try
        {
            oStorage.Create();
            oStorage.Validate();
            CryptureEntities.Storage = oStorage;
            Check(oStorage.Escrow.CertificateUserId.HasValue && oStorage.Escrow.Descriptor == null,
                "SQL Server creation enrolls and designates the selected escrow certificate");
            long nPrimaryId = EnrollTestCertificate(oStorage, oPrimaryCertificate.RawData,
                WindowsIdentity.GetCurrent().User.Value);
            User oPrimary = new User { UserId = nPrimaryId, Certificate = oPrimaryCertificate.RawData,
                Sid = WindowsIdentity.GetCurrent().User.Value };
            byte[] oSecret = Encoding.UTF8.GetBytes("Independent certificate escrow");
            Item oItem = new Item { Label = "Independent escrow", ItemType = "text", ModifiedBy = nPrimaryId };
            DatabaseOperations.SaveItem(oItem, oSecret, new[] { oPrimary });
            Item oStored = DatabaseOperations.LoadItem(oItem.ItemId);
            Check(oStored.Instances.Count == 2 && oStored.ProtectionDisplay.Contains("Independent escrow") &&
                ItemCryptography.Decrypt(oStored, oStored.Instances.Single(i =>
                    i.UserId == oStorage.Escrow.CertificateUserId), oEscrowCertificate).SequenceEqual(oSecret),
                "A distinct selected escrow certificate decrypts the saved item");
        }
        finally
        {
            CryptureEntities.Storage = oPreviousStorage;
            SqlConnectionStringBuilder oMaster = new SqlConnectionStringBuilder(oBuilder.ConnectionString)
            {
                InitialCatalog = "master"
            };
            using SqlConnection oConnection = new SqlConnection(oMaster.ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand("IF DB_ID(@name) IS NOT NULL BEGIN " +
                "ALTER DATABASE [" + sDatabase + "] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; " +
                "DROP DATABASE [" + sDatabase + "]; END", oConnection);
            oCommand.Parameters.AddWithValue("@name", sDatabase);
            oCommand.ExecuteNonQuery();
        }
    }

    private static void TestSqlServerDirectoryBinding()
    {
        bool bSelfSigned = Crypture.Properties.Settings.Default.AllowSelfSignedCertificates;
        bool bRevocation = Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck;
        using RSA oKey = new RSACng(2048);
        CertificateRequest oRequest = new CertificateRequest("CN=Alice", oKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        oRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
        SubjectAlternativeNameBuilder oNames = new SubjectAlternativeNameBuilder();
        oNames.AddUserPrincipalName("alice@example.test");
        oRequest.CertificateExtensions.Add(oNames.Build());
        using X509Certificate2 oCert = oRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1));
        string sSid = "S-1-5-21-1-2-3-1000";
        DirectoryAccount oAccount = new DirectoryAccount("Alice", "alice@example.test", "User",
            "example.test", sSid, "CN=Alice", [oCert.RawData]);
        DirectorySearchResult oResult = new DirectorySearchResult("example.test", [oAccount], false);
        try
        {
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = true;
            Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = false;
            SqlServerCertificateEnrollment.VerifyDirectoryBinding(oCert.RawData, sSid, oResult);
            Check(true, "SQL Server enrollment accepts the AD certificate, SID, and UPN together");
            Reject(() => SqlServerCertificateEnrollment.VerifyDirectoryBinding(oCert.RawData,
                "S-1-5-21-1-2-3-1001", oResult),
                "SQL Server enrollment rejects a certificate bound to another SID");
            DirectoryAccount oWrongUpn = oAccount with { Account = "bob@example.test" };
            Reject(() => SqlServerCertificateEnrollment.VerifyDirectoryBinding(oCert.RawData, sSid,
                oResult with { Accounts = [oWrongUpn] }),
                "SQL Server enrollment rejects a certificate whose UPN differs from the AD account");
            Reject(() => SqlServerCertificateEnrollment.VerifyDirectoryBinding([1, 2, 3], sSid, oResult),
                "SQL Server enrollment rejects a certificate absent from the AD account");
        }
        finally
        {
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = bSelfSigned;
            Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = bRevocation;
        }
    }

    private static long EnrollTestCertificate(SqlServerVaultStorage oStorage, byte[] oCertificate, string sSid)
    {
        using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
        oConnection.Open();
        using SqlCommand oCommand = new SqlCommand("[dbo].[EnrollCertificate]", oConnection)
        {
            CommandType = System.Data.CommandType.StoredProcedure
        };
        oCommand.Parameters.Add("@certificate", System.Data.SqlDbType.VarBinary, -1).Value = oCertificate;
        oCommand.Parameters.Add("@sid", System.Data.SqlDbType.NVarChar, 450).Value = sSid;
        SqlParameter oId = oCommand.Parameters.Add("@userId", System.Data.SqlDbType.BigInt);
        oId.Direction = System.Data.ParameterDirection.Output;
        oCommand.ExecuteNonQuery();
        return (long)oId.Value;
    }

    private static void TestSqlServerUpgrade(SqlServerVaultStorage oStorage, User oUser)
    {
        DatabaseOperations.SaveItem(new Item { Label = "Upgrade affiliation", ItemType = "text",
            ModifiedBy = oUser.UserId }, [3], new[] { oUser });
        using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
        oConnection.Open();
        using SqlCommand oCommand = oConnection.CreateCommand();
        oCommand.CommandText = "DROP PROCEDURE [dbo].[EnrollCertificate]; " +
            "DROP PROCEDURE [dbo].[VerifyUnboundCertificate]; " +
            "DROP PROCEDURE [dbo].[MarkEscrowCertificate]; " +
            "DROP PROCEDURE [dbo].[SetVaultEscrowPrincipal]; " +
            "ALTER TABLE [dbo].[CryptureVault] DROP CONSTRAINT [FK_CryptureVault_EscrowCertificate]; " +
            "ALTER TABLE [dbo].[CryptureVault] DROP CONSTRAINT [CK_CryptureVault_Escrow]; " +
            "ALTER TABLE [dbo].[CryptureVault] DROP COLUMN [EscrowCertificateUserId], " +
            "[EscrowDescriptor], [EscrowLabel]; " +
            "ALTER TABLE [dbo].[Cipher] DROP COLUMN [EscrowLabel]; " +
            "EXEC sys.sp_refreshview N'dbo.AuthorizedCipher'; " +
            "ALTER TABLE [dbo].[User] DROP CONSTRAINT [DF_User_IsEscrow]; " +
            "ALTER TABLE [dbo].[User] DROP COLUMN [IsEscrow]; " +
            "GRANT INSERT ON [dbo].[User] TO [crypture_domain]; " +
            "UPDATE [dbo].[CryptureVault] SET [SchemaVersion] = 2 WHERE [Id] = 1";
        oCommand.ExecuteNonQuery();
        using ManualResetEventSlim oStart = new ManualResetEventSlim();
        Task<Exception>[] oUpgrades = Enumerable.Range(0, 2).Select(_ => Task.Run(() =>
        {
            oStart.Wait();
            try { oStorage.Validate(); return null; }
            catch (Exception oError) { return oError; }
        })).ToArray();
        oStart.Set();
        Task.WaitAll(oUpgrades);
        if (oUpgrades.Any(t => t.Result != null))
            throw new Exception("Concurrent Vault upgrades failed.", oUpgrades.First(t => t.Result != null).Result);
        Check(true, "Concurrent Vault owners apply the schema upgrade once");
        using CryptureEntities oContext = new CryptureEntities();
        Check(oContext.Users.Single().Sid == null && !oContext.Items.Any(),
            "Upgrading a shared Vault quarantines previously unverified affiliations");
        oCommand.CommandText = "EXECUTE AS USER = N'crypture_probe'; " +
            "SELECT HAS_PERMS_BY_NAME(N'dbo.User', N'OBJECT', N'INSERT'); REVERT";
        Check((int)oCommand.ExecuteScalar() == 0,
            "Upgrade revokes direct certificate inserts from the domain role");
        oCommand.CommandText = "EXEC [dbo].[VerifyUnboundCertificate] @userId, @certificate, @sid";
        oCommand.Parameters.AddWithValue("@userId", oUser.UserId);
        oCommand.Parameters.AddWithValue("@certificate", new byte[] { 1, 2, 3 });
        oCommand.Parameters.AddWithValue("@sid", oUser.Sid);
        Reject(() => oCommand.ExecuteNonQuery(), "A different certificate cannot claim a quarantined affiliation");
        oCommand.Parameters["@certificate"].Value = oUser.Certificate;
        oCommand.ExecuteNonQuery();
        Check(oContext.Items.Any() && oContext.Users.AsNoTracking().Single().Sid == oUser.Sid,
            "Verified enrollment restores access to the existing encrypted item");
        oCommand.Parameters.Clear();

        // A Vault already using verified affiliations gains per-Vault escrow without changing its recipients.
        oCommand.CommandText = "DROP PROCEDURE [dbo].[SetVaultEscrowPrincipal]; " +
            "ALTER TABLE [dbo].[CryptureVault] DROP CONSTRAINT [FK_CryptureVault_EscrowCertificate]; " +
            "ALTER TABLE [dbo].[CryptureVault] DROP CONSTRAINT [CK_CryptureVault_Escrow]; " +
            "ALTER TABLE [dbo].[CryptureVault] DROP COLUMN [EscrowCertificateUserId], " +
            "[EscrowDescriptor], [EscrowLabel]; " +
            "ALTER TABLE [dbo].[Cipher] DROP COLUMN [EscrowLabel]; " +
            "EXEC sys.sp_refreshview N'dbo.AuthorizedCipher'; " +
            "UPDATE [dbo].[CryptureVault] SET [SchemaVersion] = 3 WHERE [Id] = 1";
        oCommand.ExecuteNonQuery();
        oStorage.Validate();
        oCommand.CommandText = "SELECT [SchemaVersion] FROM [dbo].[CryptureVault] WHERE [Id] = 1";
        Check((int)oCommand.ExecuteScalar() == 4 && oStorage.Escrow == null && oContext.Items.Any(),
            "Verified SQL Server Vaults upgrade without changing saved affiliations");
    }

    private static void TestSqlServerEscrow(SqlServerVaultStorage oStorage, User oPrimary)
    {
        string sConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginal = File.ReadAllBytes(sConfigPath);
        using RSA oKey = new RSACng(2048);
        using X509Certificate2 oDifferentCertificate = Certificate(oKey, "Different recovery",
            DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
        try
        {
            SetRecoveryConfig(null, Convert.ToBase64String(oDifferentCertificate.RawData));
            string sEscrowDescriptor = oStorage.Escrow.Descriptor;
            Item oWindowsEscrowItem = new Item { Label = "Windows escrow", ItemType = "text",
                ModifiedBy = oPrimary.UserId };
            Item oEncrypted = new Item
            {
                Cipher = new Cipher
                {
                    CipherText = [1], CipherVector = [1], CipherParams = ItemCryptography.RecoveryFormat,
                    ContentSuite = 1, AuthenticationTag = [1],
                    ProtectedKey = TestRecoveryEnvelope(sEscrowDescriptor), Signature = [1]
                }
            };
            oEncrypted.Instances.Add(new Instance { UserId = oPrimary.UserId, CipherKey = [1],
                CipherParams = ItemCryptography.RecoveryFormat, Signature = [1] });
            oEncrypted.Cipher.ProtectedKey = TestRecoveryEnvelope("SID=S-1-5-32-545");
            try
            {
                SqlServerItemOperations.Save(oStorage, oWindowsEscrowItem, oEncrypted);
                throw new Exception("SQL Server accepted an item without the Windows escrow identity.");
            }
            catch (SqlException oError) when (oError.Number == 50024)
            {
                Check(true, "SQL Server rejects a save missing the selected Windows escrow identity");
            }
            oEncrypted.Cipher.ProtectedKey = TestRecoveryEnvelope(sEscrowDescriptor);
            SqlServerItemOperations.Save(oStorage, oWindowsEscrowItem, oEncrypted);
            Item oWindowsStored = DatabaseOperations.LoadItem(oWindowsEscrowItem.ItemId);
            Check(oWindowsStored.ProtectionDisplay.Contains(oStorage.Escrow.Label) &&
                RecoveryProtection.ReadWindowsKeys(oWindowsStored.Cipher).Any(e =>
                    e.Key == sEscrowDescriptor),
                "Windows escrow is saved and named on the item despite a different local config");

            using (SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString))
            {
                oConnection.Open();
                using SqlCommand oCommand = new SqlCommand(
                    "EXEC [dbo].[MarkEscrowCertificate] @userId, @label", oConnection);
                oCommand.Parameters.AddWithValue("@userId", oPrimary.UserId);
                oCommand.Parameters.AddWithValue("@label", "Certificate: Primary escrow (" + oPrimary.Sid + ")");
                oCommand.ExecuteNonQuery();
            }
            oStorage.RefreshEscrow();
            Check(DatabaseOperations.LoadItem(oWindowsStored.ItemId).ProtectionDisplay
                .Contains("Windows: "), "Saved item text retains the escrow identity used at its save");
            DatabaseOperations.DeleteItem(oWindowsStored.ItemId);
            Item oMissingCertificate = new Item { Label = "Missing certificate escrow", ItemType = "text" };
            try
            {
                SqlServerItemOperations.Save(oStorage, oMissingCertificate, new Item
                {
                    Cipher = new Cipher { CipherText = [1], CipherVector = [1], CipherParams = 2,
                        ContentSuite = 1, AuthenticationTag = [1],
                        ProtectionDescriptor = "SID=" + WindowsIdentity.GetCurrent().User.Value,
                        ProtectedKey = [1], Signature = [1] }
                });
                throw new Exception("SQL Server accepted an item without the certificate escrow identity.");
            }
            catch (SqlException oError) when (oError.Number == 50023)
            {
                Check(true, "SQL Server rejects a save missing the selected certificate escrow identity");
            }
            DatabaseOperations.SaveItem(new Item { Label = "Verified escrow", ItemType = "text",
                ModifiedBy = oPrimary.UserId }, [2], new[] { oPrimary });
            using CryptureEntities oContext = new CryptureEntities();
            Item oCertificateItem = DatabaseOperations.LoadItem(oContext.Items.Single().ItemId);
            Check(oStorage.Escrow.CertificateUserId == oPrimary.UserId &&
                oContext.Users.Single(u => u.UserId == oPrimary.UserId).IsEscrow &&
                oCertificateItem.Instances.Any(i => i.UserId == oPrimary.UserId) &&
                oCertificateItem.ProtectionDisplay.Contains("Primary escrow"),
                "Certificate escrow uses its verified SID and is named on the item");
            DatabaseOperations.DeleteItem(oCertificateItem.ItemId);
        }
        finally { File.WriteAllBytes(sConfigPath, oOriginal); }
    }

    private static byte[] TestRecoveryEnvelope(params string[] oDescriptors)
    {
        using MemoryStream oStream = new MemoryStream();
        using BinaryWriter oWriter = new BinaryWriter(oStream, Encoding.UTF8);
        oWriter.Write(1);
        oWriter.Write(oDescriptors.Length);
        foreach (string sDescriptor in oDescriptors)
        {
            byte[] oData = Encoding.UTF8.GetBytes(sDescriptor);
            oWriter.Write(oData.Length);
            oWriter.Write(oData);
            oWriter.Write(1);
            oWriter.Write((byte)1);
        }
        return oStream.ToArray();
    }
    private static void TestSqlServerRecipientSecurity(SqlServerVaultStorage oStorage, long nItemId,
        string sCurrentSid, long nOtherUserId)
    {
        using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
        oConnection.Open();
        using SqlCommand oCommand = oConnection.CreateCommand();
        oCommand.CommandText = "SELECT [dbo].[MatchesDescriptor](@descriptor)";
        oCommand.Parameters.AddWithValue("@descriptor", "SID=S-1-5-32-545 AND SID=" + sCurrentSid);
        Check((bool)oCommand.ExecuteScalar(), "SQL Server matches every SID in an AND descriptor");
        oCommand.Parameters["@descriptor"].Value = "SID=S-1-5-21-1-2-3-1000 OR SID=" + sCurrentSid;
        Check((bool)oCommand.ExecuteScalar(), "SQL Server matches any SID in an OR descriptor");
        oCommand.Parameters["@descriptor"].Value = "SID=S-1-5-21-1-2-3-1000 AND SID=" + sCurrentSid;
        Check(!(bool)oCommand.ExecuteScalar(), "SQL Server rejects an unmatched AND descriptor");
        oCommand.Parameters.Clear();
        byte[] oRecoveryEnvelope;
        using (MemoryStream oStream = new MemoryStream())
        using (BinaryWriter oWriter = new BinaryWriter(oStream, Encoding.UTF8))
        {
            oWriter.Write(1);
            oWriter.Write(2);
            foreach (string sDescriptor in new[]
            {
                "SID=S-1-5-21-1-2-3-1000", "SID=S-1-5-32-545"
            })
            {
                byte[] oDescriptor = Encoding.UTF8.GetBytes(sDescriptor);
                oWriter.Write(oDescriptor.Length);
                oWriter.Write(oDescriptor);
                oWriter.Write(1);
                oWriter.Write((byte)1);
            }
            oRecoveryEnvelope = oStream.ToArray();
        }
        oCommand.CommandText = "SELECT [dbo].[MatchesRecoveryEnvelope](@envelope, @primary)";
        oCommand.Parameters.AddWithValue("@envelope", oRecoveryEnvelope);
        oCommand.Parameters.Add("@primary", System.Data.SqlDbType.NVarChar, -1).Value = DBNull.Value;
        Check((bool)oCommand.ExecuteScalar(), "Saved recovery descriptor grants its Windows group access");
        oCommand.Parameters["@primary"].Value = "SID=" + sCurrentSid;
        Check(!(bool)oCommand.ExecuteScalar(), "Mismatched primary recovery metadata grants no access");
        oCommand.Parameters.Clear();
        Item oRecoveryItem = new Item { Label = "Recovery affiliation", ItemType = "text" };
        Item oRecoveryEncrypted = new Item
        {
            Cipher = new Cipher
            {
                CipherText = [1], CipherVector = [1], CipherParams = ItemCryptography.RecoveryFormat,
                ContentSuite = 1, AuthenticationTag = [1], ProtectedKey = oRecoveryEnvelope, Signature = [1]
            }
        };
        oRecoveryEncrypted.Instances.Add(new Instance { UserId = oStorage.Escrow.CertificateUserId.Value,
            CipherKey = [1], CipherParams = ItemCryptography.RecoveryFormat, Signature = [1] });
        SqlServerItemOperations.Save(oStorage, oRecoveryItem, oRecoveryEncrypted);
        oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[Item] WHERE [ItemId] = @itemId";
        oCommand.Parameters.AddWithValue("@itemId", oRecoveryItem.ItemId);
        Check((int)oCommand.ExecuteScalar() == 1, "Recovery group affiliation controls item visibility");
        oCommand.Parameters.Clear();
        SqlServerItemOperations.Delete(oStorage, oRecoveryItem.ItemId);
        Item oGroupItem = new Item { Label = "Group affiliation", ItemType = "text" };
        Item oGroupEncrypted = new Item
        {
            Cipher = new Cipher
            {
                CipherText = [1], CipherVector = [1], CipherParams = 1, ContentSuite = 1,
                AuthenticationTag = [1], ProtectionDescriptor = "SID=S-1-5-32-545",
                ProtectedKey = [1], Signature = [1]
            }
        };
        oGroupEncrypted.Instances.Add(new Instance { UserId = oStorage.Escrow.CertificateUserId.Value,
            CipherKey = [1], CipherParams = 1, Signature = [1] });
        SqlServerItemOperations.Save(oStorage, oGroupItem, oGroupEncrypted);
        oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[Item] WHERE [ItemId] = @itemId";
        oCommand.Parameters.AddWithValue("@itemId", oGroupItem.ItemId);
        Check((int)oCommand.ExecuteScalar() == 1, "Windows group SID grants item visibility");
        oCommand.Parameters.Clear();
        SqlServerItemOperations.Delete(oStorage, oGroupItem.ItemId);
        oCommand.CommandText = "UPDATE [dbo].[User] SET [Sid] = N'S-1-5-21-1-2-3-1000' WHERE [UserId] = @otherId";
        oCommand.Parameters.AddWithValue("@otherId", nOtherUserId);
        oCommand.ExecuteNonQuery();
        oCommand.Parameters.Clear();
        oCommand.CommandText = "CREATE USER [crypture_probe] WITHOUT LOGIN; " +
            "ALTER ROLE [crypture_domain] ADD MEMBER [crypture_probe]";
        oCommand.ExecuteNonQuery();

        // Impersonation keeps the original Windows SID while exercising the domain role's permissions.
        oCommand.CommandText = "EXECUTE AS USER = N'crypture_probe'";
        oCommand.ExecuteNonQuery();
        try
        {
            oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[Item]";
            Check((int)oCommand.ExecuteScalar() == 1, "Affiliated Windows SID can list its item");
            oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[AuthorizedCipher]";
            Check((int)oCommand.ExecuteScalar() == 1, "Affiliated SID can read the encrypted content view");
            oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[AuthorizedInstance]";
            Check((int)oCommand.ExecuteScalar() == 2, "Affiliated SID can read the recipient view");
            oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[Cipher]";
            Reject(() => oCommand.ExecuteScalar(), "Domain role cannot bypass the encrypted-content view");
            oCommand.CommandText = "UPDATE [dbo].[User] SET [Sid] = N'S-1-5-32-545'";
            Reject(() => oCommand.ExecuteNonQuery(), "Domain role cannot rewrite recipient SIDs");
            oCommand.CommandText = "INSERT INTO [dbo].[User] ([Certificate], [Sid]) " +
                "VALUES (0x010203, @sid)";
            oCommand.Parameters.AddWithValue("@sid", sCurrentSid);
            Reject(() => oCommand.ExecuteNonQuery(), "Domain role cannot insert unverified affiliations");
            oCommand.CommandText = "DECLARE @id bigint; EXEC [dbo].[EnrollCertificate] " +
                "@certificate = 0x010203, @sid = @sid, @userId = @id OUTPUT";
            Reject(() => oCommand.ExecuteNonQuery(), "Domain role cannot invoke trusted enrollment");
            oCommand.CommandText = "EXEC [dbo].[MarkEscrowCertificate] @userId = @otherId";
            oCommand.Parameters.AddWithValue("@otherId", nOtherUserId);
            Reject(() => oCommand.ExecuteNonQuery(), "Domain role cannot designate escrow");
            oCommand.CommandText = "EXEC [dbo].[SetVaultEscrowPrincipal] @sid = @sid, " +
                "@label = N'Forged escrow'";
            Reject(() => oCommand.ExecuteNonQuery(), "Domain role cannot change the Vault escrow identity");
            oCommand.Parameters.Clear();
            oCommand.CommandText = "INSERT INTO [dbo].[Item] ([Label]) VALUES (N'bypass')";
            Reject(() => oCommand.ExecuteNonQuery(), "Domain role cannot insert item rows directly");
            oCommand.CommandText = "DECLARE @r [dbo].[EncryptedRecipient]; " +
                "INSERT INTO @r ([UserId], [CipherKey], [CipherParams], [Signature]) " +
                "SELECT TOP (1) [UserId], 0x01, 2, 0x01 FROM [dbo].[User] WHERE [Sid] = @sid; " +
                "DECLARE @newId bigint = 0; EXEC [dbo].[SaveItem] @itemId = @newId OUTPUT, " +
                "@expectedRowVersion = NULL, @label = N'Forged modifier', @itemType = N'text', " +
                "@modifiedBy = @otherId, @cipherText = 0x01, @cipherVector = 0x01, @cipherParams = 2, " +
                "@contentSuite = 1, @authenticationTag = 0x01, @protectionDescriptor = NULL, " +
                "@protectedKey = NULL, @signature = NULL, @recipients = @r";
            oCommand.Parameters.AddWithValue("@sid", sCurrentSid);
            oCommand.Parameters.AddWithValue("@otherId", nOtherUserId);
            bool bModifierRejected = false;
            try { oCommand.ExecuteNonQuery(); }
            catch (SqlException oError) when (oError.Number == 50016) { bModifierRejected = true; }
            Check(bModifierRejected, "Domain role cannot attribute an item to another Windows identity");
            oCommand.Parameters.Clear();
            oCommand.CommandText = "DECLARE @r [dbo].[EncryptedRecipient]; " +
                "INSERT INTO @r ([UserId], [CipherKey], [CipherParams], [Signature]) " +
                "SELECT TOP (1) [UserId], 0x01, 2, 0x01 FROM [dbo].[User] WHERE [Sid] = @sid; " +
                "DECLARE @newId bigint = 0; EXEC [dbo].[SaveItem] @itemId = @newId OUTPUT, " +
                "@expectedRowVersion = NULL, @label = N'Role item', @itemType = N'text', " +
                "@modifiedBy = NULL, @cipherText = 0x01, @cipherVector = 0x01, @cipherParams = 2, " +
                "@contentSuite = 1, @authenticationTag = 0x01, @protectionDescriptor = NULL, " +
                "@protectedKey = NULL, @signature = NULL, @recipients = @r; SELECT @newId";
            oCommand.Parameters.AddWithValue("@sid", sCurrentSid);
            long nRoleItem = (long)oCommand.ExecuteScalar();
            Check(nRoleItem > nItemId, "Domain role can save an affiliated item through the procedure");
            oCommand.Parameters.Clear();
            oCommand.CommandText = "EXEC [dbo].[DeleteItem] @itemId";
            oCommand.Parameters.AddWithValue("@itemId", nRoleItem);
            oCommand.ExecuteNonQuery();
            Check(true, "Domain role can delete its affiliated item through the procedure");
            oCommand.Parameters.Clear();
        }
        finally
        {
            oCommand.CommandText = "REVERT";
            oCommand.ExecuteNonQuery();
        }

        oCommand.CommandText = "UPDATE [dbo].[User] SET [Sid] = @sid";
        oCommand.Parameters.AddWithValue("@sid", "S-1-5-21-1-2-3-1000");
        oCommand.ExecuteNonQuery();
        oCommand.Parameters.Clear();
        oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[Item]";
        Check((int)oCommand.ExecuteScalar() == 0,
            "Setup account's app queries still follow recipient affiliation");
        oCommand.CommandText = "EXECUTE AS USER = N'crypture_probe'";
        oCommand.ExecuteNonQuery();
        try
        {
            oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[Item]";
            Check((int)oCommand.ExecuteScalar() == 0, "Unrelated SID cannot list the item");
            oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[AuthorizedCipher]";
            Check((int)oCommand.ExecuteScalar() == 0, "Unrelated SID cannot read encrypted content");
            oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[AuthorizedInstance]";
            Check((int)oCommand.ExecuteScalar() == 0, "Unrelated SID cannot read recipient links");
            oCommand.CommandText = "EXEC [dbo].[DeleteItem] @itemId";
            oCommand.Parameters.AddWithValue("@itemId", nItemId);
            Reject(() => oCommand.ExecuteNonQuery(), "Unrelated SID cannot delete the item");
        }
        finally
        {
            oCommand.Parameters.Clear();
            oCommand.CommandText = "REVERT";
            oCommand.ExecuteNonQuery();
            oCommand.CommandText = "UPDATE [dbo].[User] SET [Sid] = @sid";
            oCommand.Parameters.AddWithValue("@sid", sCurrentSid);
            oCommand.ExecuteNonQuery();
            oCommand.Parameters.Clear();
        }
    }
}
