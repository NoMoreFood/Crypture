using System;
using System.IO;
using System.Linq;
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
        try
        {
            SqlConnectionStringBuilder oLogin = new SqlConnectionStringBuilder(oBuilder.ConnectionString)
            {
                IntegratedSecurity = false, UserID = "crypture-test", Password = "transient-secret"
            };
            Reject(() => new SqlServerVaultStorage(oLogin.ConnectionString),
                "SQL Server Vaults reject password authentication");

            // Exercise the same encrypted item and recipient operations used by the desktop editor.
            oStorage.Create();
            oStorage.Validate();
            Reject(() => oStorage.Create(), "SQL Server refuses to overwrite an existing Vault");
            CryptureEntities.Storage = oStorage;
            string sCurrentSid = WindowsIdentity.GetCurrent().User.Value;
            User[] oUsers = { new User { Certificate = oCert.RawData, Sid = sCurrentSid },
                new User { Certificate = oOtherCert.RawData, Sid = sCurrentSid } };
            using (CryptureEntities oContext = new CryptureEntities())
            {
                oContext.Users.AddRange(oUsers);
                oContext.SaveChanges();
                Check(oContext.Users.Count() == 2, "SQL Server saves recipient certificates");
            }
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
        }
        finally
        {
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
        SqlServerItemOperations.Save(oStorage, oRecoveryItem, new Item
        {
            Cipher = new Cipher
            {
                CipherText = [1], CipherVector = [1], CipherParams = ItemCryptography.RecoveryFormat,
                ContentSuite = 1, AuthenticationTag = [1], ProtectedKey = oRecoveryEnvelope, Signature = [1]
            }
        });
        oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[Item] WHERE [ItemId] = @itemId";
        oCommand.Parameters.AddWithValue("@itemId", oRecoveryItem.ItemId);
        Check((int)oCommand.ExecuteScalar() == 1, "Recovery group affiliation controls item visibility");
        oCommand.Parameters.Clear();
        SqlServerItemOperations.Delete(oStorage, oRecoveryItem.ItemId);
        Item oGroupItem = new Item { Label = "Group affiliation", ItemType = "text" };
        SqlServerItemOperations.Save(oStorage, oGroupItem, new Item
        {
            Cipher = new Cipher
            {
                CipherText = [1], CipherVector = [1], CipherParams = 1, ContentSuite = 1,
                AuthenticationTag = [1], ProtectionDescriptor = "SID=S-1-5-32-545",
                ProtectedKey = [1], Signature = [1]
            }
        });
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
