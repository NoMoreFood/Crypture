using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Data;
using System.Collections.Generic;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Ribbon;
using System.Windows.Threading;
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
            using (SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString))
            {
                oConnection.Open();
                using SqlCommand oCommand = new SqlCommand(
                    "SELECT OBJECT_ID(N'dbo.PasswordGeneratorSettings', N'U')", oConnection);
                Check(oCommand.ExecuteScalar() is DBNull,
                    "New SQL Server Vaults contain no password generator preferences");
            }
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
            TestSqlServerEscrowSelection(oStorage, oUsers);
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
            Check(oLoaded.CreatedDate.Kind == DateTimeKind.Utc && oLoaded.ModifiedDate.Kind == DateTimeKind.Utc &&
                Math.Abs((DateTime.UtcNow - oLoaded.CreatedDate).TotalSeconds) < 60,
                "SQL Server saves and reloads UTC item timestamps");
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
            PasswordOptions.SavePreferences(new PasswordOptions { MinimumLength = 26,
                MaximumLength = 32 });
            Check(PasswordOptions.LoadPreferences().MinimumLength == 26,
                "SQL Server connections use the Windows user's password generator preferences");
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
            TestSqlServerValidation(oStorage, oUsers[0]);
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
            if (Application.Current != null) TestSqlServerEditorSave(oPrimary, oPrimaryCertificate);
            TestSqlServerSchemaConstraints(oStorage, oStored);
            TestSqlServerSaveValidation(oStorage, oStored);
            TestSqlServerContentLimits(oStorage, oStored.Instances.Select(i => i.User).ToArray(),
                oPrimary, oPrimaryCertificate);
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

    private static void TestSqlServerEditorSave(User oPrimary, X509Certificate2 oCertificate)
    {
        SynchronizationContext oPreviousContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
        ItemEditor oEditor = null;
        Exception oSaveError = null;
        DispatcherUnhandledExceptionEventHandler oUnhandled = (s, e) =>
        {
            oSaveError = e.Exception;
            e.Handled = true;
        };
        Dispatcher.CurrentDispatcher.UnhandledException += oUnhandled;
        try
        {
            // Exercise the asynchronous save handler through its busy-state cleanup and window close.
            oEditor = new ItemEditor
            {
                Left = -20000, Top = -20000, WindowStartupLocation = WindowStartupLocation.Manual,
                ShowActivated = false, ShowInTaskbar = false
            };
            oEditor.Show();
            PumpUntil(() => oEditor.IsLoaded && oEditor.CertificateLoading.IsCompleted);
            ((TextBox)oEditor.FindName("oItemLabel")).Text = "SQL Server editor save";
            ((TextBox)oEditor.FindName("oItemData")).Text = "Saved through the SQL Server editor";
            ((ComboBox)oEditor.FindName("oProtectionMode")).SelectedIndex = 1;
            oEditor.UserListSelected.Add(oPrimary);
            Check(((RibbonButton)oEditor.FindName("oSaveItemButton")).IsEnabled,
                "A new SQL Server item is ready to save with certificate protection");
            typeof(ItemEditor).GetMethod("oSaveItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oEditor, [null, new RoutedEventArgs()]);
            PumpUntil(() => !oEditor.IsVisible || oSaveError != null);
            if (oSaveError != null) throw new Exception("The SQL Server editor failed after saving.", oSaveError);
            Check(oEditor.ThisItem.ItemId != 0 && ((TextBox)oEditor.FindName("oItemData")).Text.Length == 0,
                "Saving a new SQL Server item closes the editor and clears plaintext");
            Item oStored = DatabaseOperations.LoadItem(oEditor.ThisItem.ItemId);
            oEditor.Close();
            oEditor = new ItemEditor(oStored);
            CheckItemDateDisplay(oEditor);
            Check(Encoding.Unicode.GetString(ItemCryptography.Decrypt(oStored,
                oStored.Instances.Single(i => i.UserId == oPrimary.UserId), oCertificate)) ==
                "Saved through the SQL Server editor",
                "The item saved through the SQL Server editor reopens and decrypts");
            DatabaseOperations.DeleteItem(oStored.ItemId);
        }
        finally
        {
            Dispatcher.CurrentDispatcher.UnhandledException -= oUnhandled;
            if (oEditor != null)
            {
                typeof(ItemEditor).GetField("bBusy", BindingFlags.Instance | BindingFlags.NonPublic)
                    .SetValue(oEditor, false);
                typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                    .SetValue(oEditor, false);
                oEditor.Close();
            }
            SynchronizationContext.SetSynchronizationContext(oPreviousContext);
        }
    }

    private static void TestSqlServerEscrowSelection(SqlServerVaultStorage oStorage, User[] oUsers)
    {
        using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
        oConnection.Open();
        using SqlCommand oCommand = oConnection.CreateCommand();
        oCommand.CommandText = "SELECT COL_LENGTH(N'dbo.User', N'IsEscrow')";
        Check(oCommand.ExecuteScalar() is DBNull, "SQL Server stores escrow affiliation only in the Vault marker");

        // Switching the selection updates certificate displays without maintaining another flag.
        foreach (User oUser in oUsers)
        {
            oCommand.CommandText = "EXEC [dbo].[MarkEscrowCertificate] @userId, N'Selected certificate'";
            oCommand.Parameters.AddWithValue("@userId", oUser.UserId);
            oCommand.ExecuteNonQuery();
            using CryptureEntities oContext = new CryptureEntities();
            Check(oContext.Users.Single(u => u.IsEscrow).UserId == oUser.UserId,
                "Only the Vault's selected certificate is displayed as escrow");
            oCommand.CommandText = "EXEC [dbo].[RemoveCertificate] @userId";
            bool bRejected = false;
            try { oCommand.ExecuteNonQuery(); }
            catch (SqlException oError) when (oError.Number == 50019) { bRejected = true; }
            Check(bRejected, "The Vault selection protects an escrow certificate from direct procedure deletion");
            oCommand.Parameters.Clear();
        }
        oCommand.CommandText = "EXEC [dbo].[SetVaultEscrowPrincipal] @sid, @label";
        oCommand.Parameters.AddWithValue("@sid", oUsers[0].Sid);
        oCommand.Parameters.AddWithValue("@label", oStorage.Escrow.Label);
        oCommand.ExecuteNonQuery();
        using (CryptureEntities oContext = new CryptureEntities())
            Check(!oContext.Users.Any(u => u.IsEscrow) && oContext.Users.Count() == oUsers.Length,
                "Windows escrow clears all derived certificate flags and preserves the enrolled directory");
        oStorage.RefreshEscrow();
    }

    private static void TestSqlServerSchemaConstraints(SqlServerVaultStorage oStorage, Item oStored)
    {
        using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
        oConnection.Open();
        (string Name, string Sql)[] oCases =
        {
            ("Empty certificate", "UPDATE [dbo].[User] SET [Certificate] = 0x WHERE [UserId] = @userId"),
            ("Oversized certificate", "UPDATE [dbo].[User] SET [Certificate] = " +
                "CONVERT(varbinary(max), REPLICATE(CONVERT(varchar(max), 'x'), 16385)) WHERE [UserId] = @userId"),
            ("Empty SID", "UPDATE [dbo].[User] SET [Sid] = N'' WHERE [UserId] = @userId"),
            ("Empty label", "UPDATE [dbo].[Item] SET [Label] = N'' WHERE [ItemId] = @itemId"),
            ("Oversized label", "UPDATE [dbo].[Item] SET [Label] = " +
                "REPLICATE(CONVERT(nvarchar(max), N'x'), 16001) WHERE [ItemId] = @itemId"),
            ("Oversized type", "UPDATE [dbo].[Item] SET [ItemType] = REPLICATE(N'x', 451) WHERE [ItemId] = @itemId"),
            ("Oversized modifier", "UPDATE [dbo].[Item] SET [ModifiedByIdentity] = " +
                "REPLICATE(N'x', 451) WHERE [ItemId] = @itemId"),
            ("Missing suite", "UPDATE [dbo].[Cipher] SET [ContentSuite] = NULL WHERE [ItemId] = @itemId"),
            ("Unknown suite", "UPDATE [dbo].[Cipher] SET [ContentSuite] = 99 WHERE [ItemId] = @itemId"),
            ("Unsupported format", "UPDATE [dbo].[Cipher] SET [CipherParams] = 0 WHERE [ItemId] = @itemId"),
            ("Invalid nonce", "UPDATE [dbo].[Cipher] SET [CipherVector] = 0x01 WHERE [ItemId] = @itemId"),
            ("Oversized nonce", "UPDATE [dbo].[Cipher] SET [CipherVector] = " +
                "CONVERT(varbinary(max), REPLICATE('x', 17)) WHERE [ItemId] = @itemId"),
            ("Missing tag", "UPDATE [dbo].[Cipher] SET [AuthenticationTag] = NULL WHERE [ItemId] = @itemId"),
            ("Short tag", "UPDATE [dbo].[Cipher] SET [AuthenticationTag] = 0x01 WHERE [ItemId] = @itemId"),
            ("Oversized tag", "UPDATE [dbo].[Cipher] SET [AuthenticationTag] = " +
                "CONVERT(varbinary(max), REPLICATE('x', 17)) WHERE [ItemId] = @itemId"),
            ("Oversized payload", "UPDATE [dbo].[Cipher] SET [CipherText] = " +
                "CONVERT(varbinary(max), REPLICATE(CONVERT(varchar(max), 'x'), 68157441)) WHERE [ItemId] = @itemId"),
            ("Invalid CBC length", "UPDATE [dbo].[Cipher] SET [ContentSuite] = 2, " +
                "[CipherText] = CONVERT(varbinary(max), REPLICATE('x', 17)), " +
                "[CipherVector] = CONVERT(binary(16), 0x01), [AuthenticationTag] = NULL WHERE [ItemId] = @itemId"),
            ("Empty protected key", "UPDATE [dbo].[Cipher] SET [ProtectedKey] = 0x WHERE [ItemId] = @itemId"),
            ("Oversized protected key", "UPDATE [dbo].[Cipher] SET [ProtectedKey] = " +
                "CONVERT(varbinary(max), REPLICATE(CONVERT(varchar(max), 'x'), 2225185)) WHERE [ItemId] = @itemId"),
            ("Missing Windows access signature", "UPDATE [dbo].[Cipher] SET [CipherParams] = 2, " +
                "[ProtectionDescriptor] = N'SID=' + @sid, [ProtectedKey] = 0x01, [Signature] = NULL " +
                "WHERE [ItemId] = @itemId"),
            ("Missing recovery key", "UPDATE [dbo].[Cipher] SET [CipherParams] = 4, " +
                "[ProtectedKey] = NULL, [Signature] = CONVERT(binary(32), 0x01) WHERE [ItemId] = @itemId"),
            ("Short recovery signature", "UPDATE [dbo].[Cipher] SET [Signature] = 0x01 WHERE [ItemId] = @itemId"),
            ("Invalid recipient format", "UPDATE [dbo].[Instance] SET [CipherParams] = 2 WHERE [ItemId] = @itemId"),
            ("Short recipient key", "UPDATE [dbo].[Instance] SET [CipherKey] = 0x01 WHERE [ItemId] = @itemId"),
            ("Oversized recipient key", "UPDATE [dbo].[Instance] SET [CipherKey] = " +
                "CONVERT(varbinary(max), REPLICATE('x', 4097)) WHERE [ItemId] = @itemId"),
            ("Short recipient signature", "UPDATE [dbo].[Instance] SET [Signature] = 0x01 WHERE [ItemId] = @itemId"),
            ("Duplicate recipient", "INSERT INTO [dbo].[Instance] " +
                "([ItemId], [UserId], [CipherKey], [CipherParams], [Signature]) " +
                "SELECT [ItemId], [UserId], [CipherKey], [CipherParams], [Signature] " +
                "FROM [dbo].[Instance] WHERE [ItemId] = @itemId")
        };

        // Malformed table writes must fail even when they bypass the save procedure.
        foreach ((string sName, string sSql) in oCases)
        {
            using SqlTransaction oTransaction = oConnection.BeginTransaction();
            using SqlCommand oCommand = new SqlCommand(sSql, oConnection, oTransaction) { CommandTimeout = 120 };
            oCommand.Parameters.AddWithValue("@itemId", oStored.ItemId);
            oCommand.Parameters.AddWithValue("@userId", oStored.Instances.First().UserId);
            oCommand.Parameters.AddWithValue("@sid", CertificateOperations.CurrentUserSid);
            bool bRejected = false;
            try { oCommand.ExecuteNonQuery(); }
            catch (SqlException oError) when (oError.Number is 515 or 547 or 8152 or 2628 or 2601 or 2627)
            {
                bRejected = true;
            }
            oTransaction.Rollback();
            Check(bRejected, "SQL Server schema rejects a malformed direct write: " + sName);
        }
        Item oUnchanged = DatabaseOperations.LoadItem(oStored.ItemId);
        Check(oUnchanged.Cipher.CipherText.SequenceEqual(oStored.Cipher.CipherText) &&
            oUnchanged.Instances.Count == oStored.Instances.Count &&
            oUnchanged.RowVersion.SequenceEqual(oStored.RowVersion),
            "Rejected direct writes preserve the item revision, encrypted content, and recipient keys");
    }

    private static void TestSqlServerSaveValidation(SqlServerVaultStorage oStorage, Item oStored)
    {
        using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
        oConnection.Open();
        using SqlCommand oSetup = new SqlCommand("CREATE USER [crypture_validation] WITHOUT LOGIN; " +
            "ALTER ROLE [crypture_domain] ADD MEMBER [crypture_validation]; " +
            "EXECUTE AS USER = N'crypture_validation'", oConnection);
        oSetup.ExecuteNonQuery();
        using SqlCommand oSave = new SqlCommand("[dbo].[SaveItem]", oConnection)
        {
            CommandType = CommandType.StoredProcedure, CommandTimeout = 120
        };
        oSave.Parameters.Add("@itemId", SqlDbType.BigInt).Direction = ParameterDirection.InputOutput;
        oSave.Parameters.Add("@expectedRowVersion", SqlDbType.Binary, 8).Value = DBNull.Value;
        oSave.Parameters.Add("@label", SqlDbType.NVarChar, -1);
        oSave.Parameters.Add("@itemType", SqlDbType.NVarChar, -1);
        oSave.Parameters.Add("@modifiedBy", SqlDbType.BigInt).Value = DBNull.Value;
        oSave.Parameters.Add("@cipherText", SqlDbType.VarBinary, -1);
        oSave.Parameters.Add("@cipherVector", SqlDbType.VarBinary, -1);
        oSave.Parameters.Add("@cipherParams", SqlDbType.BigInt);
        oSave.Parameters.Add("@contentSuite", SqlDbType.BigInt);
        oSave.Parameters.Add("@authenticationTag", SqlDbType.VarBinary, -1);
        oSave.Parameters.Add("@protectionDescriptor", SqlDbType.NVarChar, -1);
        oSave.Parameters.Add("@protectedKey", SqlDbType.VarBinary, -1);
        oSave.Parameters.Add("@signature", SqlDbType.VarBinary, -1);
        oSave.Parameters.Add("@recipients", SqlDbType.Structured).TypeName = "dbo.EncryptedRecipient";
        DataTable oRecipients = new DataTable();
        oRecipients.Columns.Add("UserId", typeof(long));
        oRecipients.Columns.Add("CipherKey", typeof(byte[]));
        oRecipients.Columns.Add("CipherParams", typeof(long));
        oRecipients.Columns.Add("Signature", typeof(byte[]));
        foreach (Instance oInstance in oStored.Instances)
            oRecipients.Rows.Add(oInstance.UserId, oInstance.CipherKey, oInstance.CipherParams, oInstance.Signature);
        (string Name, Action<SqlCommand> Change)[] oCases =
        {
            ("Ignored escrow recipient format", c => ((DataTable)c.Parameters["@recipients"].Value).Rows
                .Cast<DataRow>().Single(r => (long)r["UserId"] == oStorage.Escrow.CertificateUserId)["CipherParams"] = 2L),
            ("Oversized text ciphertext", c => c.Parameters["@cipherText"].Value =
                new byte[Utilities.MaxItemSize + 1]),
            ("Oversized file ciphertext", c =>
            {
                c.Parameters["@itemType"].Value = ".bin";
                c.Parameters["@cipherText"].Value = new byte[Utilities.MaxCompressedItemSize + 1];
            }),
            ("Oversized recipient key", c => ((DataTable)c.Parameters["@recipients"].Value).Rows[0]["CipherKey"] =
                new byte[4097]),
            ("Invalid recipient signature", c => ((DataTable)c.Parameters["@recipients"].Value).Rows[0]["Signature"] =
                new byte[33]),
            ("Invalid GCM nonce", c => c.Parameters["@cipherVector"].Value = new byte[13]),
            ("Invalid GCM tag", c => c.Parameters["@authenticationTag"].Value = new byte[17]),
            ("Invalid CBC block length", c =>
            {
                c.Parameters["@contentSuite"].Value = 2L;
                c.Parameters["@cipherText"].Value = new byte[17];
                c.Parameters["@cipherVector"].Value = new byte[16];
                c.Parameters["@authenticationTag"].Value = DBNull.Value;
            }),
            ("Oversized CBC ciphertext", c =>
            {
                c.Parameters["@itemType"].Value = ".bin";
                c.Parameters["@contentSuite"].Value = 2L;
                c.Parameters["@cipherText"].Value = new byte[Utilities.MaxCompressedItemSize + 32];
                c.Parameters["@cipherVector"].Value = new byte[16];
                c.Parameters["@authenticationTag"].Value = DBNull.Value;
            }),
            ("Missing content suite", c => c.Parameters["@contentSuite"].Value = DBNull.Value),
            ("Unsupported protection format", c => c.Parameters["@cipherParams"].Value = 99L),
            ("Oversized item label", c => c.Parameters["@label"].Value = new string('x', 16001)),
            ("Oversized item type", c => c.Parameters["@itemType"].Value = new string('x', 451)),
            ("Oversized protection descriptor", c => c.Parameters["@protectionDescriptor"].Value =
                "SID=" + new string('x', 16001)),
            ("Oversized recovery envelope", c =>
            {
                c.Parameters["@cipherParams"].Value = ItemCryptography.RecoveryFormat;
                c.Parameters["@signature"].Value = new byte[32];
                c.Parameters["@protectedKey"].Value = new byte[2225185];
                foreach (DataRow oRow in ((DataTable)c.Parameters["@recipients"].Value).Rows)
                    oRow["CipherParams"] = ItemCryptography.RecoveryFormat;
            }),
            ("Invalid recovery envelope header", c =>
            {
                byte[] oEnvelope = TestRecoveryEnvelope("SID=" + CertificateOperations.CurrentUserSid);
                Array.Fill(oEnvelope, (byte)255, 0, 4);
                c.Parameters["@cipherParams"].Value = ItemCryptography.RecoveryFormat;
                c.Parameters["@signature"].Value = new byte[32];
                c.Parameters["@protectedKey"].Value = oEnvelope;
                foreach (DataRow oRow in ((DataTable)c.Parameters["@recipients"].Value).Rows)
                    oRow["CipherParams"] = ItemCryptography.RecoveryFormat;
            }),
            ("Too many recipients", c =>
            {
                DataTable oRows = (DataTable)c.Parameters["@recipients"].Value;
                while (oRows.Rows.Count <= 100)
                    oRows.Rows.Add(10000L + oRows.Rows.Count, new byte[8],
                        ItemCryptography.CertificateFormat, new byte[32]);
            })
        };
        List<string> oAccepted = new List<string>();
        try
        {
            // Call the procedure as a domain-role member to bypass all client validation.
            foreach (var (sName, oChange) in oCases)
            {
                oSave.Parameters["@itemId"].Value = 0L;
                oSave.Parameters["@label"].Value = oStored.Label;
                oSave.Parameters["@itemType"].Value = oStored.ItemType;
                oSave.Parameters["@cipherText"].Value = oStored.Cipher.CipherText;
                oSave.Parameters["@cipherVector"].Value = oStored.Cipher.CipherVector;
                oSave.Parameters["@cipherParams"].Value = oStored.Cipher.CipherParams;
                oSave.Parameters["@contentSuite"].Value = oStored.Cipher.ContentSuite;
                oSave.Parameters["@authenticationTag"].Value = oStored.Cipher.AuthenticationTag;
                oSave.Parameters["@protectionDescriptor"].Value = DBNull.Value;
                oSave.Parameters["@protectedKey"].Value = DBNull.Value;
                oSave.Parameters["@signature"].Value = DBNull.Value;
                oSave.Parameters["@recipients"].Value = oRecipients.Copy();
                oChange(oSave);
                try
                {
                    oSave.ExecuteNonQuery();
                    oAccepted.Add(sName);
                    Console.WriteLine("ACCEPTED: " + sName);
                    using SqlCommand oDelete = new SqlCommand("EXEC [dbo].[DeleteItem] @id", oConnection);
                    oDelete.Parameters.AddWithValue("@id", oSave.Parameters["@itemId"].Value);
                    oDelete.ExecuteNonQuery();
                }
                catch (SqlException oError) when (oError.Number == 50026)
                {
                    Check(true, "SQL Server rejects " + sName.ToLowerInvariant());
                }
            }

            // Reject malformed edits before replacing the existing ciphertext and recipients.
            oSave.Parameters["@itemId"].Value = oStored.ItemId;
            oSave.Parameters["@expectedRowVersion"].Value = oStored.RowVersion;
            oSave.Parameters["@recipients"].Value = oRecipients.Copy();
            oSave.Parameters["@cipherVector"].Value = new byte[13];
            try
            {
                oSave.ExecuteNonQuery();
                throw new Exception("SQL Server accepted an invalid encrypted item update.");
            }
            catch (SqlException oError) when (oError.Number == 50026)
            {
                Check(true, "SQL Server rejects malformed encrypted item updates");
            }
        }
        finally
        {
            oSetup.CommandText = "REVERT";
            oSetup.ExecuteNonQuery();
        }
        Check(oAccepted.Count == 0, "SQL Server rejects every malformed save");
        Item oUnchanged = DatabaseOperations.LoadItem(oStored.ItemId);
        using SqlCommand oCount = new SqlCommand("SELECT COUNT(*) FROM [dbo].[Item]", oConnection);
        Check((int)oCount.ExecuteScalar() == 1 && oUnchanged.RowVersion.SequenceEqual(oStored.RowVersion) &&
            oUnchanged.Cipher.CipherText.SequenceEqual(oStored.Cipher.CipherText) &&
            oUnchanged.Instances.Count == oStored.Instances.Count && oUnchanged.Instances.All(i =>
                i.CipherKey.SequenceEqual(oStored.Instances.Single(j => j.UserId == i.UserId).CipherKey)),
            "Rejected saves leave the stored item intact and create no item rows");
    }

    private static void TestSqlServerContentLimits(SqlServerVaultStorage oStorage, User[] oRecipients,
        User oPrimary, X509Certificate2 oCertificate)
    {
        // Verify real encryption and decryption at the server's empty and maximum content boundaries.
        foreach (ContentEncryptionSuite nSuite in Enum.GetValues<ContentEncryptionSuite>())
        {
            foreach (var (sType, nLength) in new[]
            {
                ("text", 0), ("text", Utilities.MaxItemSize), (".bin", Utilities.MaxCompressedItemSize)
            })
            {
                byte[] oPlainText = new byte[nLength];
                if (nLength != 0) oPlainText[0] = 1;
                Item oItem = new Item { Label = "SQL content boundary", ItemType = sType };
                Item oEncrypted = new Item { Label = oItem.Label, ItemType = sType };
                ItemCryptography.Encrypt(oEncrypted, oPlainText, oRecipients, nContentSuite: nSuite);
                SqlServerItemOperations.Save(oStorage, oItem, oEncrypted);
                Item oLoaded = DatabaseOperations.LoadItem(oItem.ItemId);
                Check(ItemCryptography.Decrypt(oLoaded,
                    oLoaded.Instances.Single(i => i.UserId == oPrimary.UserId), oCertificate)
                    .SequenceEqual(oPlainText),
                    "SQL Server round trips " + nSuite + " " + sType + " content at " + nLength + " bytes");
                DatabaseOperations.DeleteItem(oItem.ItemId);
            }
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

    private static void TestSqlServerValidation(SqlServerVaultStorage oStorage, User oUser)
    {
        DatabaseOperations.SaveItem(new Item { Label = "Schema validation", ItemType = "text",
            ModifiedBy = oUser.UserId }, [3], new[] { oUser });
        using CryptureEntities oContext = new CryptureEntities();
        long nItemId = oContext.Items.Single().ItemId;
        byte[] oCipherText = DatabaseOperations.LoadItem(nItemId).Cipher.CipherText;
        string sEscrowLabel = oStorage.Escrow.Label;
        using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
        oConnection.Open();
        using SqlCommand oCommand = oConnection.CreateCommand();
        try
        {
            // Unsupported schemas must be rejected without changing stored data or certificate affiliations.
            foreach (int nVersion in new[] { 0, 1, 2, 3, 4, 5, 6, 8 })
            {
                oCommand.CommandText = "UPDATE [dbo].[CryptureVault] SET [SchemaVersion] = @version WHERE [Id] = 1";
                oCommand.Parameters.AddWithValue("@version", nVersion);
                oCommand.ExecuteNonQuery();
                oCommand.Parameters.Clear();
                bool bRejected = false;
                try { oStorage.Validate(); }
                catch (InvalidDataException) { bRejected = true; }
                Check(bRejected, "Opening an unsupported SQL Server schema is rejected: " + nVersion);
                oCommand.CommandText = "SELECT [SchemaVersion] FROM [dbo].[CryptureVault] WHERE [Id] = 1";
                Check((int)oCommand.ExecuteScalar() == nVersion &&
                    oContext.Users.AsNoTracking().Single().Sid == oUser.Sid &&
                    DatabaseOperations.LoadItem(nItemId).Cipher.CipherText.SequenceEqual(oCipherText),
                    "Rejected SQL Server opens preserve the schema, affiliations, and encrypted content");
            }
        }
        finally
        {
            oCommand.CommandText = "UPDATE [dbo].[CryptureVault] SET [SchemaVersion] = 7 WHERE [Id] = 1";
            oCommand.Parameters.Clear();
            oCommand.ExecuteNonQuery();
        }

        // Concurrent opens read the same saved escrow policy without requiring a schema writer.
        Task.WaitAll(Enumerable.Range(0, 2).Select(_ => Task.Run(() => oStorage.Validate())).ToArray());
        Check(oStorage.Escrow.Label == sEscrowLabel &&
            oContext.Users.AsNoTracking().Single().Sid == oUser.Sid &&
            DatabaseOperations.LoadItem(nItemId).Cipher.CipherText.SequenceEqual(oCipherText),
            "Concurrent SQL Server opens preserve escrow, affiliations, and encrypted content");
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
                    CipherText = [1], CipherVector = new byte[12], CipherParams = ItemCryptography.RecoveryFormat,
                    ContentSuite = 1, AuthenticationTag = new byte[16],
                    ProtectedKey = TestRecoveryEnvelope(sEscrowDescriptor), Signature = new byte[32]
                }
            };
            oEncrypted.Instances.Add(new Instance { UserId = oPrimary.UserId, CipherKey = new byte[8],
                CipherParams = ItemCryptography.RecoveryFormat, Signature = new byte[32] });
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

            // Certificate-only protection must not satisfy escrow with an unused recovery envelope.
            Item oIgnoredEscrow = new Item { Label = "Ignored Windows escrow", ItemType = "text" };
            Item oCertificateOnly = new Item { Label = oIgnoredEscrow.Label, ItemType = oIgnoredEscrow.ItemType };
            ItemCryptography.Encrypt(oCertificateOnly, [2], new[] { oPrimary });
            oCertificateOnly.Cipher.ProtectedKey = TestRecoveryEnvelope(sEscrowDescriptor);
            try
            {
                SqlServerItemOperations.Save(oStorage, oIgnoredEscrow, oCertificateOnly);
                throw new Exception("SQL Server accepted a recovery envelope ignored by the item format.");
            }
            catch (SqlException oError) when (oError.Number == 50026)
            {
                Check(oIgnoredEscrow.ItemId == 0,
                    "SQL Server rejects Windows escrow data ignored by certificate-only protection");
            }

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
                    Cipher = new Cipher { CipherText = [1], CipherVector = new byte[12], CipherParams = 2,
                        ContentSuite = 1, AuthenticationTag = new byte[16],
                        ProtectionDescriptor = "SID=" + WindowsIdentity.GetCurrent().User.Value,
                        ProtectedKey = [1], Signature = new byte[32] }
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
                CipherText = [1], CipherVector = new byte[12], CipherParams = ItemCryptography.RecoveryFormat,
                ContentSuite = 1, AuthenticationTag = new byte[16],
                ProtectedKey = oRecoveryEnvelope, Signature = new byte[32]
            }
        };
        oRecoveryEncrypted.Instances.Add(new Instance { UserId = oStorage.Escrow.CertificateUserId.Value,
            CipherKey = new byte[8], CipherParams = ItemCryptography.RecoveryFormat, Signature = new byte[32] });
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
                CipherText = [1], CipherVector = new byte[12], CipherParams = ItemCryptography.RecoveryFormat,
                ContentSuite = 1, AuthenticationTag = new byte[16], ProtectionDescriptor = "SID=S-1-5-32-545",
                ProtectedKey = TestRecoveryEnvelope("SID=S-1-5-32-545"), Signature = new byte[32]
            }
        };
        oGroupEncrypted.Instances.Add(new Instance { UserId = oStorage.Escrow.CertificateUserId.Value,
            CipherKey = new byte[8], CipherParams = ItemCryptography.RecoveryFormat, Signature = new byte[32] });
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
            oCommand.CommandText = "SELECT COUNT(*) FROM [dbo].[EnrolledUser] WHERE [IsEscrow] = 1";
            Check((int)oCommand.ExecuteScalar() == 1, "The domain role can read the derived escrow affiliation");
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
                "SELECT TOP (1) [UserId], CONVERT(binary(8), 0x01), 3, CONVERT(binary(32), 0x01) " +
                "FROM [dbo].[User] WHERE [Sid] = @sid; " +
                "DECLARE @nonce binary(12) = 0x01, @tag binary(16) = 0x01; " +
                "DECLARE @newId bigint = 0; EXEC [dbo].[SaveItem] @itemId = @newId OUTPUT, " +
                "@expectedRowVersion = NULL, @label = N'Forged modifier', @itemType = N'text', " +
                "@modifiedBy = @otherId, @cipherText = 0x01, @cipherVector = @nonce, @cipherParams = 3, " +
                "@contentSuite = 1, @authenticationTag = @tag, @protectionDescriptor = NULL, " +
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
                "SELECT TOP (1) [UserId], CONVERT(binary(8), 0x01), 3, CONVERT(binary(32), 0x01) " +
                "FROM [dbo].[User] WHERE [Sid] = @sid; " +
                "DECLARE @nonce binary(12) = 0x01, @tag binary(16) = 0x01; " +
                "DECLARE @newId bigint = 0; EXEC [dbo].[SaveItem] @itemId = @newId OUTPUT, " +
                "@expectedRowVersion = NULL, @label = N'Role item', @itemType = N'text', " +
                "@modifiedBy = NULL, @cipherText = 0x01, @cipherVector = @nonce, @cipherParams = 3, " +
                "@contentSuite = 1, @authenticationTag = @tag, @protectionDescriptor = NULL, " +
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
