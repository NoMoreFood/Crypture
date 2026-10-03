using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
            SqlServerVaultStorage oLoginStorage = new SqlServerVaultStorage(oLogin.ConnectionString);
            Check(new SqlConnectionStringBuilder(oLoginStorage.RecentConnection).Password.Length == 0,
                "Recent SQL Server Vaults never persist login passwords");

            // Exercise the same encrypted item and recipient operations used by the desktop editor.
            oStorage.Create();
            oStorage.Validate();
            Reject(() => oStorage.Create(), "SQL Server refuses to overwrite an existing Vault");
            CryptureEntities.Storage = oStorage;
            User[] oUsers = { new User { Certificate = oCert.RawData },
                new User { Certificate = oOtherCert.RawData } };
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
            DatabaseOperations.RemoveCertificate(oUsers[1].UserId);
            Check(DatabaseOperations.LoadItem(nItemId).Instances.Count == 1,
                "SQL Server removes an alternate certificate recipient");
            Reject(() => DatabaseOperations.RemoveCertificate(oUsers[0].UserId),
                "SQL Server blocks deletion of the last recipient");
            oStorage.Backup(sBackup);
            Check(File.Exists(sBackup) && new FileInfo(sBackup).Length > 0,
                "SQL Server creates a server-side backup");
            using (CryptureEntities oContext = new CryptureEntities())
            {
                oContext.Items.Remove(oContext.Items.Single());
                oContext.SaveChanges();
                Check(!oContext.Ciphers.Any() && !oContext.Instances.Any(),
                    "SQL Server cascades item deletion to encrypted records");
            }
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
}
