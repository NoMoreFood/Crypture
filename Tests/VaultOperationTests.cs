using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Crypture;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

internal static partial class RegressionTests
{
    private static void TestVaultOperations(string sDirectory)
    {
        IVaultStorage oPreviousStorage = CryptureEntities.Storage;
        var oSettings = Crypture.Properties.Settings.Default;
        string sLastVault = oSettings.LastVault;
        StringCollection oRecent = oSettings.RecentVaults;
        using RSA oKey = RSA.Create(2048);
        using X509Certificate2 oCert = Certificate(oKey, "Vault operations", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1));
        ItemBrowser oBrowser = null;
        try
        {
            SqliteVaultStorage oStorageA = new SqliteVaultStorage(Path.Combine(sDirectory, "switch-a.cryptdb"));
            SqliteVaultStorage oStorageB = new SqliteVaultStorage(Path.Combine(sDirectory, "switch-b.cryptdb"));
            foreach (var (oStorage, sLabel) in new[] { (oStorageA, "Vault A"), (oStorageB, "Vault B") })
            {
                oStorage.Create();
                CryptureEntities.Storage = oStorage;
                User oUser = new User { Certificate = oCert.RawData };
                using (CryptureEntities oContent = new CryptureEntities())
                {
                    oContent.Users.Add(oUser);
                    oContent.SaveChanges();
                }
                DatabaseOperations.SaveItem(new Item { Label = sLabel, ItemType = "text" },
                    Encoding.Unicode.GetBytes(sLabel), new[] { oUser });
            }

            // A failure after reading the candidate's rows must retain the original data and write target.
            oBrowser = new ItemBrowser
            {
                Width = 850, Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false,
                WindowStartupLocation = WindowStartupLocation.Manual
            };
            BindingFlags nFlags = BindingFlags.NonPublic | BindingFlags.Instance;
            ((CheckBox)oBrowser.FindName("oHideAccessible")).IsChecked = false;
            typeof(ItemBrowser).GetMethod("LoadVault", nFlags)
                .Invoke(oBrowser, new object[] { oStorageA, false, true });
            DataGrid oGrid = (DataGrid)oBrowser.FindName("oItemDataGrid");
            Item oOriginal = (Item)oGrid.Items[0];
            oGrid.SelectedItem = oOriginal;
            FaultingVaultStorage oFailing = new FaultingVaultStorage(oStorageB, true);
            MethodInfo oPrepare = typeof(ItemBrowser).GetMethod("PrepareVaultAsync",
                BindingFlags.NonPublic | BindingFlags.Static);
            Task oFailed = (Task)oPrepare.Invoke(null, new object[] { oFailing, false, CancellationToken.None });
            PumpUntil(() => oFailed.IsCompleted);
            Reject(() => oFailed.GetAwaiter().GetResult(), "A late Vault permission failure aborts the switch");
            Check(oFailing.RowsRead && ReferenceEquals(CryptureEntities.Storage, oStorageA) &&
                ReferenceEquals(oGrid.Items[0], oOriginal) && ReferenceEquals(oGrid.SelectedItem, oOriginal) &&
                oSettings.LastVault == oStorageA.DisplayName,
                "A failed switch preserves the active Vault, displayed rows, selection, and history");
            Check(DatabaseOperations.LoadItem(oOriginal.ItemId).Label == oOriginal.Label,
                "The retained displayed row still addresses its original Vault");

            // Cancellation after fetching candidate data must keep actions disabled until loading has stopped.
            oBrowser.Show();
            MethodInfo oLoadAsync = typeof(ItemBrowser).GetMethod("LoadVaultAsync", nFlags);
            foreach (double nFont in new[] { 12d, 18d })
            {
                oBrowser.FontSize = nFont;
                ((TextBlock)oBrowser.FindName("oDatabaseStatus")).FontSize = nFont;
                ((TextBlock)oBrowser.FindName("oCountStatus")).FontSize = nFont;
                ((Button)oBrowser.FindName("oCancelVaultOperationButton")).FontSize = nFont;
                FaultingVaultStorage oDelayed = new FaultingVaultStorage(oStorageB, false);
                Task<bool> oLoading = oBrowser.Dispatcher.InvokeAsync(() =>
                    (Task<bool>)oLoadAsync.Invoke(oBrowser, new object[] { oDelayed, false })).Task.Unwrap();
                PumpUntil(() => oDelayed.RowsRead);
                bool bRepainted = false;
                oBrowser.Dispatcher.BeginInvoke(new Action(() => bRepainted = true));
                PumpUntil(() => bRepainted);
                Button oCancel = (Button)oBrowser.FindName("oCancelVaultOperationButton");
                oBrowser.UpdateLayout();
                FrameworkElement oRoot = (FrameworkElement)oBrowser.Content;
                Rect oBounds = oCancel.TransformToAncestor(oRoot).TransformBounds(new Rect(oCancel.RenderSize));
                Check(!oLoading.IsCompleted && !oGrid.IsEnabled && oCancel.IsVisible &&
                    oBounds.Right <= oRoot.ActualWidth && oBounds.Bottom <= oRoot.ActualHeight,
                    "Loading repaints and keeps cancellation visible at minimum width, font " + nFont);
                Check(!(bool)typeof(ItemBrowser).GetMethod("LoadVault", nFlags)
                    .Invoke(oBrowser, new object[] { oStorageB, false, true }),
                    "A second Vault switch cannot race an in-flight load");
                oCancel.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                PumpUntil(() => oLoading.IsCompleted);
                Check(!oLoading.Result && oGrid.IsEnabled && !oCancel.IsVisible &&
                    ReferenceEquals(CryptureEntities.Storage, oStorageA) &&
                    ((Item)oGrid.Items[0]).Label == "Vault A" && oSettings.LastVault == oStorageA.DisplayName,
                    "Cancelled loading restores controls and retains the original Vault, font " + nFont);
            }
            TestBlockedSqlCancellation(oBrowser, oCert);

            // A stale deletion must not remove another process's committed revision.
            CryptureEntities.Storage = oStorageB;
            Item oStale = DatabaseOperations.LoadItem(1);
            User oRecipient;
            using (CryptureEntities oContent = new CryptureEntities()) oRecipient = oContent.Users.Single();
            DatabaseOperations.SaveItem(DatabaseOperations.LoadItem(1), Encoding.Unicode.GetBytes("New revision"),
                new[] { oRecipient });
            Reject(() => DatabaseOperations.DeleteItem(oStale), "SQLite rejects a stale item deletion");
            Item oCurrent = DatabaseOperations.LoadItem(1);
            Check(Encoding.Unicode.GetString(ItemCryptography.Decrypt(oCurrent, oCurrent.Instances.Single(), oCert))
                == "New revision", "A rejected SQLite deletion preserves the newer encrypted content");
            Task<Exception>[] oDeletes = Enumerable.Range(0, 2).Select(_ => Task.Run(() =>
            {
                try { DatabaseOperations.DeleteItem(oCurrent); return null; }
                catch (Exception oError) { return oError; }
            })).ToArray();
            Task.WaitAll(oDeletes);
            Check(oDeletes.Count(t => t.Result == null) == 1 &&
                oDeletes.Count(t => t.Result is InvalidOperationException) == 1,
                "Concurrent SQLite deletions accept one displayed revision and reject the other");

            // Released timestamp encodings must remain deletable after parsing the displayed revision.
            CryptureEntities.Storage = oStorageA;
            using (SqliteConnection oConnection = new SqliteConnection(oStorageA.ConnectionString))
            {
                oConnection.Open();
                using SqliteCommand oCommand = new SqliteCommand(
                    "UPDATE Item SET ModifiedDate = '2020-04-05 12:13:14.123' WHERE ItemId = 1", oConnection);
                oCommand.ExecuteNonQuery();
            }
            DatabaseOperations.DeleteItem(DatabaseOperations.LoadItem(1));
            using (CryptureEntities oContent = new CryptureEntities())
                Check(!oContent.Items.Any(), "SQLite revision checks accept released timestamp encodings");
        }
        finally
        {
            if (oBrowser != null)
            {
                oBrowser.Closing -= (CancelEventHandler)Delegate.CreateDelegate(
                    typeof(CancelEventHandler), oBrowser, "oItemBrowser_Closing");
                oBrowser.Close();
            }
            CryptureEntities.Storage = oPreviousStorage;
            oSettings.LastVault = sLastVault;
            oSettings.RecentVaults = oRecent;
            oSettings.Save();
        }
    }

    private static void TestBlockedSqlCancellation(ItemBrowser oBrowser, X509Certificate2 oCert)
    {
        string sServer = Environment.GetEnvironmentVariable("CRYPTURE_TEST_SQLSERVER");
        if (String.IsNullOrWhiteSpace(sServer)) return;
        SqlConnectionStringBuilder oBuilder = new SqlConnectionStringBuilder(sServer)
        {
            InitialCatalog = "CryptureCancellationTest_" + Guid.NewGuid().ToString("N"), Pooling = false
        };
        SqlServerVaultStorage oStorage = new SqlServerVaultStorage(oBuilder.ConnectionString)
        {
            EscrowChoice = SqlServerEscrowChoice.ForCertificate(oCert.RawData,
                WindowsIdentity.GetCurrent().User.Value, "Cancellation test escrow")
        };
        IVaultStorage oPrevious = CryptureEntities.Storage;
        try
        {
            oStorage.Create();
            using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
            oConnection.Open();
            using SqlTransaction oLock = oConnection.BeginTransaction();
            using (SqlCommand oCommand = new SqlCommand("SELECT * FROM Item WITH (TABLOCKX, HOLDLOCK)",
                oConnection, oLock)) oCommand.ExecuteNonQuery();
            Task<bool> oLoading = oBrowser.Dispatcher.InvokeAsync(() =>
                (Task<bool>)typeof(ItemBrowser).GetMethod("LoadVaultAsync",
                    BindingFlags.Instance | BindingFlags.NonPublic)
                    .Invoke(oBrowser, new object[] { oStorage, false })).Task.Unwrap();
            bool bRepainted = false;
            oBrowser.Dispatcher.BeginInvoke(new Action(() => bRepainted = true));
            PumpUntil(() => bRepainted);
            using SqlCommand oBlocked = new SqlCommand("SELECT COUNT(*) FROM sys.dm_exec_requests " +
                "WHERE blocking_session_id = @@SPID", oConnection, oLock);
            PumpUntil(() => (int)oBlocked.ExecuteScalar() > 0);
            Check(!oLoading.IsCompleted, "SQL loading leaves the dispatcher responsive while server work is pending");
            ((Button)oBrowser.FindName("oCancelVaultOperationButton"))
                .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            PumpUntil(() => oLoading.IsCompleted);
            Check(!oLoading.Result && ReferenceEquals(CryptureEntities.Storage, oPrevious),
                "SQL cancellation ends pending I/O without switching the active Vault");
            oLock.Rollback();
        }
        finally
        {
            SqlConnectionStringBuilder oMaster = new SqlConnectionStringBuilder(sServer) { InitialCatalog = "master" };
            using SqlConnection oConnection = new SqlConnection(oMaster.ConnectionString);
            oConnection.Open();
            using SqlCommand oDrop = new SqlCommand("DROP DATABASE [" + oBuilder.InitialCatalog + "]", oConnection);
            oDrop.ExecuteNonQuery();
        }
    }

    private sealed class FaultingVaultStorage(IVaultStorage oInner, bool bFailPermissions) : IVaultStorage
    {
        internal volatile bool RowsRead;
        public string ConnectionString => oInner.ConnectionString;
        public string DisplayName => oInner.DisplayName;
        public bool IsSqlServer => oInner.IsSqlServer;
        public bool SupportsCompact => oInner.SupportsCompact;
        public void Configure(DbContextOptionsBuilder oOptions) => oInner.Configure(oOptions);
        public void Create() => oInner.Create();
        public void Validate() => oInner.Validate();
        public void ReadSnapshot(CryptureEntities oContent, Action oRead) => oInner.ReadSnapshot(oContent, oRead);
        public DbConnection OpenHealthConnection() => oInner.OpenHealthConnection();
        public DbTransaction BeginHealthSnapshot(DbConnection oConnection) => oInner.BeginHealthSnapshot(oConnection);
        public void Backup(string sDestination) => oInner.Backup(sDestination);
        public void Compact() => oInner.Compact();

        public async Task<(bool CanEnroll, bool CanBackup)> ReadPermissionsAsync(CancellationToken oCancellation)
        {
            RowsRead = true;
            if (bFailPermissions) throw new IOException("The server disconnected during permission checks.");
            await Task.Delay(Timeout.Infinite, oCancellation);
            return (true, true);
        }
    }
}
