using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestRecentVaultHistory(ItemBrowser oBrowser, string sDatabase, string sDirectory)
    {
        Crypture.Properties.Settings oSettings = Crypture.Properties.Settings.Default;
        StringCollection oOriginal = oSettings.RecentVaults;
        string sOriginalLastVault = oSettings.LastVault;
        MethodInfo oLoadVault = typeof(ItemBrowser).GetMethod("LoadDatabaseAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);

        bool LoadVault(string sPath)
        {
            Task<bool> oLoading = (Task<bool>)oLoadVault.Invoke(oBrowser, new object[] { sPath });
            PumpUntil(() => oLoading.IsCompleted);
            return oLoading.GetAwaiter().GetResult();
        }

        try
        {
            oSettings.RecentVaults = new StringCollection();

            // Successful opens update history; path aliases deduplicate and reopening promotes to the front.
            LoadVault(sDatabase);
            Check(oSettings.RecentVaults.Count == 1 && oSettings.RecentVaults[0] == Path.GetFullPath(sDatabase) &&
                oSettings.LastVault == Path.GetFullPath(sDatabase),
                "Opening a Vault adds its absolute path to recent history");
            string sSecond = Path.Combine(sDirectory, "Recent_Vault \u00e9.cryptdb");
            DatabaseOperations.CreateDatabase(sSecond, File.ReadAllText(Path.Combine(AppContext.BaseDirectory,
                "SQLite.sql")));
            Check(LoadVault(sSecond) &&
                oSettings.RecentVaults[0] == sSecond, "The newest successfully opened Vault is listed first");
            string sPreviousDirectory = Environment.CurrentDirectory;
            try
            {
                Environment.CurrentDirectory = sDirectory;
                oBrowser.RememberRecentVault(Path.GetRelativePath(sDirectory, sSecond).ToUpperInvariant());
            }
            finally
            {
                Environment.CurrentDirectory = sPreviousDirectory;
            }
            Check(oSettings.RecentVaults.Count == 2 && String.Equals(oSettings.RecentVaults[0], sSecond,
                StringComparison.OrdinalIgnoreCase), "Relative and differently cased Windows paths deduplicate");
            for (int nIndex = 0; nIndex < ItemBrowser.RecentVaultLimit + 2; nIndex++)
                oBrowser.RememberRecentVault(Path.Combine(sDirectory, $"Recent-{nIndex}.cryptdb"));
            Check(oSettings.RecentVaults.Count == ItemBrowser.RecentVaultLimit &&
                !oSettings.RecentVaults.Contains(sDatabase), "Recent Vaults evicts the oldest entries at its limit");
            oBrowser.RememberRecentVault(sDatabase);
            oBrowser.RememberRecentVault(sSecond);
            Crypture.Properties.Settings oSaved = new();
            oSaved.Reload();
            Check(oSaved.RecentVaults.Cast<string>().SequenceEqual(oSettings.RecentVaults.Cast<string>()),
                "Recent history persists immediately outside the Vault");
            typeof(ItemBrowser).GetMethod("oClearRecentVaults_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oBrowser, new object[] { null,
                    new System.Windows.RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent) });
            Check(oSettings.RecentVaults.Count == 0 && oSettings.LastVault == sSecond,
                "Clearing recent history preserves automatic reopening of the last Vault");
        }
        finally
        {
            LoadVault(sDatabase);
            oSettings.RecentVaults = oOriginal;
            oSettings.LastVault = sOriginalLastVault;
            oSettings.Save();
        }
    }
}
