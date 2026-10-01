using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Reflection;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestRecentVaultHistory(ItemBrowser oBrowser, string sDatabase, string sDirectory)
    {
        Crypture.Properties.Settings oSettings = Crypture.Properties.Settings.Default;
        StringCollection oOriginal = oSettings.RecentVaults;
        MethodInfo oLoadVault = typeof(ItemBrowser).GetMethod("LoadDatabase",
            BindingFlags.Instance | BindingFlags.NonPublic);

        try
        {
            oSettings.RecentVaults = new StringCollection();

            // Successful opens update history; path aliases deduplicate and reopening promotes to the front.
            oLoadVault.Invoke(oBrowser, new object[] { sDatabase, true });
            Check(oSettings.RecentVaults.Count == 1 && oSettings.RecentVaults[0] == Path.GetFullPath(sDatabase),
                "Opening a Vault adds its absolute path to recent history");
            string sSecond = Path.Combine(sDirectory, "Recent_Vault \u00e9.cryptdb");
            DatabaseOperations.CreateDatabase(sSecond, File.ReadAllText(Path.Combine(AppContext.BaseDirectory,
                "SQLite.sql")));
            Check((bool)oLoadVault.Invoke(oBrowser, new object[] { sSecond, true }) &&
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
        }
        finally
        {
            oLoadVault.Invoke(oBrowser, new object[] { sDatabase, true });
            oSettings.RecentVaults = oOriginal;
            oSettings.Save();
        }
    }
}
