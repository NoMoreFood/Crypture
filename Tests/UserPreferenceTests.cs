using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Reflection;
using Crypture;
using Microsoft.Data.Sqlite;

internal static partial class RegressionTests
{
    private sealed class UserPreferenceSnapshot : IDisposable
    {
        private readonly Dictionary<string, byte[]> oFiles;

        internal UserPreferenceSnapshot()
        {
            // Preserve only this test executable's configuration, leaving Crypture's profile untouched.
            if (Assembly.GetEntryAssembly().GetName().Name != "Crypture.Tests")
                throw new InvalidOperationException("User preference tests require the test executable.");
            oFiles = new[] { ConfigurationUserLevel.PerUserRoaming, ConfigurationUserLevel.PerUserRoamingAndLocal }
                .Select(nLevel => ConfigurationManager.OpenExeConfiguration(nLevel).FilePath)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(s => s,
                    s => File.Exists(s) ? File.ReadAllBytes(s) : null);
            Crypture.Properties.Settings.Default.Reset();
        }

        public void Dispose()
        {
            foreach (var oFile in oFiles)
            {
                if (oFile.Value == null)
                {
                    if (File.Exists(oFile.Key)) File.Delete(oFile.Key);
                }
                else File.WriteAllBytes(oFile.Key, oFile.Value);
            }
        }
    }

    private static bool VaultHasNoPreferences(string sPath)
    {
        using SqliteConnection oConnection = new(new SqliteConnectionStringBuilder
            { DataSource = sPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ConnectionString);
        oConnection.Open();
        using SqliteCommand oCommand = new("SELECT COUNT(*) FROM sqlite_master " +
            "WHERE type = 'table' AND name = 'PasswordGeneratorSettings'", oConnection);
        return (long)oCommand.ExecuteScalar() == 0;
    }

    private static void TestUserPreferences()
    {
        string sPreviousConnection = CryptureEntities.ConnectionString;
        var oSettings = Crypture.Properties.Settings.Default;
        try
        {
            // An old local profile value must not shadow a saved roaming preference.
            Configuration oLocal = ConfigurationManager.OpenExeConfiguration(
                ConfigurationUserLevel.PerUserRoamingAndLocal);
            ClientSettingsSection oLocalSettings = (ClientSettingsSection)oLocal.GetSection(
                "userSettings/Crypture.Properties.Settings");
            System.Xml.XmlDocument oXml = new System.Xml.XmlDocument();
            System.Xml.XmlElement oValue = oXml.CreateElement("value");
            oValue.InnerText = "Obsolete local theme";
            oLocalSettings.Settings.Get("ThemeMode").Value.ValueXml = oValue;
            oLocal.Save();

            // Persist a realistic mixture of scalar, collection, and generator preferences without a Vault.
            CryptureEntities.ConnectionString = "";
            oSettings.ThemeMode = "Dark";
            oSettings.SecretFontFamily = "Cascadia Mono";
            oSettings.LastVault = "C:\\Private Vault.cryptdb";
            oSettings.RecentVaults = new StringCollection { oSettings.LastVault };
            oSettings.AllowSelfSignedCertificates = true;
            oSettings.PerformCertificateRevocationCheck = false;
            oSettings.Save();
            PasswordOptions.SavePreferences(new PasswordOptions
                { MinimumLength = 28, MaximumLength = 35, ExcludedCharacters = "\"'&<>" });
            var oReloaded = new Crypture.Properties.Settings();
            Check(oReloaded.ThemeMode == "Dark" && oReloaded.SecretFontFamily == "Cascadia Mono" &&
                oReloaded.LastVault == oSettings.LastVault &&
                oReloaded.RecentVaults.Cast<string>().SequenceEqual(oSettings.RecentVaults.Cast<string>()) &&
                oReloaded.AllowSelfSignedCertificates && !oReloaded.PerformCertificateRevocationCheck &&
                oReloaded.PasswordGeneratorOptions.MaximumLength == 35 &&
                oReloaded.PasswordGeneratorOptions.ExcludedCharacters == "\"'&<>",
                "User preferences persist together without a Vault and retain quoted character lists");
            string sPath = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.PerUserRoaming).FilePath;
            string sRoaming = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)) +
                Path.DirectorySeparatorChar;
            Check(sPath.StartsWith(sRoaming, StringComparison.OrdinalIgnoreCase) &&
                File.ReadAllText(sPath).Contains("PasswordGeneratorOptions"),
                "Generator preferences are written to user.config under APPDATA");
            Check(oReloaded.Properties.Cast<SettingsProperty>().Where(p =>
                p.Attributes[typeof(UserScopedSettingAttribute)] is UserScopedSettingAttribute).All(p =>
                p.Attributes[typeof(SettingsManageabilityAttribute)] is SettingsManageabilityAttribute oAttribute &&
                oAttribute.Manageability == SettingsManageability.Roaming),
                "Every user preference uses roaming profile storage");

            // Saving an unrelated preference must preserve the generator selection on disk.
            oSettings.ThemeMode = "Light";
            oSettings.Save();
            Check(PasswordOptions.LoadPreferences().MaximumLength == 35,
                "An unrelated settings save preserves the user's generator selection");
        }
        finally
        {
            oSettings.Reset();
            CryptureEntities.ConnectionString = sPreviousConnection;
        }
    }
}
