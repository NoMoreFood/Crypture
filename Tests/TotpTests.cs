using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Crypture;

internal static partial class RegressionTests
{
    private const string RfcTotpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    private static void TestTotpAlgorithms(X509Certificate2 oCertificate)
    {
        // RFC 6238 Appendix B covers all supported algorithms, leading zeroes, and dates beyond 2038.
        long[] oTimes = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];
        string[][] oExpected =
        [
            ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
            ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
            ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"]
        ];
        string[] oAlgorithms = ["SHA1", "SHA256", "SHA512"];
        string[] oSeeds =
        [
            RfcTotpSecret,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" +
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"
        ];
        for (int nAlgorithm = 0; nAlgorithm < oAlgorithms.Length; nAlgorithm++)
        {
            using TotpSecret oSecret = new TotpSecret(oSeeds[nAlgorithm],
                sAlgorithm: oAlgorithms[nAlgorithm], nDigits: 8);
            for (int nTime = 0; nTime < oTimes.Length; nTime++)
                Check(oSecret.GetCode(DateTimeOffset.FromUnixTimeSeconds(oTimes[nTime])) == oExpected[nAlgorithm][nTime],
                    "RFC 6238 " + oAlgorithms[nAlgorithm] + " vector at " + oTimes[nTime]);
            string sGenerated = TotpSecret.Generate(oAlgorithms[nAlgorithm]);
            using TotpSecret oGenerated = new TotpSecret(sGenerated, sAlgorithm: oAlgorithms[nAlgorithm]);
            Check(sGenerated.Length == new[] { 32, 52, 103 }[nAlgorithm] &&
                sGenerated != TotpSecret.Generate(oAlgorithms[nAlgorithm]),
                "Generate an independent " + oAlgorithms[nAlgorithm] + " seed");
        }
        using TotpSecret oDefault = new TotpSecret(RfcTotpSecret);
        Check(oDefault.GetCode(DateTimeOffset.FromUnixTimeSeconds(59)) == "287082" && oDefault.Period == 30,
            "TOTP defaults to 6 digits and 30 seconds");
        Check(oDefault.GetCode(DateTimeOffset.FromUnixTimeSeconds(59).ToOffset(TimeSpan.FromHours(-4))) == "287082",
            "TOTP codes use UTC regardless of the local time zone");
        Check(oDefault.SecondsRemaining(DateTimeOffset.FromUnixTimeMilliseconds(29999)) == 0.001 &&
            oDefault.SecondsRemaining(DateTimeOffset.FromUnixTimeSeconds(30)) == 30,
            "The countdown resets precisely on the rotation boundary");
        using TotpSecret oLongCounter = new TotpSecret(RfcTotpSecret, nDigits: 8, nPeriod: 1);
        Check(oLongCounter.GetCode(DateTimeOffset.FromUnixTimeSeconds(20000000000)) == "04468884",
            "TOTP counters retain all 64 bits");
        Reject(() => oDefault.GetCode(DateTimeOffset.FromUnixTimeSeconds(-1)), "Reject TOTP times before the epoch");
        using TotpSecret oSpaced = TotpSecret.Parse("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq");
        Check(oSpaced.GetBase32() == RfcTotpSecret, "Accept grouped lowercase Base32 secrets");
        using TotpSecret oPadded = TotpSecret.Parse(oSeeds[1] + "====");
        Check(oPadded.GetBase32() == oSeeds[1], "Accept valid optional Base32 padding and save without padding");
        using TotpSecret oUri = TotpSecret.Parse("otpauth://totp/Acme%20%26%20Co%3Aalice%2Bops%40example.com?secret=" +
            oSeeds[1] + "&issuer=Acme%20%26%20Co&algorithm=SHA256&digits=8&period=60");
        using TotpSecret oRoundTrip = TotpSecret.Parse(oUri.ToUri());
        Check(oRoundTrip.Issuer == "Acme & Co" && oRoundTrip.Account == "alice+ops@example.com" &&
            oRoundTrip.Algorithm == "SHA256" && oRoundTrip.Digits == 8 && oRoundTrip.Period == 60 &&
            oRoundTrip.GetBase32() == oSeeds[1],
            "Setup links round-trip the encrypted seed and all authenticator settings");
        foreach (string sInvalid in new[]
        {
            "", "JBSWY3DP0HPK3PXP", "AAAA", RfcTotpSecret + "=", new string('A', 17) + "B",
            "otpauth://hotp/Account?secret=" + RfcTotpSecret + "&counter=1",
            "otpauth://totp/Account?secret=" + RfcTotpSecret + "&secret=" + RfcTotpSecret,
            "otpauth://totp/Service:Account?secret=" + RfcTotpSecret + "&issuer=Other",
            "otpauth://totp/Account?secret=" + RfcTotpSecret + "&digits=7",
            "otpauth://totp/Account?secret=" + RfcTotpSecret + "&period=0",
            "otpauth://totp/Account?secret=" + RfcTotpSecret + "&algorithm=MD5",
            "otpauth://totp/Account?issuer=Service"
        }) Reject(() => { using TotpSecret oRejected = TotpSecret.Parse(sInvalid); }, "Reject invalid TOTP setup");

        // Both existing encryption models protect the same authenticator payload and authenticate its item type.
        byte[] oPayload = Encoding.UTF8.GetBytes(oUri.ToUri());
        foreach (bool bWindows in new[] { false, true })
        {
            User oUser = new User { UserId = 1, Certificate = oCertificate.RawData };
            Item oItem = new Item { Label = "Authenticator", ItemType = "totp" };
            ItemCryptography.Encrypt(oItem, oPayload, bWindows ? null : new[] { oUser },
                bWindows ? PrincipalProtection.LocalUserDescriptor : null);
            byte[] oPlain = bWindows ? ItemCryptography.Decrypt(oItem) :
                ItemCryptography.Decrypt(oItem, oItem.Instances.Single(), oCertificate);
            Check(oPlain.SequenceEqual(oPayload) && !oItem.Cipher.CipherText.SequenceEqual(oPayload),
                "Encrypt and decrypt a TOTP seed with " + (bWindows ? "Windows protection" : "certificate protection"));
            CryptographicOperations.ZeroMemory(oPlain);
            oItem.ItemType = "text";
            Reject(() => ItemCryptography.Decrypt(oItem, bWindows ? null : oItem.Instances.Single(),
                bWindows ? null : oCertificate), "Reject altered TOTP item metadata");
        }
        CryptographicOperations.ZeroMemory(oPayload);
        TotpSecret oDisposed = new TotpSecret(RfcTotpSecret);
        byte[] oKey = (byte[])typeof(TotpSecret).GetField("oKey", BindingFlags.Instance | BindingFlags.NonPublic)
            .GetValue(oDisposed);
        oDisposed.Dispose();
        Check(oKey.All(b => b == 0), "Disposing a TOTP seed clears its decoded key bytes");
        Reject(() => oDisposed.GetCode(DateTimeOffset.UtcNow), "A disposed TOTP seed cannot generate codes");
    }

    private static void TestTotpWindow(ItemBrowser oBrowser)
    {
        string sLabel = "Authenticator Regression Fixture";
        ItemEditor oEditor = null;
        TextBox oSearch = (TextBox)oBrowser.FindName("oSearchTextBox");
        try
        {
            // Follow the real new-item, import, encrypted save, unlock, rotate, and lock flow.
            oEditor = new ItemEditor();
            ShowTestWindow(oEditor);
            ((TextBox)oEditor.FindName("oItemLabel")).Text = sLabel;
            ((ComboBox)oEditor.FindName("oItemTypeSelector")).SelectedIndex = 1;
            TotpPanel oPanel = (TotpPanel)oEditor.FindName("oTotpPanel");
            DateTimeOffset oNow = DateTimeOffset.FromUnixTimeSeconds(1111111109);
            oPanel.Clock = () => oNow;
            ((TextBox)oPanel.FindName("oImportInput")).Text =
                "otpauth://totp/Service:totp-seed%40example.com?secret=" + RfcTotpSecret + "&digits=8";
            typeof(TotpPanel).GetMethod("oImport_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oPanel, new object[] { null, null });
            TextBox oCode = (TextBox)oPanel.FindName("oCurrentCode");
            Check(oEditor.ThisItem.ItemType == "totp" && oPanel.Visibility == Visibility.Visible &&
                ((TextBox)oEditor.FindName("oItemData")).Visibility == Visibility.Collapsed &&
                ((Button)oEditor.FindName("oDownloadPanel")).Visibility == Visibility.Collapsed &&
                oCode.Text == "07081804",
                "New TOTP items show authenticator tooling instead of text or file content");
            Check(((TextBox)oPanel.FindName("oIssuer")).Text == "Service" &&
                ((TextBox)oPanel.FindName("oAccount")).Text == "totp-seed@example.com" && oCode.IsReadOnly &&
                ((Button)oPanel.FindName("oCopyCode")).IsEnabled,
                "Import configures the account and enables current code copying");
            FieldInfo oChanged = typeof(ItemEditor).GetField("bHasChanges",
                BindingFlags.Instance | BindingFlags.NonPublic);
            oChanged.SetValue(oEditor, false);
            oNow = DateTimeOffset.FromUnixTimeSeconds(1111111110);
            PumpUntil(() => oCode.Text == "14050471");
            Check(!(bool)oChanged.GetValue(oEditor) && ((TextBlock)oPanel.FindName("oRemainingText"))
                .Text.Contains("30 Seconds"), "The timer rotates at the boundary without creating unsaved changes");
            oNow = DateTimeOffset.FromUnixTimeSeconds(2000000000);
            PumpUntil(() => oCode.Text == "69279037");
            Check(true, "TOTP recovers directly from the current time after a sleep or clock jump");
            oNow = DateTimeOffset.FromUnixTimeSeconds(-1);
            oPanel.RefreshCode();
            Check(oCode.Text.Length == 0 && !((Button)oPanel.FindName("oCopyCode")).IsEnabled,
                "An invalid clock removes the stale code and disables copying");
            oNow = DateTimeOffset.FromUnixTimeSeconds(59);
            oPanel.RefreshCode();
            Check(oCode.Text == "94287082" && ((TextBlock)oPanel.FindName("oValidationMessage")).Text.Length == 0,
                "A corrected clock restores the current code and clears the clock error");
            ((TextBox)oPanel.FindName("oSecretInput")).Text = "invalid";
            Check(oCode.Text.Length == 0 && !((Button)oPanel.FindName("oCopyCode")).IsEnabled,
                "Invalid seed edits remove stale codes");
            Reject(() => oPanel.ReadUri(), "Invalid authenticator settings cannot be serialized for saving");
            ((TextBox)oPanel.FindName("oImportInput")).Text = RfcTotpSecret.ToLowerInvariant();
            typeof(TotpPanel).GetMethod("oImport_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oPanel, new object[] { null, null });
            Check(((TextBox)oPanel.FindName("oIssuer")).Text == "Service" && oCode.Text == "94287082",
                "Importing a raw Base32 seed preserves the account and chosen algorithm settings");
            typeof(ItemEditor).GetMethod("oSaveItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oEditor, new object[] { null, null });
            PumpUntil(() => (bool)typeof(ItemEditor).GetField("bCompleted", BindingFlags.Instance | BindingFlags.NonPublic)
                .GetValue(oEditor));
            Check(oCode.Text.Length == 0 && ((TextBox)oPanel.FindName("oSecretInput")).Text.Length == 0,
                "Saving and closing clears authenticator plaintext");
            Item oStored;
            using (CryptureEntities oContext = new CryptureEntities())
                oStored = oContext.Items.Single(i => i.Label == sLabel);
            byte[] oPlain = ItemCryptography.Decrypt(DatabaseOperations.LoadItem(oStored.ItemId));
            using (TotpSecret oReloaded = TotpSecret.Parse(Encoding.UTF8.GetString(oPlain)))
                Check(oReloaded.GetBase32() == RfcTotpSecret && oReloaded.Digits == 8 &&
                    oReloaded.Account == "totp-seed@example.com",
                    "Vault saves preserve the encrypted TOTP seed and settings");
            CryptographicOperations.ZeroMemory(oPlain);
            string sVault = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(
                CryptureEntities.ConnectionString).DataSource;
            string sStoredBytes = Encoding.ASCII.GetString(File.ReadAllBytes(sVault));
            Check(!sStoredBytes.Contains(RfcTotpSecret) && !sStoredBytes.Contains("otpauth://") &&
                !sStoredBytes.Contains("totp-seed@example.com"),
                "The Vault contains no plaintext TOTP seed, setup URI, or account");
            typeof(ItemBrowser).GetMethod("RefreshData", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oBrowser, null);
            oSearch.Text = "TOTP";
            Check(((DataGrid)oBrowser.FindName("oItemDataGrid")).Items.Cast<Item>().Any(i => i.ItemId == oStored.ItemId) &&
                oStored.ItemTypeDisplay == "TOTP", "Vault items identify and search TOTP authenticator entries");
            oSearch.Clear();
            oEditor = new ItemEditor(oStored);
            oPanel = (TotpPanel)oEditor.FindName("oTotpPanel");
            oCode = (TextBox)oPanel.FindName("oCurrentCode");
            Check(oPanel.Visibility == Visibility.Collapsed && oCode.Text.Length == 0 &&
                ((TextBox)oPanel.FindName("oSecretInput")).Text.Length == 0,
                "Reopened authenticators keep seeds and codes locked");
            ShowTestWindow(oEditor);
            typeof(ItemEditor).GetMethod("oLoadItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oEditor, new object[] { null, null });
            PumpUntil(() => !(bool)typeof(ItemEditor).GetField("bBusy", BindingFlags.Instance | BindingFlags.NonPublic)
                .GetValue(oEditor));
            Check(oCode.Text.Length == 8 && !((Expander)oPanel.FindName("oSetup")).IsExpanded &&
                !((System.Windows.Controls.Ribbon.RibbonButton)oEditor.FindName("oGeneratePasswordButton")).IsEnabled,
                "Unlock displays rotating codes while keeping setup collapsed and password insertion disabled");
            TotpSecret oCached = (TotpSecret)typeof(TotpPanel).GetField("oSecret",
                BindingFlags.Instance | BindingFlags.NonPublic)
                .GetValue(oPanel);
            oChanged.SetValue(oEditor, false);
            typeof(ItemEditor).GetMethod("oLockItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oEditor, new object[] { null, null });
            Check(oCode.Text.Length == 0 && ((TextBox)oPanel.FindName("oSecretInput")).Text.Length == 0 &&
                oPanel.Visibility == Visibility.Collapsed && !((Button)oPanel.FindName("oCopyCode")).IsEnabled,
                "Lock clears the seed and code, hides the panel, and disables copying");
            Reject(() => oCached.GetCode(DateTimeOffset.UtcNow), "Lock disposes the live TOTP key");
            oPanel.RefreshCode();
            Check(oCode.Text.Length == 0, "An inactive authenticator cannot recreate a code after locking");
        }
        finally
        {
            if (oEditor != null)
            {
                typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                    .SetValue(oEditor, false);
                oEditor.Close();
            }
            using (CryptureEntities oContext = new CryptureEntities())
            {
                oContext.Items.RemoveRange(oContext.Items.Where(i => i.Label == sLabel));
                oContext.SaveChanges();
            }
            oSearch.Clear();
            typeof(ItemBrowser).GetMethod("RefreshData", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oBrowser, null);
        }
    }
}
