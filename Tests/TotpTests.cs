using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

    private static void TestTotpVault(string sDirectory)
    {
        string sConnection = CryptureEntities.ConnectionString;
        string sVault = Path.Combine(sDirectory, "totp.cryptdb");
        string sUri = "otpauth://totp/Service:totp-seed%40example.com?secret=" + RfcTotpSecret + "&digits=8";
        byte[] oPayload = Encoding.UTF8.GetBytes(sUri);
        byte[] oPlain = null;
        ItemEditor oEditor = null;
        try
        {
            // Verify encrypted persistence without relying on the import or save dialog flow.
            DatabaseOperations.CreateDatabase(sVault,
                File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
            CryptureEntities.DatabasePath = sVault;
            DatabaseOperations.SaveItem(new Item { Label = "Authenticator Regression Fixture", ItemType = "totp" },
                oPayload, null, PrincipalProtection.LocalUserDescriptor);
            Item oStored;
            using (CryptureEntities oContext = new CryptureEntities())
                oStored = DatabaseOperations.LoadItem(oContext.Items.Single().ItemId);
            oPlain = ItemCryptography.Decrypt(oStored);
            using (TotpSecret oReloaded = TotpSecret.Parse(Encoding.UTF8.GetString(oPlain)))
                Check(oReloaded.GetBase32() == RfcTotpSecret && oReloaded.Digits == 8 &&
                    oReloaded.Account == "totp-seed@example.com",
                    "Vault saves preserve the encrypted TOTP seed and settings");
            string sStoredBytes = Encoding.ASCII.GetString(File.ReadAllBytes(sVault));
            Check(!sStoredBytes.Contains(RfcTotpSecret) && !sStoredBytes.Contains("otpauth://") &&
                !sStoredBytes.Contains("totp-seed@example.com"),
                "The Vault contains no plaintext TOTP seed, setup URI, or account");

            // Locking must dispose the active key and erase all authenticator plaintext.
            oEditor = new ItemEditor(oStored);
            oEditor.SetEditingControls(true);
            TotpPanel oPanel = (TotpPanel)oEditor.FindName("oTotpPanel");
            oPanel.LoadUri(Encoding.UTF8.GetString(oPlain));
            TotpSecret oCached = (TotpSecret)typeof(TotpPanel).GetField("oSecret",
                BindingFlags.Instance | BindingFlags.NonPublic).GetValue(oPanel);
            Check(oCached.GetBase32() == RfcTotpSecret, "Unlock loads the active TOTP key before cleanup");
            typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                .SetValue(oEditor, false);
            typeof(ItemEditor).GetMethod("oLockItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oEditor, new object[] { null, null });
            TextBox oCode = (TextBox)oPanel.FindName("oCurrentCode");
            Check(oCode.Text.Length == 0 && ((TextBox)oPanel.FindName("oSecretInput")).Text.Length == 0,
                "Lock clears the TOTP seed and code");
            Reject(() => oCached.GetCode(DateTimeOffset.UtcNow), "Lock disposes the live TOTP key");
            oPanel.RefreshCode();
            Check(oCode.Text.Length == 0, "An inactive authenticator cannot recreate a code after locking");
        }
        finally
        {
            oEditor?.Close();
            CryptographicOperations.ZeroMemory(oPayload);
            if (oPlain != null) CryptographicOperations.ZeroMemory(oPlain);
            CryptureEntities.ConnectionString = sConnection;
        }
    }
}
