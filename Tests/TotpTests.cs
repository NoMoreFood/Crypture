using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Crypture;
using ZXing;
using ZXing.QrCode;

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
            TestTotpQrImport(sDirectory);

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

    private static BitmapSource CreateQrScreenshot(string[] oValues, bool bInverted = false, bool bTransparent = false)
    {
        const int nSize = 320, nMargin = 32;
        int nWidth = Math.Max(1, oValues.Length) * (nSize + nMargin) + nMargin;
        int nHeight = nSize + nMargin * 2;
        int nStride = nWidth * 4;
        byte[] oPixels = new byte[nStride * nHeight];
        if (!bTransparent) Array.Fill(oPixels, (byte)255);
        for (int nCode = 0; nCode < oValues.Length; nCode++)
        {
            var oCode = new QRCodeWriter().encode(oValues[nCode], BarcodeFormat.QR_CODE, nSize, nSize);
            for (int nY = 0; nY < nSize; nY++)
                for (int nX = 0; nX < nSize; nX++)
                {
                    int nPixel = (nY + nMargin) * nStride + (nX + nMargin + nCode * (nSize + nMargin)) * 4;
                    byte nValue = oCode[nX, nY] || bTransparent ? (byte)0 : (byte)255;
                    oPixels[nPixel] = oPixels[nPixel + 1] = oPixels[nPixel + 2] = nValue;
                    oPixels[nPixel + 3] = bTransparent && !oCode[nX, nY] ? (byte)0 : (byte)255;
                }
        }
        if (bInverted)
            for (int nPixel = 0; nPixel < oPixels.Length; nPixel += 4)
                for (int nChannel = 0; nChannel < 3; nChannel++)
                    oPixels[nPixel + nChannel] = (byte)(255 - oPixels[nPixel + nChannel]);
        BitmapSource oImage = BitmapSource.Create(nWidth, nHeight, 96, 96, PixelFormats.Bgra32, null,
            oPixels, nStride);
        oImage.Freeze();
        CryptographicOperations.ZeroMemory(oPixels);
        return oImage;
    }

    private static void TestTotpQrImport(string sDirectory)
    {
        string sUri = "otpauth://totp/Acme%20%26%20Co:alice%2Bops%40example.com?secret=" + RfcTotpSecret +
            "&issuer=Acme%20%26%20Co&algorithm=SHA256&digits=8&period=60";
        string sOther = "otpauth://totp/Other:second%40example.com?secret=" + RfcTotpSecret;
        BitmapSource oImage = CreateQrScreenshot([sUri]);
        TotpPanel oPanel = new TotpPanel { Clock = () => DateTimeOffset.FromUnixTimeSeconds(59) };
        int nChanges = 0;
        oPanel.SettingsChanged += (s, e) => nChanges++;
        Task Import(Func<TotpSecret> oReader) => oPanel.Dispatcher
            .InvokeAsync(() => oPanel.ImportQrCodeAsync(oReader)).Task.Unwrap();
        void Complete(Task oTask)
        {
            PumpUntil(() => oTask.IsCompleted);
            oTask.GetAwaiter().GetResult();
        }
        try
        {
            // Decode real image formats and screenshot variations rather than mocking QR results.
            BitmapEncoder[] oEncoders = [new PngBitmapEncoder(), new JpegBitmapEncoder(), new BmpBitmapEncoder(),
                new GifBitmapEncoder(), new TiffBitmapEncoder()];
            string[] oExtensions = ["png", "jpg", "bmp", "gif", "tiff"];
            for (int nFormat = 0; nFormat < oEncoders.Length; nFormat++)
            {
                string sPath = Path.Combine(sDirectory, "authenticator-qr." + oExtensions[nFormat]);
                oEncoders[nFormat].Frames.Add(BitmapFrame.Create(oImage));
                using (FileStream oOutput = File.Create(sPath)) oEncoders[nFormat].Save(oOutput);
                using TotpSecret oRead = TotpPanel.ReadQrFile(sPath);
                Check(oRead.GetBase32() == RfcTotpSecret && oRead.Issuer == "Acme & Co" &&
                    oRead.Account == "alice+ops@example.com" && oRead.Algorithm == "SHA256" &&
                    oRead.Digits == 8 && oRead.Period == 60,
                    "Import the complete authenticator setup from a " + oExtensions[nFormat] + " QR image");
                using FileStream oExclusive = File.Open(sPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                Check(oExclusive.Length > 0, "QR import releases the " + oExtensions[nFormat] + " image file");
            }
            foreach (BitmapSource oVariant in new BitmapSource[]
            {
                new FormatConvertedBitmap(oImage, PixelFormats.Gray8, null, 0),
                new TransformedBitmap(oImage, new RotateTransform(90)),
                CreateQrScreenshot([sUri], bInverted: true),
                CreateQrScreenshot([sUri], bTransparent: true),
                CreateQrScreenshot(["https://example.com/", sUri]),
                CreateQrScreenshot([sUri, sUri])
            })
            {
                using TotpSecret oRead = TotpPanel.ReadQrImage(oVariant);
                Check(oRead.ToUri() == sUri,
                    "Decode rotated, grayscale, transparent, inverted, or mixed QR screenshots");
            }

            // Image and file imports must update the same editor settings and mark the item as changed.
            oPanel.SetActive(true);
            Complete(Import(() => TotpPanel.ReadQrFile(Path.Combine(sDirectory, "authenticator-qr.png"))));
            using TotpSecret oExpected = TotpSecret.Parse(sUri);
            Check(oPanel.ReadUri() == sUri && nChanges == 1 &&
                ((TextBox)oPanel.FindName("oCurrentCode")).Text == oExpected.GetCode(oPanel.Clock()),
                "QR file import fills every setup field, refreshes the code, and raises one change notification");
            Complete(Import(() => TotpPanel.ReadQrImage(CreateQrScreenshot([sOther]))));
            Check(oPanel.ReadUri().Contains("second%40example.com") && nChanges == 2,
                "QR screenshot import uses the same authenticator editor flow");
            string sBefore = oPanel.ReadUri();
            foreach (string[] oInvalid in new string[][]
            {
                [], ["https://example.com/"], ["otpauth://hotp/Account?secret=" + RfcTotpSecret + "&counter=1"],
                ["otpauth://totp/Account?secret=AAAA"], [sUri, sOther]
            })
            {
                BitmapSource oInvalidImage = CreateQrScreenshot(oInvalid);
                Reject(() => Complete(Import(() => TotpPanel.ReadQrImage(oInvalidImage))),
                    "Reject absent, unrelated, unsupported, malformed, or ambiguous setup QR codes");
                Check(oPanel.ReadUri() == sBefore && nChanges == 2 &&
                    ((StackPanel)oPanel.FindName("oSetupFields")).IsEnabled &&
                    ((TextBlock)oPanel.FindName("oQrImportStatus")).Text.Length == 0,
                    "Failed QR imports preserve the existing authenticator and restore setup controls");
            }
            string sBroken = Path.Combine(sDirectory, "broken-qr.png");
            File.WriteAllBytes(sBroken, [1, 2, 3]);
            Reject(() => Complete(Import(() => TotpPanel.ReadQrFile(sBroken))), "Reject unreadable QR image files");
            Reject(() => { using TotpSecret oRead = TotpPanel.ReadQrImage(null); }, "Reject a missing clipboard image");
            string sLarge = Path.Combine(sDirectory, "large-qr.png");
            using (FileStream oLarge = File.Create(sLarge)) oLarge.SetLength(Utilities.MaxItemSize + 1L);
            Reject(() => { using TotpSecret oRead = TotpPanel.ReadQrFile(sLarge); }, "Reject oversized QR image files");

            // A pending background decode cannot overwrite another import or bring a locked seed back.
            using ManualResetEventSlim oStarted = new ManualResetEventSlim();
            using ManualResetEventSlim oRelease = new ManualResetEventSlim();
            TotpSecret oDecoded = null;
            int nUnexpectedReads = 0;
            Task oPending = Import(() =>
            {
                oStarted.Set();
                if (!oRelease.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("QR test was not released.");
                oDecoded = TotpPanel.ReadQrImage(oImage);
                return oDecoded;
            });
            try
            {
                PumpUntil(() => oStarted.IsSet);
                Complete(Import(() => { nUnexpectedReads++; return TotpPanel.ReadQrImage(oImage); }));
                Check(nUnexpectedReads == 0, "A second QR import cannot race the current setup operation");
                oPanel.Clear();
                Check(((TextBox)oPanel.FindName("oSecretInput")).Text.Length == 0,
                    "Locking clears the authenticator while QR decoding is still in progress");
                oPanel.SetActive(true);
                Complete(Import(() => TotpPanel.ReadQrImage(CreateQrScreenshot([sOther]))));
                sBefore = oPanel.ReadUri();
            }
            finally
            {
                oRelease.Set();
                PumpUntil(() => oPending.IsCompleted);
            }
            oPending.GetAwaiter().GetResult();
            Check(oPanel.ReadUri() == sBefore && nChanges == 3,
                "An import invalidated by locking cannot overwrite a later authenticator setup");
            Reject(() => oDecoded.GetCode(DateTimeOffset.UtcNow), "A discarded QR setup disposes its decoded seed");

            string sRenderDirectory = Environment.GetEnvironmentVariable("CRYPTURE_TEST_RENDER_DIR");
            if (!String.IsNullOrEmpty(sRenderDirectory))
            {
                Directory.CreateDirectory(sRenderDirectory);
                oPanel.Background = (Brush)oPanel.FindResource("Crypture.WindowBrush");
                oPanel.Foreground = (Brush)oPanel.FindResource("Crypture.TextBrush");
                oPanel.Measure(new Size(640, 1100));
                oPanel.Arrange(new Rect(0, 0, 640, 1100));
                oPanel.UpdateLayout();
                RenderTargetBitmap oRender = new RenderTargetBitmap(640, 1100, 96, 96, PixelFormats.Pbgra32);
                oRender.Render(oPanel);
                PngBitmapEncoder oEncoder = new PngBitmapEncoder();
                oEncoder.Frames.Add(BitmapFrame.Create(oRender));
                using FileStream oOutput = File.Create(Path.Combine(sRenderDirectory, "totp-qr-import.png"));
                oEncoder.Save(oOutput);
            }
        }
        finally
        {
            oPanel.Clear();
        }
    }
}
