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
using System.Windows.Controls.Ribbon;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestFidoEncryption(string sDirectory, X509Certificate2 oCert)
    {
        // Supply a synthetic authenticator output to exercise the actual encryption and persistence paths.
        byte[] oId = RandomNumberGenerator.GetBytes(64);
        byte[] oSalt = RandomNumberGenerator.GetBytes(FidoKeyProtection.SaltBytes);
        using FidoKeyAccess oAccess = new FidoKeyAccess(oId, oSalt,
            RandomNumberGenerator.GetBytes(FidoKeyProtection.SecretBytes));
        byte[] oPlain = Encoding.Unicode.GetBytes("A security key protects this secret. \u2603");
        User oUser = new User { UserId = 1, Certificate = oCert.RawData };
        foreach (ContentEncryptionSuite nSuite in Enum.GetValues<ContentEncryptionSuite>())
        {
            foreach (byte[] oInput in new[] { Array.Empty<byte>(), oPlain, RandomNumberGenerator.GetBytes(8193) })
            {
                Item oItem = new Item { Label = "FIDO2 item", ItemType = "text" };
                ItemCryptography.Encrypt(oItem, oInput, null, nContentSuite: nSuite, oFidoKey: oAccess);
                Check(oItem.Cipher.CipherParams == ItemCryptography.FidoFormat && oItem.Instances.Count == 0 &&
                    ItemCryptography.Decrypt(oItem, oFidoKey: oAccess).SequenceEqual(oInput),
                    nSuite + " FIDO2 key protection round trip for " + oInput.Length + " bytes");
                Reject(() => ItemCryptography.Decrypt(oItem), "FIDO2 item requires its key when recovery is absent");
                using FidoKeyAccess oWrongKey = new FidoKeyAccess(oId, oSalt,
                    RandomNumberGenerator.GetBytes(FidoKeyProtection.SecretBytes));
                Reject(() => ItemCryptography.Decrypt(oItem, oFidoKey: oWrongKey),
                    "A different security key secret cannot decrypt FIDO2 content");
            }

            Item oProtected = new Item { Label = "FIDO2 recovery item", ItemType = "text" };
            ItemCryptography.Encrypt(oProtected, oPlain, new[] { oUser },
                sRecoveryDescriptor: PrincipalProtection.LocalUserDescriptor,
                nContentSuite: nSuite, oFidoKey: oAccess);
            Instance oInstance = oProtected.Instances.Single();
            Check(ItemCryptography.Decrypt(oProtected, oFidoKey: oAccess).SequenceEqual(oPlain) &&
                ItemCryptography.Decrypt(oProtected).SequenceEqual(oPlain) &&
                ItemCryptography.Decrypt(oProtected, oInstance, oCert).SequenceEqual(oPlain),
                nSuite + " FIDO2, Windows recovery, and certificate recovery decrypt independently");

            // Every access path authenticates the FIDO2 envelope as well as the content and metadata.
            byte[] oEnvelope = oProtected.Cipher.ProtectedKey;
            foreach (int nOffset in new[] { 0, 4, 8, 8 + oId.Length, 8 + oId.Length + oSalt.Length,
                8 + oId.Length + oSalt.Length + 12, 8 + oId.Length + oSalt.Length + 12 + 64, oEnvelope.Length - 1 })
            {
                oEnvelope[nOffset] ^= 1;
                Reject(() => ItemCryptography.Decrypt(oProtected, oFidoKey: oAccess),
                    "FIDO2 access rejects envelope tampering at byte " + nOffset);
                Reject(() => ItemCryptography.Decrypt(oProtected, oInstance, oCert),
                    "Certificate recovery rejects FIDO2 envelope tampering at byte " + nOffset);
                Reject(() => ItemCryptography.Decrypt(oProtected),
                    "Windows recovery rejects FIDO2 envelope tampering at byte " + nOffset);
                oEnvelope[nOffset] ^= 1;
            }
            oProtected.Label += " altered";
            Reject(() => ItemCryptography.Decrypt(oProtected, oFidoKey: oAccess),
                "FIDO2 encryption authenticates item labels");
            oProtected.Label = "FIDO2 recovery item";
            oProtected.Cipher.CipherText[0] ^= 1;
            Reject(() => ItemCryptography.Decrypt(oProtected, oFidoKey: oAccess),
                "FIDO2 encryption rejects changed content");
            oProtected.Cipher.CipherText[0] ^= 1;
            oProtected.Cipher.ProtectedKey = oEnvelope.Concat(new byte[] { 0 }).ToArray();
            Reject(() => ItemCryptography.Decrypt(oProtected, oFidoKey: oAccess),
                "FIDO2 encryption rejects trailing envelope data");
            oProtected.Cipher.ProtectedKey = oEnvelope[..^1];
            Reject(() => ItemCryptography.Decrypt(oProtected, oFidoKey: oAccess),
                "FIDO2 encryption rejects truncated recovery data");
            oProtected.Cipher.ProtectedKey = oEnvelope;
            oProtected.Cipher.ContentSuite = null;
            Reject(() => ItemCryptography.Decrypt(oProtected, oFidoKey: oAccess),
                "FIDO2 encryption rejects removal of the saved content suite");
        }

        string sConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginalConfig = File.ReadAllBytes(sConfigPath);
        string sConnection = CryptureEntities.ConnectionString;
        bool bSelfSigned = Crypture.Properties.Settings.Default.AllowSelfSignedCertificates;
        bool bRevocation = Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck;
        string sPath = Path.Combine(sDirectory, "fido.cryptdb");
        try
        {
            SetRecoveryConfig(null, null);
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = true;
            Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = false;
            DatabaseOperations.CreateDatabase(sPath,
                File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
            CryptureEntities.DatabasePath = sPath;
            DatabaseOperations.SaveItem(new Item { Label = "FIDO2 saved item", ItemType = "text" },
                oPlain, null, oFidoKey: oAccess);
            long nId;
            using (CryptureEntities oContext = new CryptureEntities()) nId = oContext.Items.Single().ItemId;
            Item oStored = DatabaseOperations.LoadItem(nId);
            Check(oStored.ProtectionDisplay == "FIDO2 Security Key" &&
                ItemCryptography.Decrypt(oStored, oFidoKey: oAccess).SequenceEqual(oPlain),
                "File Vault stores and reloads FIDO2 metadata and encrypted content");
            VaultHealthReport oHealth = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(!oHealth.Findings.Any(f => f.Severity == HealthStatus.Error) &&
                oHealth.Findings.Any(f => f.Details.Contains("FIDO2")),
                "Health check recognizes a FIDO2 item without contacting its key");

            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, Convert.ToBase64String(oCert.RawData));
            oHealth = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(oHealth.Findings.Any(f => f.Kind == "Emergency Recovery" && f.Severity == HealthStatus.Warning),
                "Health check reports missing configured recovery for FIDO2 items");
            DatabaseOperations.SaveItem(oStored, oPlain, null, oFidoKey: oAccess);
            oStored = DatabaseOperations.LoadItem(nId);
            Check(oStored.Instances.Count == 1 && ItemCryptography.Decrypt(oStored).SequenceEqual(oPlain) &&
                ItemCryptography.Decrypt(oStored, oStored.Instances.Single(), oCert).SequenceEqual(oPlain),
                "The save boundary enforces both configured FIDO2 recovery paths");
            Reject(() => DatabaseOperations.RemoveCertificate(oStored.Instances.Single().UserId),
                "Required FIDO2 recovery certificate cannot be removed");
            oHealth = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
            Check(!oHealth.Findings.Any(f => f.Severity == HealthStatus.Error || f.Kind == "Emergency Recovery"),
                "Health check accepts FIDO2 envelopes with the configured recovery coverage");

            string sBackup = Path.Combine(sDirectory, "fido-backup.cryptdb");
            DatabaseOperations.BackupDatabase(sPath, sBackup);
            SetRecoveryConfig(null, null);
            CryptureEntities.DatabasePath = sBackup;
            Item oBackup = DatabaseOperations.LoadItem(nId);
            Check(ItemCryptography.Decrypt(oBackup, oFidoKey: oAccess).SequenceEqual(oPlain) &&
                ItemCryptography.Decrypt(oBackup).SequenceEqual(oPlain),
                "Vault backup retains both FIDO2 key protection and saved recovery access");
            CryptureEntities.DatabasePath = sPath;
            DatabaseOperations.RemoveCertificate(oStored.Instances.Single().UserId);
            oStored = DatabaseOperations.LoadItem(nId);
            Check(oStored.Instances.Count == 0 &&
                ItemCryptography.Decrypt(oStored, oFidoKey: oAccess).SequenceEqual(oPlain),
                "Removing optional certificate recovery preserves primary FIDO2 access");

            // Conversion removes obsolete access paths and rejects stale edits across the change.
            Item oBeforeConversion = oStored;
            DatabaseOperations.SaveItem(oStored, oPlain, null, PrincipalProtection.LocalUserDescriptor);
            oStored = DatabaseOperations.LoadItem(nId);
            Check(oStored.Cipher.CipherParams == ItemCryptography.PrincipalFormat &&
                ItemCryptography.Decrypt(oStored).SequenceEqual(oPlain), "FIDO2 item converts to Windows protection");
            Reject(() => DatabaseOperations.SaveItem(oBeforeConversion, oPlain, null, oFidoKey: oAccess),
                "FIDO2 save rejects stale edits across protection conversion");
            DatabaseOperations.SaveItem(oStored, oPlain, null, oFidoKey: oAccess);
            oStored = DatabaseOperations.LoadItem(nId);
            Check(FidoKeyProtection.Read(oStored.Cipher).RecoveryKey == null && oStored.Instances.Count == 0 &&
                ItemCryptography.Decrypt(oStored, oFidoKey: oAccess).SequenceEqual(oPlain),
                "Converting Windows protection to FIDO2 removes unconfigured Windows access");
            using FidoKeyAccess oExpiredAccess = new FidoKeyAccess(oId, oSalt,
                RandomNumberGenerator.GetBytes(FidoKeyProtection.SecretBytes));
            oExpiredAccess.Dispose();
            byte[] oBefore = File.ReadAllBytes(sPath);
            Reject(() => DatabaseOperations.SaveItem(oStored, oPlain, null, oFidoKey: oExpiredAccess),
                "A cleared FIDO2 secret cannot save an item");
            Check(File.ReadAllBytes(sPath).SequenceEqual(oBefore), "Failed FIDO2 save preserves the complete Vault");
        }
        finally
        {
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            CryptureEntities.ConnectionString = sConnection;
            Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = bSelfSigned;
            Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = bRevocation;
        }
    }

    private static void TestFidoEditor(string sDirectory)
    {
        string sConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginalConfig = File.ReadAllBytes(sConfigPath);
        string sConnection = CryptureEntities.ConnectionString;
        ItemEditor oEditor = null;
        SynchronizationContext oPreviousContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
        using FidoKeyAccess oAccess = new FidoKeyAccess(RandomNumberGenerator.GetBytes(64),
            RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
        try
        {
            string sPath = Path.Combine(sDirectory, "fido-editor.cryptdb");
            SetRecoveryConfig(PrincipalProtection.LocalUserDescriptor, null);
            DatabaseOperations.CreateDatabase(sPath,
                File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
            CryptureEntities.DatabasePath = sPath;
            byte[] oPlain = Encoding.Unicode.GetBytes("Recovered FIDO2 secret");
            DatabaseOperations.SaveItem(new Item { Label = "Security key secret", ItemType = "text" },
                oPlain, null, oFidoKey: oAccess);
            long nId;
            using (CryptureEntities oContext = new CryptureEntities()) nId = oContext.Items.Single().ItemId;
            oEditor = new ItemEditor(DatabaseOperations.LoadItem(nId))
            {
                Left = -20000, Top = -20000, WindowStartupLocation = WindowStartupLocation.Manual,
                ShowActivated = false, ShowInTaskbar = false
            };
            oEditor.Show();
            PumpUntil(() => oEditor.IsLoaded && oEditor.CertificateLoading.IsCompleted);
            ComboBox oMode = (ComboBox)oEditor.FindName("oProtectionMode");
            StackPanel oPanel = (StackPanel)oEditor.FindName("oFidoPanel");
            Button oRecovery = (Button)oEditor.FindName("oFidoRecoveryButton");
            Check(oMode.SelectedIndex == 2 && oPanel.IsVisible && oRecovery.IsVisible &&
                !((RibbonGroup)oEditor.FindName("oCertificateSharingGroup")).IsVisible &&
                !((StackPanel)oEditor.FindName("oPrincipalPanel")).IsVisible,
                "Locked FIDO2 editor shows its security-key policy and applicable recovery action");
            foreach (double nFontSize in new[] { 12.0, 18.0, 24.0 })
            {
                oEditor.Width = 920;
                oEditor.FontSize = nFontSize;
                oRecovery.BringIntoView();
                oEditor.UpdateLayout();
                TextBlock oStatus = (TextBlock)oEditor.FindName("oFidoKeyStatus");
                Check(oPanel.ActualWidth > 250 && oStatus.ActualWidth <= oPanel.ActualWidth &&
                    oRecovery.ActualWidth <= oPanel.ActualWidth && oRecovery.ActualHeight >= nFontSize,
                    "FIDO2 controls fit the minimum editor width at font size " + nFontSize);
            }
            oEditor.FontSize = 12;
            oEditor.Width = 1080;
            oEditor.UpdateLayout();
            string sRenderDirectory = Environment.GetEnvironmentVariable("CRYPTURE_TEST_RENDER_DIR");
            if (!String.IsNullOrWhiteSpace(sRenderDirectory))
            {
                Directory.CreateDirectory(sRenderDirectory);
                RenderTargetBitmap oRender = new RenderTargetBitmap((int)oEditor.ActualWidth,
                    (int)oEditor.ActualHeight, 96, 96, PixelFormats.Pbgra32);
                oRender.Render(oEditor);
                PngBitmapEncoder oEncoder = new PngBitmapEncoder();
                oEncoder.Frames.Add(BitmapFrame.Create(oRender));
                using FileStream oFile = File.Create(Path.Combine(sRenderDirectory, "fido-editor.png"));
                oEncoder.Save(oFile);
            }
            oRecovery.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            PumpUntil(() => ((TextBox)oEditor.FindName("oItemData")).IsEnabled);
            Check(((TextBox)oEditor.FindName("oItemData")).Text == "Recovered FIDO2 secret" &&
                !oRecovery.IsVisible,
                "Explicit FIDO2 recovery unlocks content without contacting the security key");
            if (FidoNative.IsAvailable)
            {
                Button oChangeKey = (Button)oEditor.FindName("oChangeFidoKeyButton");
                Check(oChangeKey.IsVisible, "Unlocked FIDO2 item offers changing its security key");
                oChangeKey.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Check(((TextBlock)oEditor.FindName("oFidoKeyStatus")).Text.Contains("set up when you save"),
                    "Choosing another FIDO2 key defers setup until the next save");
            }
            else
                Check(((TextBlock)oEditor.FindName("oProtectionDisabledNotice")).IsVisible &&
                    !((RibbonButton)oEditor.FindName("oSaveItemButton")).IsEnabled,
                    "Unavailable WebAuthn blocks FIDO2 saves while retaining recovery access");
            oMode.SelectedIndex = 0;
            Check(!oPanel.IsVisible && ((StackPanel)oEditor.FindName("oPrincipalPanel")).IsVisible,
                "Changing from FIDO2 to Windows protection updates the available controls");
            Check(!Utilities.TryOperationAsync(oEditor, () => Task.FromCanceled(new CancellationToken(true)))
                .GetAwaiter().GetResult(), "Cancelling a security-key operation leaves the editor open");
        }
        finally
        {
            if (oEditor != null)
            {
                typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                    .SetValue(oEditor, false);
                oEditor.Close();
            }
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            CryptureEntities.ConnectionString = sConnection;
            SynchronizationContext.SetSynchronizationContext(oPreviousContext);
        }
    }

    private static int RunFidoHardware()
    {
        // Opt in explicitly because native round trips require a connected key and user interaction.
        Window oOwner = new Window();
        try
        {
            IntPtr hOwner = new WindowInteropHelper(oOwner).EnsureHandle();
            Console.WriteLine("Complete the security key PIN and touch prompts for setup and two assertions.");
            byte[] oCredentialId = FidoNative.CreateCredential(hOwner);
            byte[] oSalt = RandomNumberGenerator.GetBytes(32);
            using FidoKeyAccess oFirst = FidoNative.Open(hOwner, oCredentialId, oSalt);
            using FidoKeyAccess oSecond = FidoNative.Open(hOwner, oCredentialId, oSalt);
            Check(CryptographicOperations.FixedTimeEquals(oFirst.Secret, oSecond.Secret),
                "Real FIDO2 key returns a stable verified hmac-secret output");
            byte[] oPlain = Encoding.UTF8.GetBytes("Hardware round trip");
            Item oItem = new Item { Label = "Hardware test", ItemType = "text" };
            ItemCryptography.Encrypt(oItem, oPlain, null, oFidoKey: oFirst);
            Check(ItemCryptography.Decrypt(oItem, oFidoKey: oSecond).SequenceEqual(oPlain),
                "Real FIDO2 key encrypts and decrypts an item");
            return 0;
        }
        catch (Exception oError)
        {
            Console.Error.WriteLine(oError);
            return 1;
        }
        finally { oOwner.Close(); }
    }
}
