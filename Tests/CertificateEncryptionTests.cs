using System;
using System.IO;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Controls.Ribbon;
using System.Configuration;
using System.Xml;
using System.Formats.Asn1;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Crypture;
using Microsoft.Win32.SafeHandles;

internal static partial class RegressionTests
{
    private static void RejectCryptography(Action oAction, string sName)
    {
        try
        {
            oAction();
        }
        catch (CryptographicException)
        {
            Check(true, sName);
            return;
        }
        throw new Exception("FAIL: " + sName);
    }

    private static X509Certificate2 UsageCertificate(RSA oKey, X509KeyUsageFlags? oKeyUsage,
        params string[] oEnhancedUsages)
    {
        CertificateRequest oRequest = new CertificateRequest("CN=Certificate Usage Test", oKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (oKeyUsage.HasValue)
            oRequest.CertificateExtensions.Add(new X509KeyUsageExtension(oKeyUsage.Value, true));
        if (oEnhancedUsages.Length > 0)
        {
            OidCollection oUsages = new OidCollection();
            foreach (string sOid in oEnhancedUsages) oUsages.Add(new Oid(sOid));
            oRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oUsages, false));
        }
        return oRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
    }

    private static void TestCertificateUsageFilters(RSA oKey)
    {
        const string sClient = "1.3.6.1.5.5.7.3.2";
        const string sServer = "1.3.6.1.5.5.7.3.1";
        const string sSigning = "1.3.6.1.5.5.7.3.3";
        using (X509Certificate2 oPlain = UsageCertificate(oKey, X509KeyUsageFlags.KeyEncipherment))
        using (X509Certificate2 oUnrestricted = UsageCertificate(oKey, null))
        using (X509Certificate2 oClient = UsageCertificate(oKey,
            X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, sClient))
        using (X509Certificate2 oServer = UsageCertificate(oKey, X509KeyUsageFlags.KeyEncipherment, sServer))
        using (X509Certificate2 oMixed = UsageCertificate(oKey,
            X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, sClient, sSigning))
        using (X509Certificate2 oAny = UsageCertificate(oKey, X509KeyUsageFlags.KeyEncipherment, "2.5.29.37.0"))
        {
            CertificateUsageFilter oDefaults = CertificateUsageFilter.Read();
            Check(oDefaults.Matches(oPlain) && oDefaults.Matches(oClient) && oDefaults.Matches(oServer),
                "Default usage filters retain eligible encryption certificates with different EKUs");
            Check(oDefaults.Matches(oUnrestricted) && oDefaults.Matches(oAny),
                "Default usage filters permit unrestricted certificate usages");
            CertificateUsageFilter oFilter = new CertificateUsageFilter("keyagreement; KEYENCIPHERMENT", "", "", "");
            Check(oFilter.Matches(oPlain), "Key Usage include lists accept any matching name regardless of case");
            oFilter = new CertificateUsageFilter("DigitalSignature", "", "", "");
            Check(oFilter.Matches(oClient) && !oFilter.Matches(oPlain),
                "Key Usage inclusion distinguishes multipurpose and encryption-only certificates");
            oFilter = new CertificateUsageFilter("KeyEncipherment", "DigitalSignature", "", "");
            Check(oFilter.Matches(oPlain) && !oFilter.Matches(oClient),
                "Excluded Key Usages take precedence over included encryption permissions");
            oFilter = new CertificateUsageFilter("", "", sClient + "; " + sServer, "");
            Check(oFilter.Matches(oClient) && oFilter.Matches(oServer) && oFilter.Matches(oPlain),
                "EKU include lists accept any matching OID and optionally unrestricted certificates");
            oFilter = new CertificateUsageFilter("", "", sClient, "", true, false);
            Check(oFilter.Matches(oClient) && !oFilter.Matches(oServer) && !oFilter.Matches(oPlain) &&
                !oFilter.Matches(oAny), "Strict EKU inclusion rejects missing, any-purpose, and unrelated EKUs");
            oFilter = new CertificateUsageFilter("", "", sClient, sSigning);
            Check(oFilter.Matches(oClient) && !oFilter.Matches(oMixed),
                "Excluded EKUs take precedence on certificates with multiple purposes");
            oFilter = new CertificateUsageFilter("", "", "", sSigning);
            Check(!oFilter.Matches(oMixed) && oFilter.Matches(oServer),
                "An EKU exclusion list works without an inclusion list");
            oFilter = new CertificateUsageFilter("KeyEncipherment", "", "", "", false);
            Check(!oFilter.Matches(oUnrestricted) && oFilter.Matches(oPlain),
                "Unrestricted Key Usage can be excluded separately from unrestricted EKU");
            oFilter = new CertificateUsageFilter("", "", "", "2.5.29.37.0");
            Check(!oFilter.Matches(oAny), "Explicit any-purpose EKU exclusions take precedence");
            oFilter = new CertificateUsageFilter("DigitalSignature", "", sServer, "");
            Check(!oFilter.Matches(oClient) && !oFilter.Matches(oServer),
                "Certificates must satisfy both the Key Usage and EKU inclusion lists");
            oFilter = new CertificateUsageFilter(" , ; ", "", "", "");
            Check(oFilter.Matches(oClient.RawData) && !oFilter.Matches(new byte[] { 1, 2 }) &&
                !oFilter.Matches((byte[])null), "Empty filters accept valid certificate data and reject damaged entries");
            Reject(() => new CertificateUsageFilter("MisspelledUsage", "", "", ""),
                "Reject unknown Key Usage names instead of silently broadening selection");
            Reject(() => new CertificateUsageFilter("", "512", "", ""), "Reject numeric Key Usage filter entries");
            Reject(() => new CertificateUsageFilter("", "", "Client Authentication", ""),
                "Reject friendly names where an EKU OID is required");
            Reject(() => new CertificateUsageFilter("", "", "", "1.99.3"), "Reject invalid EKU OID arcs");
        }
    }

    private static void TestCertificateVisibility(RSA oKey)
    {
        string sConfigPath = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath;
        byte[] oOriginal = File.ReadAllBytes(sConfigPath);
        Crypture.Properties.Settings oSettings = Crypture.Properties.Settings.Default;
        bool bSelfSigned = oSettings.AllowSelfSignedCertificates;
        bool bRevocation = oSettings.PerformCertificateRevocationCheck;
        Check(!oSettings.ShowExpiredCertificates && !oSettings.ShowUntrustedCertificates,
            "Expired and untrusted selection settings default to hidden");

        // Exercise configuration reloads with real certificates, without changing Windows trust anchors.
        void Reload(bool bExpired, bool bUntrusted, bool bAllowSelfSigned = false, bool bCheckRevocation = false)
        {
            XmlDocument oConfig = new XmlDocument { PreserveWhitespace = true };
            oConfig.LoadXml(Encoding.UTF8.GetString(oOriginal).TrimStart('\uFEFF'));
            oConfig.SelectSingleNode("//setting[@name='ShowExpiredCertificates']/value").InnerText =
                bExpired.ToString();
            oConfig.SelectSingleNode("//setting[@name='ShowUntrustedCertificates']/value").InnerText =
                bUntrusted.ToString();
            File.WriteAllText(sConfigPath, oConfig.OuterXml, new UTF8Encoding(false));
            ConfigurationManager.RefreshSection("applicationSettings/Crypture.Properties.Settings");
            oSettings.Reload();
            oSettings.AllowSelfSignedCertificates = bAllowSelfSigned;
            oSettings.PerformCertificateRevocationCheck = bCheckRevocation;
        }
        using RSA oIssuerKey = new RSACng(2048);
        CertificateRequest oIssuerRequest = new("CN=Visibility Issuer " + Guid.NewGuid().ToString("N"), oIssuerKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        oIssuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        oIssuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using X509Certificate2 oIssuer = oIssuerRequest.CreateSelfSigned(
            DateTimeOffset.Now.AddDays(-5), DateTimeOffset.Now.AddDays(5));
        using X509Certificate2 oPublicIssuer = X509CertificateLoader.LoadCertificate(oIssuer.RawData);
        using X509Store oStore = new(StoreName.My, StoreLocation.CurrentUser);
        oStore.Open(OpenFlags.ReadWrite);
        CertificateRequest oRequest = new("CN=Visibility Recipient", oKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        oRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
        X509SignatureGenerator oSigner = X509SignatureGenerator.CreateForRSA(oIssuerKey, RSASignaturePadding.Pkcs1);
        using X509Certificate2 oIssued = oRequest.Create(oIssuer.SubjectName, oSigner,
            DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using X509Certificate2 oExpiredIssued = oRequest.Create(oIssuer.SubjectName, oSigner,
            DateTimeOffset.Now.AddDays(-3), DateTimeOffset.Now.AddDays(-2), RandomNumberGenerator.GetBytes(16));
        using X509Certificate2 oMissingIssuer = oRequest.Create(new X500DistinguishedName("CN=Absent Visibility CA"),
            oSigner, DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using X509Certificate2 oValid = Certificate(oKey, "Visible Self-Signed", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1));
        using X509Certificate2 oExpired = Certificate(oKey, "Visible Expired", DateTimeOffset.Now.AddDays(-3),
            DateTimeOffset.Now.AddDays(-2));
        using X509Certificate2 oFuture = Certificate(oKey, "Visible Future", DateTimeOffset.Now.AddDays(1),
            DateTimeOffset.Now.AddDays(2));
        using X509Certificate2 oSigning = Certificate(oKey, "Visible Signing Only", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1), X509KeyUsageFlags.DigitalSignature);
        byte[] oBrokenData = oValid.RawData;
        oBrokenData[^1] ^= 1;
        using X509Certificate2 oBroken = X509CertificateLoader.LoadCertificate(oBrokenData);
        oBrokenData = oIssued.RawData;
        oBrokenData[^1] ^= 1;
        using X509Certificate2 oBrokenIssued = X509CertificateLoader.LoadCertificate(oBrokenData);
        try
        {
            oStore.Add(oPublicIssuer);
            foreach (bool bExpired in new[] { false, true })
            foreach (bool bUntrusted in new[] { false, true })
            {
                Reload(bExpired, bUntrusted);
                CertificateUsageFilter oFilter = CertificateUsageFilter.Read();
                string sPolicy = $"expired={bExpired}, untrusted={bUntrusted}";
                Check(CertificateOperations.CanSelectCertificate(oValid.RawData, oFilter) == bUntrusted,
                    "Self-signed selection follows trust visibility: " + sPolicy);
                Check(CertificateOperations.CanSelectCertificate(oIssued.RawData, oFilter) == bUntrusted,
                    "Issued selection uses Windows trust anchors: " + sPolicy);
                Check(CertificateOperations.CanSelectCertificate(oMissingIssuer.RawData, oFilter) == bUntrusted,
                    "Missing trust chain follows untrusted visibility: " + sPolicy);
                Check(CertificateOperations.CanSelectCertificate(oExpired.RawData, oFilter) ==
                    (bExpired && bUntrusted), "Expired self-signed selection requires both permissions: " + sPolicy);
                Check(CertificateOperations.CanSelectCertificate(oExpiredIssued.RawData, oFilter) ==
                    (bExpired && bUntrusted), "Expired issued selection requires both permissions: " + sPolicy);
                Check(!CertificateOperations.CanSelectCertificate(oFuture.RawData, oFilter),
                    "Future validity is never waived by expiry visibility: " + sPolicy);
                Check(!CertificateOperations.CanSelectCertificate(oBroken.RawData, oFilter) &&
                    !CertificateOperations.CanSelectCertificate(oBrokenIssued.RawData, oFilter),
                    "Invalid signatures remain excluded: " + sPolicy);
                Check(!CertificateOperations.CheckCertificateStatus(oExpired) &&
                    !CertificateOperations.CheckCertificateStatus(oIssued),
                    "Visibility does not waive strict expiry and trust validation: " + sPolicy);
            }
            Reload(true, false, true);
            Check(CertificateOperations.CheckCertificateStatus(oExpired, true) &&
                !CertificateOperations.CheckCertificateStatus(oIssued, true),
                "Expiry visibility combines with the existing self-signed permission independently of CA trust");
            Reload(true, true);
            Check(!CertificateOperations.CheckCertificateStatus(oSigning, true) &&
                !CertificateOperations.CanSelectCertificate(new byte[] { 1, 2 }, CertificateUsageFilter.Read()),
                "Selection visibility excludes signing-only and damaged certificates");
            Reload(true, true, bCheckRevocation: true);
            Check(!CertificateOperations.CheckCertificateStatus(oIssued, true),
                "Untrusted visibility preserves online revocation checks");
        }
        finally
        {
            oStore.Remove(oPublicIssuer);
            File.WriteAllBytes(sConfigPath, oOriginal);
            ConfigurationManager.RefreshSection("applicationSettings/Crypture.Properties.Settings");
            oSettings.Reload();
            oSettings.AllowSelfSignedCertificates = bSelfSigned;
            oSettings.PerformCertificateRevocationCheck = bRevocation;
        }
    }

    private static void TestCertificateUsageStartup()
    {
        System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(App).TypeHandle);
        Crypture.Properties.Settings oSettings = Crypture.Properties.Settings.Default;
        Check(ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath ==
            Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config"),
            "Application startup reads the named adjacent configuration file");
        Check(oSettings.CertificateKeyUsageInclude == "DigitalSignature" &&
            oSettings.CertificateKeyUsageExclude == "KeyAgreement" &&
            oSettings.CertificateEnhancedKeyUsageInclude == "1.3.6.1.5.5.7.3.2" &&
            oSettings.CertificateEnhancedKeyUsageExclude == "1.3.6.1.5.5.7.3.3" &&
            !oSettings.AllowUnrestrictedCertificateKeyUsage && !oSettings.AllowUnrestrictedCertificateEnhancedKeyUsage,
            "Application startup loads all six certificate selection defaults from the sidecar");
        Check(oSettings.ShowExpiredCertificates && oSettings.ShowUntrustedCertificates,
            "Application startup loads both certificate visibility settings from the sidecar");
    }

    private static void TestCertificateUsageConfiguration(ItemBrowser oBrowser, Item oItem)
    {
        string sConfigPath = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).FilePath;
        string sSidecarPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginalSidecar = File.ReadAllBytes(sSidecarPath);
        const string sSection = "applicationSettings/Crypture.Properties.Settings";
        byte[] oOriginal = File.ReadAllBytes(sConfigPath);
        Crypture.Properties.Settings oSettings = Crypture.Properties.Settings.Default;
        bool bSelfSigned = oSettings.AllowSelfSignedCertificates;
        bool bRevocation = oSettings.PerformCertificateRevocationCheck;
        string sTheme = oSettings.ThemeMode;
        Item oStored = DatabaseOperations.LoadItem(oItem.ItemId);
        User oRecipient = oStored.Instances.First().User;

        // Reload the real adjacent configuration to exercise deployed defaults and recovery policy.
        void Reload(string sInclude, bool bRecovery = false,
            bool bShowExpired = false, bool bShowUntrusted = false)
        {
            XmlDocument oConfig = new XmlDocument { PreserveWhitespace = true };
            oConfig.LoadXml(Encoding.UTF8.GetString(oOriginal).TrimStart('\uFEFF'));
            oConfig.SelectSingleNode("//setting[@name='ShowExpiredCertificates']/value").InnerText =
                bShowExpired.ToString();
            oConfig.SelectSingleNode("//setting[@name='ShowUntrustedCertificates']/value").InnerText =
                bShowUntrusted.ToString();
            oConfig.SelectSingleNode("//setting[@name='CertificateKeyUsageInclude']/value").InnerText = sInclude;
            oConfig.SelectSingleNode("//setting[@name='CertificateKeyUsageExclude']/value").InnerText = "KeyAgreement";
            oConfig.SelectSingleNode("//setting[@name='CertificateEnhancedKeyUsageInclude']/value").InnerText =
                "1.3.6.1.5.5.7.3.2";
            oConfig.SelectSingleNode("//setting[@name='CertificateEnhancedKeyUsageExclude']/value").InnerText =
                "1.3.6.1.5.5.7.3.3";
            oConfig.SelectSingleNode("//setting[@name='AllowUnrestrictedCertificateKeyUsage']/value").InnerText = "False";
            oConfig.SelectSingleNode("//setting[@name='AllowUnrestrictedCertificateEnhancedKeyUsage']/value").InnerText =
                "False";
            oConfig.SelectSingleNode("//appSettings/add[@key='RecoveryCertificateBase64']/@value").Value =
                bRecovery ? Convert.ToBase64String(oRecipient.Certificate) : "";
            File.WriteAllText(sConfigPath, oConfig.OuterXml, new UTF8Encoding(false));
            File.WriteAllText(sSidecarPath, oConfig.OuterXml, new UTF8Encoding(false));
            ConfigurationManager.RefreshSection(sSection);
            ConfigurationManager.RefreshSection("appSettings");
            oSettings.Reload();
            oSettings.AllowSelfSignedCertificates = true;
            oSettings.PerformCertificateRevocationCheck = false;
            oSettings.ThemeMode = sTheme;
        }
        try
        {
            Reload("DigitalSignature", bShowExpired: true, bShowUntrusted: true);
            Check(oSettings.CertificateKeyUsageInclude == "DigitalSignature" &&
                oSettings.CertificateKeyUsageExclude == "KeyAgreement" &&
                oSettings.CertificateEnhancedKeyUsageInclude == "1.3.6.1.5.5.7.3.2" &&
                oSettings.CertificateEnhancedKeyUsageExclude == "1.3.6.1.5.5.7.3.3" &&
                !oSettings.AllowUnrestrictedCertificateKeyUsage && !oSettings.AllowUnrestrictedCertificateEnhancedKeyUsage,
                "Adjacent config supplies all six certificate usage defaults");
            Check(oSettings.ShowExpiredCertificates && oSettings.ShowUntrustedCertificates,
                "Adjacent config supplies both certificate visibility settings");

            // A fresh process also verifies the real application's startup config path.
            var oStart = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            oStart.Environment["CRYPTURE_TEST_CONFIG_STARTUP"] = "1";
            using (var oProcess = System.Diagnostics.Process.Start(oStart))
            {
                var oOutput = oProcess.StandardOutput.ReadToEndAsync();
                var oErrors = oProcess.StandardError.ReadToEndAsync();
                if (!oProcess.WaitForExit(15000))
                {
                    oProcess.Kill(true);
                    throw new TimeoutException("The configuration startup check did not finish.");
                }
                Check(oProcess.ExitCode == 0, "Fresh application startup loads the adjacent usage configuration: " +
                    oOutput.GetAwaiter().GetResult().Trim() + oErrors.GetAwaiter().GetResult().Trim());
            }
            CertificateUsageFilter oFilter = CertificateUsageFilter.Read();
            Check(!oFilter.Matches(oRecipient.Certificate), "Configured usage filters exclude unrelated new recipients");
            using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oRecipient.Certificate))
            {
                Check(CertificateOperations.CheckCertificateStatus(oCert),
                    "Selection filters do not invalidate certificates used for saved access and recovery");
                Reject(() => oBrowser.AddCertificate(oCert, CertificateOperations.CurrentUserSid),
                    "Direct certificate imports honor the configured usage filters");
            }
            Reload("DigitalSignature", bRecovery: true);
            Item oRecoveryItem = new Item { Label = "Filtered Certificate Recovery", ItemType = "text" };
            byte[] oSecret = Encoding.Unicode.GetBytes("Recovery remains available under restrictive selection filters.");
            DatabaseOperations.SaveItem(oRecoveryItem, oSecret, Array.Empty<User>(), PrincipalProtection.LocalUserDescriptor);
            using (CryptureEntities oContent = new CryptureEntities())
                oRecoveryItem = DatabaseOperations.LoadItem(oContent.Items.Single(i =>
                    i.Label == "Filtered Certificate Recovery").ItemId);
            Check(oRecoveryItem.Instances.Any(i => i.User.Certificate.SequenceEqual(oRecipient.Certificate)),
                "Certificate usage filters do not remove emergency recovery from Windows-protected saves");
            Check(ItemCryptography.Decrypt(oRecoveryItem).SequenceEqual(oSecret),
                "Restrictive certificate selection defaults preserve Windows-protected item access");
            Reload("InvalidUsage");
            Reject(() => CertificateUsageFilter.Read(), "Invalid usage settings reject certificate selection");
        }
        finally
        {
            File.WriteAllBytes(sConfigPath, oOriginal);
            File.WriteAllBytes(sSidecarPath, oOriginalSidecar);
            ConfigurationManager.RefreshSection(sSection);
            ConfigurationManager.RefreshSection("appSettings");
            oSettings.Reload();
            oSettings.AllowSelfSignedCertificates = bSelfSigned;
            oSettings.PerformCertificateRevocationCheck = bRevocation;
            oSettings.ThemeMode = sTheme;
        }
    }

    private static void TestPersonalCertificateStores()
    {
        using (var oIdentity = WindowsIdentity.GetCurrent())
        {
            bool bAdmin = new WindowsPrincipal(oIdentity)
                .IsInRole(WindowsBuiltInRole.Administrator);
            foreach (StoreLocation oLocation in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
            {
                if (oLocation == StoreLocation.LocalMachine && !bAdmin)
                {
                    Console.WriteLine("SKIP: Computer-store private-key round trips require elevation.");
                    continue;
                }
                string sKeyName = "Crypture.StoreTest-" + Guid.NewGuid().ToString("N");
                CngKeyCreationParameters oOptions = new CngKeyCreationParameters
                {
                    KeyUsage = CngKeyUsages.Decryption | CngKeyUsages.Signing,
                    KeyCreationOptions = oLocation == StoreLocation.LocalMachine
                        ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None
                };
                oOptions.Parameters.Add(new CngProperty("Length",
                    BitConverter.GetBytes(2048), CngPropertyOptions.None));
                using (CngKey oKey = CngKey.Create(CngAlgorithm.Rsa, sKeyName, oOptions))
                using (RSA oRsa = new RSACng(oKey))
                using (X509Certificate2 oOriginal = Certificate(oRsa, sKeyName, DateTimeOffset.Now.AddDays(-1),
                    DateTimeOffset.Now.AddDays(1)))
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oOriginal.RawData))
                using (X509Store oStore = new X509Store(StoreName.My, oLocation))
                {
                    try
                    {
                        // Persist the provider association so discovery must reopen the actual Windows private key.
                        TestKeyProvider oProvider = new TestKeyProvider
                        {
                            Container = sKeyName, Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider,
                            Flags = oLocation == StoreLocation.LocalMachine ? 0x20u : 0,
                            KeySpec = UInt32.MaxValue
                        };
                        if (!CertSetCertificateContextProperty(oCert.Handle, 2, 0, ref oProvider))
                            throw new CryptographicException(Marshal.GetLastWin32Error());
                        oStore.Open(OpenFlags.ReadWrite);
                        try
                        {
                            oStore.Add(oCert);
                            Check(CertificateOperations.GetPrivateCertificateData().Contains(
                                Convert.ToBase64String(oCert.RawData)), oLocation + " private key discovery");
                            X509Certificate2Collection oChoices = CertificateOperations.GetPersonalCertificates();
                            try
                            {
                                X509Certificate2 oDiscovered = oChoices.Cast<X509Certificate2>().Single(c =>
                                    c.RawData.SequenceEqual(oCert.RawData) && c.HasPrivateKey);
                                byte[] oPlain = Encoding.UTF8.GetBytes("Personal-store discovery round trip");
                                Item oItem = new Item { Label = "Store discovery", ItemType = "text" };
                                ItemCryptography.Encrypt(oItem, oPlain,
                                    new[] { new User { UserId = 7, Certificate = oCert.RawData } });
                                Check(ItemCryptography.Decrypt(oItem, oItem.Instances.Single(), oDiscovered)
                                    .SequenceEqual(oPlain), oLocation + " discovered private key decrypts an item");
                            }
                            finally
                            {
                                foreach (X509Certificate2 oChoice in oChoices) oChoice.Dispose();
                            }
                        }
                        finally
                        {
                            oStore.Remove(oCert);
                        }
                    }
                    finally
                    {
                        oKey.Delete();
                    }
                }
                Check(!CngKey.Exists(sKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    oLocation == StoreLocation.LocalMachine ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None),
                    oLocation + " temporary private key is removed");
            }
        }
    }

    private static void TestEditorCertificateLoading(string sDirectory)
    {
        string sPreviousConnection = CryptureEntities.ConnectionString;
        Crypture.Properties.Settings oSettings = Crypture.Properties.Settings.Default;
        bool bSelfSigned = oSettings.AllowSelfSignedCertificates;
        bool bRevocation = oSettings.PerformCertificateRevocationCheck;
        bool bUntrusted = oSettings.ShowUntrustedCertificates;
        var oAutomatic = oSettings.AutomaticallyAddedCertificatesList;
        try
        {
            oSettings.AllowSelfSignedCertificates = true;
            oSettings.PerformCertificateRevocationCheck = false;
            oSettings["ShowUntrustedCertificates"] = true;
            oSettings["AutomaticallyAddedCertificatesList"] = new System.Collections.Specialized.StringCollection();
            foreach (string sScenario in new[] { "new", "existing", "save", "close" })
            {
                ItemEditor oEditor = null;
                var oListener = new TcpListener(IPAddress.Loopback, 0);
                oListener.Start();
                using (var oCancellation = new CancellationTokenSource())
                using (RSA oIssuerKey = new RSACng(2048))
                using (RSA oLeafKey = new RSACng(2048))
                using (X509Certificate2 oWarm = Certificate(oLeafKey, "Warm editor", DateTimeOffset.Now.AddDays(-1),
                    DateTimeOffset.Now.AddDays(1)))
                {
                    var oRequested = new TaskCompletionSource<bool>(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                    var oRelease = new TaskCompletionSource<bool>(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                    var oIssuerRequest = new CertificateRequest("CN=Editor issuer " + Guid.NewGuid().ToString("N"),
                        oIssuerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    oIssuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                    oIssuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign,
                        true));
                    using (X509Certificate2 oIssuer = oIssuerRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-2),
                        DateTimeOffset.Now.AddDays(2)))
                    {
                        byte[] oIssuerData = oIssuer.RawData;
                        var oServer = Task.Run(async () =>
                        {
                            using (var oClient = await oListener.AcceptTcpClientAsync(oCancellation.Token))
                            using (var oStream = oClient.GetStream())
                            {
                                int nRead = await oStream.ReadAsync(new byte[8192], oCancellation.Token);
                                if (nRead == 0) throw new IOException("The issuer request ended before its headers.");
                                oRequested.SetResult(true);
                                await oRelease.Task;
                                byte[] oHeader = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n" +
                                    "Content-Type: application/pkix-cert\r\nContent-Length: " + oIssuerData.Length +
                                    "\r\nConnection: close\r\n\r\n");
                                await oStream.WriteAsync(oHeader, oCancellation.Token);
                                await oStream.WriteAsync(oIssuerData, oCancellation.Token);
                            }
                        });
                        try
                        {
                            // Hold a real issuer download until dispatcher responsiveness has been observed.
                            string sUrl = "http://127.0.0.1:" +
                                ((IPEndPoint)oListener.LocalEndpoint).Port + "/issuer.cer";
                            AsnWriter oAia = new AsnWriter(AsnEncodingRules.DER);
                            oAia.PushSequence();
                            oAia.PushSequence();
                            oAia.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2");
                            oAia.WriteCharacterString(UniversalTagNumber.IA5String, sUrl,
                                new Asn1Tag(TagClass.ContextSpecific, 6));
                            oAia.PopSequence();
                            oAia.PopSequence();
                            var oLeafRequest = new CertificateRequest("CN=Slow editor " + sScenario, oLeafKey,
                                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                            oLeafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                                X509KeyUsageFlags.KeyEncipherment, true));
                            oLeafRequest.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.1",
                                oAia.Encode(), false));
                            using (X509Certificate2 oPublic = oLeafRequest.Create(oIssuer,
                                DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1),
                                RandomNumberGenerator.GetBytes(16)))
                            using (X509Certificate2 oLeaf = oPublic.CopyWithPrivateKey(oLeafKey))
                            {
                                string sPath = Path.Combine(sDirectory, "editor-" + sScenario + ".cryptdb");
                                DatabaseOperations.CreateDatabase(sPath,
                                    File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
                                CryptureEntities.DatabasePath = sPath;
                                User oUser = new User { Certificate = sScenario == "save" ? oWarm.RawData : oLeaf.RawData };
                                using (CryptureEntities oContext = new CryptureEntities())
                                {
                                    oContext.Users.Add(oUser);
                                    oContext.SaveChanges();
                                }
                                Item oStored = null;
                                if (sScenario == "existing")
                                {
                                    DatabaseOperations.SaveItem(
                                        new Item { Label = "Windows editor", ItemType = "text" },
                                        Encoding.Unicode.GetBytes("Stored Windows content"), null,
                                        PrincipalProtection.LocalUserDescriptor);
                                    using (CryptureEntities oContext = new CryptureEntities())
                                        oStored = DatabaseOperations.LoadItem(oContext.Items.Single().ItemId);
                                }
                                var oWatch = Stopwatch.StartNew();
                                oEditor = oStored == null ? new ItemEditor() : new ItemEditor(oStored);
                                Check(oWatch.Elapsed < TimeSpan.FromSeconds(3),
                                    sScenario + " editor construction does not wait for certificate network lookups");
                                oEditor.SetEditingControls(true);
                                var oMode = (ComboBox)oEditor.FindName("oProtectionMode");
                                var oSave = (RibbonButton)oEditor.FindName("oSaveItemButton");
                                var oShare = (RibbonMenuButton)oEditor.FindName(
                                    "oAddCertDropDown");
                                if (sScenario == "save")
                                {
                                    PumpUntil(() => oEditor.CertificateLoading.IsCompleted);
                                    oEditor.CertificateLoading.GetAwaiter().GetResult();
                                    oEditor.UserList.Single().Certificate = oLeaf.RawData;
                                    using (CryptureEntities oContext = new CryptureEntities())
                                    {
                                        oContext.Users.Find(oUser.UserId).Certificate = oLeaf.RawData;
                                        oContext.SaveChanges();
                                    }
                                    oEditor.UserListSelected.Add(oEditor.UserList.Single());
                                    oMode.SelectedIndex = 1;
                                    ((TextBox)oEditor.FindName("oItemData")).Text = "Saved content";
                                    var oSaveEvent = oEditor.Dispatcher.InvokeAsync(() =>
                                    {
                                        oWatch.Restart();
                                        typeof(ItemEditor).GetMethod("oSaveItemButton_Click",
                                            BindingFlags.Instance | BindingFlags.NonPublic)
                                            .Invoke(oEditor, new object[] { null, null });
                                        Check(oWatch.Elapsed < TimeSpan.FromSeconds(3),
                                            "Saving returns control while recipient validation downloads an issuer");
                                    });
                                    PumpUntil(() => oSaveEvent.Task.IsCompleted);
                                    oSaveEvent.Task.GetAwaiter().GetResult();
                                }
                                else
                                {
                                    Check(oSave.IsEnabled, "Windows saving remains available while certificates load");
                                    oMode.SelectedIndex = 1;
                                    Check(!oSave.IsEnabled && !oShare.IsEnabled,
                                        "Certificate saving and selection wait for completed background validation");
                                }
                                PumpUntil(() => oRequested.Task.IsCompleted);
                                bool bDispatched = false;
                                oEditor.Dispatcher.BeginInvoke(new Action(() => bDispatched = true));
                                PumpUntil(() => bDispatched);
                                Check(!oRelease.Task.IsCompleted,
                                    sScenario + " dispatcher runs while a certificate issuer response is pending");
                                if (sScenario == "close")
                                {
                                    typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance |
                                        BindingFlags.NonPublic).SetValue(oEditor, false);
                                    oEditor.Close();
                                }
                                oRelease.SetResult(true);
                                if (sScenario == "save")
                                {
                                    PumpUntil(() => (bool)typeof(ItemEditor).GetField("bCompleted",
                                        BindingFlags.Instance | BindingFlags.NonPublic)
                                        .GetValue(oEditor));
                                    using (CryptureEntities oContext = new CryptureEntities())
                                        oStored = DatabaseOperations.LoadItem(oContext.Items.Single().ItemId);
                                    Check(Encoding.Unicode.GetString(ItemCryptography.Decrypt(oStored,
                                        oStored.Instances.Single(), oLeaf)) == "Saved content",
                                        "Saving completes after background certificate validation " +
                                        "and preserves content");
                                }
                                else
                                {
                                    PumpUntil(() => oEditor.CertificateLoading.IsCompleted);
                                    oEditor.CertificateLoading.GetAwaiter().GetResult();
                                    Check(sScenario == "close" ? oShare.Items.Count == 0 :
                                        oShare.Items.Count == 1 && oShare.IsEnabled && oSave.IsEnabled,
                                        sScenario + " certificate results respect the editor lifecycle");
                                }
                            }
                        }
                        finally
                        {
                            if (oEditor != null)
                            {
                                typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance |
                                    BindingFlags.NonPublic).SetValue(oEditor, false);
                                oEditor.Close();
                            }
                            oRelease.TrySetResult(true);
                            oCancellation.Cancel();
                            oListener.Stop();
                            try { oServer.GetAwaiter().GetResult(); }
                            catch (OperationCanceledException) { }
                        }
                    }
                }
            }
        }
        finally
        {
            CryptureEntities.ConnectionString = sPreviousConnection;
            oSettings.AllowSelfSignedCertificates = bSelfSigned;
            oSettings.PerformCertificateRevocationCheck = bRevocation;
            oSettings["ShowUntrustedCertificates"] = bUntrusted;
            oSettings["AutomaticallyAddedCertificatesList"] = oAutomatic;
        }
    }

    private static X509Certificate2 EccCertificate(CngKey oKey,
        X509KeyUsageFlags oUsage = X509KeyUsageFlags.KeyAgreement)
    {
        using (ECDsaCng oSigner = new ECDsaCng(oKey))
        {
            CertificateRequest oRequest = new CertificateRequest("CN=ECC Encryption Test", oSigner,
                HashAlgorithmName.SHA256);
            oRequest.CertificateExtensions.Add(new X509KeyUsageExtension(oUsage, true));
            X509Certificate2 oCert = oRequest.Create(oRequest.SubjectName,
                X509SignatureGenerator.CreateForECDsa(oSigner), DateTimeOffset.Now.AddDays(-1),
                DateTimeOffset.Now.AddDays(1), new byte[] { 2, 3, 4 });
            using (SafeNCryptKeyHandle oHandle = oKey.Handle)
            {
                TestKeyContext oContext = new TestKeyContext
                {
                    Size = Marshal.SizeOf(typeof(TestKeyContext)), Handle = oHandle.DangerousGetHandle(),
                    KeySpec = UInt32.MaxValue
                };
                if (!CertSetCertificateContextProperty(oCert.Handle, 5, 1, ref oContext))
                {
                    oCert.Dispose();
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }
            }
            return oCert;
        }
    }

    private static void TestCertificateAlgorithms(string sDirectory, X509Certificate2 oRsaCert)
    {
        Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = true;
        Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = false;
        foreach (CngAlgorithm oAlgorithm in new[] { CngAlgorithm.ECDiffieHellmanP256,
            CngAlgorithm.ECDiffieHellmanP384, CngAlgorithm.ECDiffieHellmanP521 })
        {
            using (CngKey oKey = CngKey.Create(oAlgorithm, null, new CngKeyCreationParameters
            {
                KeyUsage = CngKeyUsages.KeyAgreement | CngKeyUsages.Signing
            }))
            using (X509Certificate2 oCert = EccCertificate(oKey))
            using (X509Certificate2 oSigning = EccCertificate(oKey, X509KeyUsageFlags.DigitalSignature))
            {
                Check(CertificateOperations.CheckCertificateStatus(oCert), "Accept " + oAlgorithm + " certificate");
                Check(CertificateUsageFilter.Read().Matches(oCert), "Default usage filters retain " + oAlgorithm);
                Check(!CertificateOperations.CheckCertificateStatus(oSigning), "Reject signing-only " + oAlgorithm);
                TestRecipientEnvelope(oCert, oRsaCert, oAlgorithm.Algorithm);
                TestAlgorithmVault(sDirectory, oCert, oAlgorithm.Algorithm);
            }
        }

        using (CngKey oSigningKey = CngKey.Create(CngAlgorithm.ECDsaP256))
        using (X509Certificate2 oSigning = EccCertificate(oSigningKey))
        {
            byte[] oWrapped = CertificateKeyProtection.Wrap(oSigning, new byte[64]);
            RejectCryptography(() => CertificateKeyProtection.Unwrap(oSigning, oWrapped),
                "Reject ECDSA private key incorrectly labeled for key agreement");
        }

        TestPersistedCertificate(false, oRsaCert);
        Console.WriteLine("Native ML-KEM available: " + CertificateKeyProtection.IsPostQuantumSupported);
        if (!CertificateKeyProtection.IsPostQuantumSupported)
        {
            using (RSA oIssuer = new RSACng(2048))
            using (X509Certificate2 oUnsupported = MlKemCertificate(oIssuer, "768", new byte[1184]))
            {
                Check(!CertificateOperations.CheckCertificateStatus(oUnsupported),
                    "Unavailable ML-KEM certificate is excluded from encryption choices");
                try
                {
                    CertificateKeyProtection.Wrap(oUnsupported, new byte[64]);
                    throw new Exception("ML-KEM must not fall back when unavailable.");
                }
                catch (PlatformNotSupportedException)
                {
                    Check(true, "Unavailable ML-KEM reports platform support without fallback");
                }
            }
            Console.WriteLine("SKIP: Native ML-KEM round trips require Windows ML-KEM support.");
            return;
        }

        TestPersistedCertificate(true, oRsaCert);
        foreach (string sParameters in new[] { "512", "768", "1024" })
        {
            CngKeyCreationParameters oOptions = new CngKeyCreationParameters();
            oOptions.Parameters.Add(new CngProperty("ParameterSetName",
                Encoding.Unicode.GetBytes(sParameters + "\0"), CngPropertyOptions.None));
            using (CngKey oKey = CngKey.Create(new CngAlgorithm("ML-KEM"), null, oOptions))
            using (MLKem oKem = new MLKemCng(oKey))
            using (RSA oIssuer = new RSACng(2048))
            using (X509Certificate2 oCert = MlKemCertificate(oIssuer, sParameters, oKem.ExportEncapsulationKey()))
            using (SafeNCryptKeyHandle oHandle = oKey.Handle)
            {
                TestKeyContext oContext = new TestKeyContext
                {
                    Size = Marshal.SizeOf(typeof(TestKeyContext)), Handle = oHandle.DangerousGetHandle(),
                    KeySpec = UInt32.MaxValue
                };
                if (!CertSetCertificateContextProperty(oCert.Handle, 5, 1, ref oContext))
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                Check(oCert.HasPrivateKey, "Associate ephemeral ML-KEM-" + sParameters + " private key");
                CertificateKeyProtection.ValidateForEncryption(oCert);
                CertificateRequest oIssuerRequest = new CertificateRequest("CN=Test Issuer", oIssuer,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                oIssuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                oIssuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
                using (X509Certificate2 oIssuerCertificate = oIssuerRequest.CreateSelfSigned(
                    DateTimeOffset.Now.AddDays(-2), DateTimeOffset.Now.AddDays(2)))
                using (X509Chain oChain = new X509Chain())
                {
                    oChain.ChainPolicy.ExtraStore.Add(oIssuerCertificate);
                    oChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    oChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                    Check(oChain.Build(oCert) && oChain.ChainElements.Count == 2 && oChain.ChainStatus.All(s =>
                        (s.Status & ~X509ChainStatusFlags.UntrustedRoot) == 0),
                        "Windows validates ML-KEM-" + sParameters + " certificate with a test issuer");
                }
                TestRecipientEnvelope(oCert, oRsaCert, "ML-KEM-" + sParameters);
                TestAlgorithmVault(sDirectory, oCert, "ML-KEM-" + sParameters);
            }
        }
    }

    private static void TestPersistedCertificate(bool bPostQuantum, X509Certificate2 oRsaCert)
    {
        string sName = "Crypture.Test-" + Guid.NewGuid().ToString("N");
        CngKeyCreationParameters oOptions = new CngKeyCreationParameters();
        if (bPostQuantum)
            oOptions.Parameters.Add(new CngProperty("ParameterSetName",
                Encoding.Unicode.GetBytes("768\0"), CngPropertyOptions.None));
        else oOptions.KeyUsage = CngKeyUsages.KeyAgreement | CngKeyUsages.Signing;
        using (CngKey oKey = CngKey.Create(bPostQuantum ? new CngAlgorithm("ML-KEM")
            : CngAlgorithm.ECDiffieHellmanP256, sName, oOptions))
        {
            try
            {
                using (MLKem oKem = bPostQuantum ? new MLKemCng(oKey) : null)
                using (RSA oIssuer = new RSACng(2048))
                using (X509Certificate2 oOriginal = bPostQuantum
                    ? MlKemCertificate(oIssuer, "768", oKem.ExportEncapsulationKey()) : EccCertificate(oKey))
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oOriginal.RawData))
                {
                    TestKeyProvider oProvider = new TestKeyProvider
                    {
                        Container = sName, Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider,
                        KeySpec = UInt32.MaxValue
                    };
                    if (!CertSetCertificateContextProperty(oCert.Handle, 2, 0, ref oProvider))
                        throw new CryptographicException(Marshal.GetLastWin32Error());
                    TestRecipientEnvelope(oCert, oRsaCert, bPostQuantum ? "Persisted ML-KEM" : "Persisted ECDH");
                }
            }
            finally
            {
                oKey.Delete();
            }
        }
        Check(!CngKey.Exists(sName), "Remove temporary persisted test key");
    }

    private static X509Certificate2 MlKemCertificate(RSA oIssuer, string sParameters, byte[] oPublicKey)
    {
        string sOid = "2.16.840.1.101.3.4.4." + (sParameters == "512" ? "1" : sParameters == "768" ? "2" : "3");
        AsnWriter oAlgorithm = new AsnWriter(AsnEncodingRules.DER);
        oAlgorithm.PushSequence();
        oAlgorithm.WriteObjectIdentifier("1.2.840.113549.1.1.11");
        oAlgorithm.WriteNull();
        oAlgorithm.PopSequence();
        AsnWriter oBody = new AsnWriter(AsnEncodingRules.DER);
        oBody.PushSequence();
        Asn1Tag oVersionTag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        oBody.PushSequence(oVersionTag);
        oBody.WriteInteger(2);
        oBody.PopSequence(oVersionTag);
        oBody.WriteInteger(1);
        oBody.WriteEncodedValue(oAlgorithm.Encode());
        oBody.WriteEncodedValue(new X500DistinguishedName("CN=Test Issuer").RawData);
        oBody.PushSequence();
        oBody.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
        oBody.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(1));
        oBody.PopSequence();
        oBody.WriteEncodedValue(new X500DistinguishedName("CN=ML-KEM Test").RawData);
        oBody.PushSequence();
        oBody.PushSequence();
        oBody.WriteObjectIdentifier(sOid);
        oBody.PopSequence();
        oBody.WriteBitString(oPublicKey);
        oBody.PopSequence();
        Asn1Tag oExtensionTag = new Asn1Tag(TagClass.ContextSpecific, 3, true);
        oBody.PushSequence(oExtensionTag);
        oBody.PushSequence();
        oBody.PushSequence();
        oBody.WriteObjectIdentifier("2.5.29.15");
        oBody.WriteBoolean(true);
        oBody.WriteOctetString(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true).RawData);
        oBody.PopSequence();
        oBody.PopSequence();
        oBody.PopSequence(oExtensionTag);
        oBody.PopSequence();
        byte[] oTbs = oBody.Encode();
        AsnWriter oCertificate = new AsnWriter(AsnEncodingRules.DER);
        oCertificate.PushSequence();
        oCertificate.WriteEncodedValue(oTbs);
        oCertificate.WriteEncodedValue(oAlgorithm.Encode());
        oCertificate.WriteBitString(oIssuer.SignData(oTbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        oCertificate.PopSequence();
        return X509CertificateLoader.LoadCertificate(oCertificate.Encode());
    }

    private static void TestRecipientEnvelope(X509Certificate2 oCert, X509Certificate2 oRsaCert, string sName)
    {
        byte[] oPlain = Encoding.UTF8.GetBytes("ECC and post-quantum recipient test\n\u2603");
        User[] oRecipients = { new User { UserId = 8, Certificate = oCert.RawData },
            new User { UserId = 9, Certificate = oRsaCert.RawData } };
        foreach (ContentEncryptionSuite nSuite in Enum.GetValues<ContentEncryptionSuite>())
        {
            string sSuiteName = sName + " " + nSuite;
            Item oItem = new Item { Label = "Algorithm test", ItemType = "text" };
            ItemCryptography.Encrypt(oItem, oPlain, oRecipients, nContentSuite: nSuite);
            Instance oInstance = oItem.Instances.First();
            Check(oItem.Cipher.CipherParams == ItemCryptography.CertificateFormat &&
                ItemCryptography.Decrypt(oItem, oInstance, oCert).SequenceEqual(oPlain), sSuiteName + " round trip");
            Check(ItemCryptography.Decrypt(oItem, oItem.Instances.Last(), oRsaCert).SequenceEqual(oPlain),
                sSuiteName + " mixed RSA recipient round trip");
            byte[] oFirstEnvelope = oInstance.CipherKey.ToArray();
            ItemCryptography.Encrypt(oItem, oPlain, oRecipients, nContentSuite: nSuite);
            oInstance = oItem.Instances.First();
            Check(!oFirstEnvelope.SequenceEqual(oInstance.CipherKey), sSuiteName + " fresh encapsulation per save");
            using (X509Certificate2 oPublicOnly = X509CertificateLoader.LoadCertificate(oCert.RawData))
                RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oPublicOnly),
                    sSuiteName + " requires a private key");
            RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oRsaCert),
                sSuiteName + " rejects incorrect recipient algorithm");
            foreach (int nOffset in new[] { 0, 4, 8, oInstance.CipherKey.Length - 17, oInstance.CipherKey.Length - 1 })
            {
                oInstance.CipherKey[nOffset] ^= 1;
                RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
                    sSuiteName + " rejects modified key envelope at " + nOffset);
                oInstance.CipherKey[nOffset] ^= 1;
            }
            byte[] oSaved = oInstance.CipherKey;
            foreach (byte[] oBadEnvelope in new[] { new byte[0], oSaved.Take(oSaved.Length - 1).ToArray(),
                oSaved.Concat(new byte[1]).ToArray(), new byte[4097] })
            {
                oInstance.CipherKey = oBadEnvelope;
                RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
                    sSuiteName + " rejects malformed envelope of " + oBadEnvelope.Length + " bytes");
            }
            oInstance.CipherKey = oSaved;
            oInstance.UserId++;
            RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
                sSuiteName + " authenticates the recipient identity");
            oInstance.UserId--;
            oItem.Cipher.CipherParams = oInstance.CipherParams = ItemCryptography.AuthenticatedFormat;
            RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
                sSuiteName + " rejects a format downgrade");
            oItem.Cipher.CipherParams = oInstance.CipherParams = ItemCryptography.CertificateFormat;
            oItem.Label = "Tampered";
            RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
                sSuiteName + " authenticates item metadata");
        }
    }

    private static void TestAlgorithmVault(string sDirectory, X509Certificate2 oCert, string sName)
    {
        string sPath = Path.Combine(sDirectory, sName + ".cryptdb");
        DatabaseOperations.CreateDatabase(sPath,
            File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SQLite.sql")));
        CryptureEntities.DatabasePath = sPath;
        User oUser = new User { Certificate = oCert.RawData };
        using (CryptureEntities oContent = new CryptureEntities())
        {
            oContent.Users.Add(oUser);
            oContent.SaveChanges();
        }
        byte[] oPlain = Encoding.UTF8.GetBytes("Persisted " + sName);
        DatabaseOperations.SaveItem(new Item { Label = sName, ItemType = "text" }, oPlain, new[] { oUser });
        long nId;
        using (CryptureEntities oContent = new CryptureEntities()) nId = oContent.Items.Single().ItemId;
        Item oStored = DatabaseOperations.LoadItem(nId);
        Check(oStored.Cipher.CipherParams == ItemCryptography.CertificateFormat &&
            ItemCryptography.Decrypt(oStored, oStored.Instances.Single(), oCert).SequenceEqual(oPlain),
            sName + " Vault save and reload");
        DatabaseOperations.SaveItem(oStored, oPlain, null, PrincipalProtection.LocalUserDescriptor);
        Check(ItemCryptography.Decrypt(DatabaseOperations.LoadItem(nId)).SequenceEqual(oPlain),
            sName + " conversion to Windows protection");
    }

    private static void EncryptPreviousRsaFormat(Item oItem, byte[] oPlain, X509Certificate2 oCert)
    {
        byte[] oKeys = new byte[64];
        using (RandomNumberGenerator oRandom = RandomNumberGenerator.Create()) oRandom.GetBytes(oKeys);
        try
        {
            using (Aes oAes = new AesCng())
            {
                oAes.Key = oKeys.Take(32).ToArray();
                using (ICryptoTransform oEncryptor = oAes.CreateEncryptor())
                    oItem.Cipher = new Cipher
                    {
                        CipherParams = 1, CipherVector = oAes.IV,
                        CipherText = oEncryptor.TransformFinalBlock(oPlain, 0, oPlain.Length)
                    };
            }
            byte[] oSignature;
            using (HMACSHA256 oHmac = new HMACSHA256(oKeys.Skip(32).ToArray()))
            using (MemoryStream oStream = new MemoryStream())
            using (BinaryWriter oWriter = new BinaryWriter(oStream))
            {
                oWriter.Write("Crypture");
                oWriter.Write((long)1);
                oWriter.Write(oItem.Label);
                oWriter.Write(oItem.ItemType);
                oWriter.Write(oItem.Cipher.CipherVector);
                oWriter.Write(oItem.Cipher.CipherText.Length);
                oWriter.Write(oItem.Cipher.CipherText);
                oSignature = oHmac.ComputeHash(oStream.ToArray());
            }
            using (RSA oPublic = oCert.GetRSAPublicKey())
                oItem.Instances.Add(new Instance
                {
                    UserId = 1, CipherParams = 1, CipherKey = oPublic.Encrypt(oKeys, RSAEncryptionPadding.OaepSHA1),
                    Signature = oSignature
                });
        }
        finally
        {
            Array.Clear(oKeys, 0, oKeys.Length);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TestKeyContext
    {
        internal int Size;
        internal IntPtr Handle;
        internal uint KeySpec;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TestKeyProvider
    {
        internal string Container;
        internal string Provider;
        internal uint ProviderType;
        internal uint Flags;
        internal uint ParameterCount;
        internal IntPtr Parameters;
        internal uint KeySpec;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertSetCertificateContextProperty(IntPtr pCert, uint nProperty, uint nFlags,
        ref TestKeyProvider oProvider);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertSetCertificateContextProperty(IntPtr pCert, uint nProperty, uint nFlags,
        ref TestKeyContext oContext);
}
