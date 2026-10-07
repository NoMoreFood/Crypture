using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Reflection;
using System.Xml.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using Crypture;

internal static partial class RegressionTests
{
    private static int nChecks;

    private static void Check(bool bCondition, string sName)
    {
        if (!bCondition) throw new Exception("FAIL: " + sName);
        nChecks++;
        Console.WriteLine("PASS: " + sName);
    }

    private static void Reject(Action oAction, string sName)
    {
        try
        {
            oAction();
        }
        catch (Exception)
        {
            Check(true, sName);
            return;
        }
        throw new Exception("FAIL: " + sName);
    }

    private static X509Certificate2 Certificate(RSA oKey, string sName, DateTimeOffset oStart,
        DateTimeOffset oEnd, X509KeyUsageFlags oUsage = X509KeyUsageFlags.KeyEncipherment)
    {
        CertificateRequest oRequest = new CertificateRequest("CN=" + sName, oKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        oRequest.CertificateExtensions.Add(new X509KeyUsageExtension(oUsage, true));
        return oRequest.CreateSelfSigned(oStart, oEnd);
    }

    [STAThread]
    private static int Main()
    {
        if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_FIDO_HARDWARE") == "1")
            return RunFidoHardware();
        if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_AD_ROLE") is string sIdentityRole)
            return RunSqlServerIdentityTests(sIdentityRole);
        if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_DEFAULTS_STARTUP") == "1")
            return RunConfiguredStartup();
        if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_CONCURRENCY_ROLE") is string sRole)
            return RunConcurrencyWorker(sRole);
        if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_PORTABLE_DIRECTORY") != null)
            return RunPortableStartupWorker();
        AppContext.SetData("APP_CONFIG_FILE", Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config"));
        string sDirectory = Path.Combine(Path.GetTempPath(), "Crypture.Tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sDirectory);
        using UserPreferenceSnapshot oPreferences = new UserPreferenceSnapshot();
        try
        {
            if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_PREFERENCES_ONLY") == "1")
            {
                TestUserPreferences();
                return 0;
            }
            if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_CONFIG_STARTUP") == "1")
            {
                TestCertificateUsageStartup();
                return 0;
            }
            if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_DEFAULTS_ONLY") == "1" ||
                Environment.GetEnvironmentVariable("CRYPTURE_TEST_GENERATOR_ONLY") == "1" ||
                Environment.GetEnvironmentVariable("CRYPTURE_TEST_VAULT_OPERATIONS_ONLY") == "1" ||
                Environment.GetEnvironmentVariable("CRYPTURE_TEST_POPUP_ONLY") == "1")
            {
                Application oApplication = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                oApplication.Resources = new ResourceDictionary
                {
                    Source = new Uri("pack://application:,,,/Crypture;component/Themes/Controls.xaml", UriKind.Absolute)
                };
                try
                {
                    if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_POPUP_ONLY") == "1") TestPopups();
                    else if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_VAULT_OPERATIONS_ONLY") == "1")
                        TestVaultOperations(sDirectory);
                    else if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_GENERATOR_ONLY") == "1")
                    {
                        TestPasswordGeneratorLayout();
                        TestPasswordGeneratorDefaults(sDirectory);
                    }
                    else TestConfigurationDefaults(sDirectory);
                }
                finally { oApplication.Shutdown(); }
                Console.WriteLine("Completed " + nChecks + " regression checks.");
                return 0;
            }
            TestPortableExtraction(sDirectory);
            using (RSA oKey = new RSACng(2048))
            using (RSA oOtherKey = new RSACng(2048))
            using (X509Certificate2 oCert = Certificate(oKey, "Test", DateTimeOffset.Now.AddDays(-1),
                DateTimeOffset.Now.AddDays(1)))
            using (X509Certificate2 oOtherCert = Certificate(oOtherKey, "Other", DateTimeOffset.Now.AddDays(-1),
                DateTimeOffset.Now.AddDays(1)))
            {
                if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_FIDO_ONLY") == "1")
                {
                    TestFidoEncryption(sDirectory, oCert);
                    Application oApplication = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                    oApplication.Resources = new ResourceDictionary
                    {
                        Source = new Uri("pack://application:,,,/Crypture;component/Themes/Controls.xaml", UriKind.Absolute)
                    };
                    try
                    {
                        TestFidoEditor(sDirectory);
                        TestFidoConfiguration(sDirectory, oCert);
                    }
                    finally { oApplication.Shutdown(); }
                    Console.WriteLine("Completed " + nChecks + " FIDO2 regression checks.");
                    return 0;
                }
                if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_SQLSERVER_ONLY") == "1")
                {
                    Application oApplication = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                    oApplication.Resources = new ResourceDictionary
                    {
                        Source = new Uri("pack://application:,,,/Crypture;component/Themes/Controls.xaml",
                            UriKind.Absolute)
                    };
                    try { TestSqlServerBackend(sDirectory, oCert, oOtherCert); }
                    finally { oApplication.Shutdown(); }
                    Console.WriteLine("Completed " + nChecks + " SQL Server regression checks.");
                    return 0;
                }
                TestSqlServerBackend(sDirectory, oCert, oOtherCert);
                TestUserPreferences();
                TestConcurrentDatabase(sDirectory, oCert, oOtherCert);
                if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_CONCURRENCY_ONLY") == "1") return 0;
                TestContentEncryptionSuites(sDirectory, oCert, oOtherCert);
                TestEncryption(oCert, oOtherCert);
                TestFidoEncryption(sDirectory, oCert);
                TestTotpAlgorithms(oCert);
                TestPrincipalProtection();
                TestPasswordGeneration();
                TestClipboardTimeout();
                TestDirectoryResolution();
                TestCertificates(oKey, oCert);
                TestCertificateVisibility(oKey);
                TestCertificateAlgorithms(sDirectory, oCert);
                TestPersonalCertificateStores();
                TestCertificateUsageFilters(oKey);
                TestCompression(sDirectory);
                TestHealthChecks(sDirectory, oKey, oCert);
                TestRecovery(sDirectory, oCert, oOtherCert);
                TestDatabase(sDirectory, oCert, oOtherCert);
            }
            Console.WriteLine("Completed " + nChecks + " regression checks.");
            return 0;
        }
        catch (Exception oError)
        {
            Console.Error.WriteLine(oError);
            return 1;
        }
        finally
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            SqliteConnection.ClearAllPools();
            Directory.Delete(sDirectory, true);
        }
    }

    private static int RunPortableStartupWorker()
    {
        AppContext.SetData("APP_CONTEXT_BASE_DIRECTORY",
            Environment.GetEnvironmentVariable("CRYPTURE_TEST_PORTABLE_BASE"));
        AppContext.SetData("NATIVE_DLL_SEARCH_DIRECTORIES",
            Environment.GetEnvironmentVariable("CRYPTURE_TEST_PORTABLE_DIRECTORY"));
        if (PortableStartup.TryRestartWithLocalExtraction()) return 0;
        string sResult = Environment.GetEnvironmentVariable("CRYPTURE_TEST_PORTABLE_RESULT");
        File.WriteAllLines(sResult + ".tmp",
            new[] { Environment.GetEnvironmentVariable("DOTNET_BUNDLE_EXTRACT_BASE_DIR") ?? "",
                Environment.ProcessId.ToString() }.Concat(Environment.GetCommandLineArgs().Skip(1)));
        File.Move(sResult + ".tmp", sResult);
        return 0;
    }

    private static void TestPortableExtraction(string sDirectory)
    {
        string[] sArguments = [@"Vault folder\test vault.db", "argument with \"quotes\"", @"trailing\", "Unicode: \u2603"];
        foreach (string sScenario in new[] { "Valid", "Failed", "Retried", "Unwritable" })
        {
            string sRoot = Path.Combine(sDirectory, "Portable", sScenario);
            string sNativeDirectory = Path.Combine(sRoot, "Native");
            string sApplicationDirectory = Path.Combine(sRoot, "Application");
            Directory.CreateDirectory(sNativeDirectory);
            Directory.CreateDirectory(sApplicationDirectory);
            if (sScenario == "Valid")
                File.Copy(Path.Combine(Environment.SystemDirectory, "version.dll"),
                    Path.Combine(sNativeDirectory, "version.dll"));
            else File.WriteAllBytes(Path.Combine(sNativeDirectory, "Invalid.dll"), [1, 2, 3]);
            string sLocalCache = Path.Combine(sApplicationDirectory, ".net");
            if (sScenario == "Unwritable") File.WriteAllText(sLocalCache, "The cache path is occupied by a file.");
            string sResult = Path.Combine(sRoot, "Result.txt");
            ProcessStartInfo oStart = new ProcessStartInfo(Environment.ProcessPath)
            {
                UseShellExecute = false, CreateNoWindow = true
            };
            foreach (string sArgument in sArguments) oStart.ArgumentList.Add(sArgument);
            oStart.Environment["CRYPTURE_TEST_PORTABLE_DIRECTORY"] = sNativeDirectory;
            oStart.Environment["CRYPTURE_TEST_PORTABLE_BASE"] = sApplicationDirectory;
            oStart.Environment["CRYPTURE_TEST_PORTABLE_RESULT"] = sResult;
            oStart.Environment.Remove("DOTNET_BUNDLE_EXTRACT_BASE_DIR");
            if (sScenario == "Retried")
                oStart.Environment["DOTNET_BUNDLE_EXTRACT_BASE_DIR"] = sLocalCache + Path.DirectorySeparatorChar;
            using Process oWorker = Process.Start(oStart);
            Check(oWorker.WaitForExit(10000) && oWorker.ExitCode == 0, sScenario + " portable startup worker exits");
            Stopwatch oWait = Stopwatch.StartNew();
            while (!File.Exists(sResult) && oWait.ElapsedMilliseconds < 10000)
                System.Threading.Thread.Sleep(20);
            Check(File.Exists(sResult), sScenario + " portable startup completes without a restart loop");
            string[] sReport = File.ReadAllLines(sResult);
            bool bRestarted = sScenario == "Failed";
            Check((int.Parse(sReport[1]) != oWorker.Id) == bRestarted,
                sScenario + " portable startup restarts only when a library fails and the local cache is available");
            string sExpectedCache = sScenario == "Retried" ? sLocalCache + Path.DirectorySeparatorChar :
                bRestarted ? sLocalCache : "";
            Check(sReport[0] == sExpectedCache, sScenario + " portable startup uses the expected extraction directory");
            Check(sReport.Skip(2).SequenceEqual(sArguments),
                sScenario + " portable startup preserves command-line arguments");
        }
    }

    private static void TestEncryption(X509Certificate2 oCert, X509Certificate2 oOtherCert)
    {
        User[] oUsers = { new User { UserId = 1, Certificate = oCert.RawData },
            new User { UserId = 2, Certificate = oOtherCert.RawData } };
        byte[][] oInputs = { new byte[0], Encoding.Unicode.GetBytes("Password: \u2603\nSecond line"),
            Enumerable.Range(0, 8193).Select(i => (byte)i).ToArray() };
        foreach (byte[] oInput in oInputs)
        {
            Item oItem = new Item { Label = "Label", ItemType = "text" };
            ItemCryptography.Encrypt(oItem, oInput, oUsers);
            Check(ItemCryptography.Decrypt(oItem, oItem.Instances.First(), oCert).SequenceEqual(oInput),
                "Authenticated round trip, " + oInput.Length + " bytes");
            Check(ItemCryptography.Decrypt(oItem, oItem.Instances.Last(), oOtherCert).SequenceEqual(oInput),
                "Second recipient round trip, " + oInput.Length + " bytes");
        }

        Item oTampered = new Item { Label = "Label", ItemType = "text" };
        ItemCryptography.Encrypt(oTampered, oInputs[1], oUsers);
        Instance oInstance = oTampered.Instances.First();
        oTampered.Cipher.CipherText[0] ^= 1;
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oCert), "Reject altered ciphertext");
        oTampered.Cipher.CipherText[0] ^= 1;
        oTampered.Cipher.CipherVector[0] ^= 1;
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oCert), "Reject altered IV");
        oTampered.Cipher.CipherVector[0] ^= 1;
        oInstance.Signature[0] ^= 1;
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oCert), "Reject altered authentication tag");
        oInstance.Signature[0] ^= 1;
        oTampered.Label = "Changed";
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oCert), "Reject altered label");
        oTampered.Label = "Label";
        oTampered.ItemType = ".bin";
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oCert), "Reject altered item type");
        oTampered.ItemType = "text";
        oTampered.Cipher.CipherParams = 0;
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oCert), "Reject mismatched formats");
        oInstance.CipherParams = 0;
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oCert), "Reject downgrade to legacy format");
        oTampered.Cipher.CipherParams = 99;
        oInstance.CipherParams = 99;
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oCert), "Reject unknown format");
        oTampered.Cipher.CipherParams = ItemCryptography.CertificateFormat;
        oInstance.CipherParams = ItemCryptography.CertificateFormat;
        Reject(() => ItemCryptography.Decrypt(oTampered, oInstance, oOtherCert), "Reject wrong private key");
        Reject(() => ItemCryptography.Encrypt(new Item { Label = "Empty", ItemType = "text" },
            new byte[0], new User[0]), "Reject empty recipient list");

        using (Aes oAes = new AesCng())
        using (RSA oPublic = oCert.GetRSAPublicKey())
        using (ICryptoTransform oEncryptor = oAes.CreateEncryptor())
        {
            Item oLegacy = new Item
            {
                Label = "Legacy", ItemType = "text", Cipher = new Cipher
                {
                    CipherVector = oAes.IV,
                    CipherText = oEncryptor.TransformFinalBlock(oInputs[1], 0, oInputs[1].Length)
                }
            };
            Instance oLegacyInstance = new Instance
            {
                CipherKey = oPublic.Encrypt(oAes.Key, RSAEncryptionPadding.Pkcs1), Signature = new byte[0]
            };
            Check(ItemCryptography.Decrypt(oLegacy, oLegacyInstance, oCert).SequenceEqual(oInputs[1]),
                "Read legacy encryption");
        }
    }

    private static void TestCertificates(RSA oKey, X509Certificate2 oCert)
    {
        Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = true;
        Crypture.Properties.Settings.Default.PerformCertificateRevocationCheck = false;
        Check(CertificateOperations.CheckCertificateStatus(oCert), "Accept valid self-signed encryption certificate");
        Check(new User { Certificate = oCert.RawData }.IsSelfSigned, "Identify self-signed certificate safely");
        using (X509Certificate2 oExpired = Certificate(oKey, "Expired", DateTimeOffset.Now.AddDays(-2),
            DateTimeOffset.Now.AddDays(-1)))
            Check(!CertificateOperations.CheckCertificateStatus(oExpired), "Reject expired self-signed certificate");
        using (X509Certificate2 oFuture = Certificate(oKey, "Future", DateTimeOffset.Now.AddDays(1),
            DateTimeOffset.Now.AddDays(2)))
            Check(!CertificateOperations.CheckCertificateStatus(oFuture), "Reject not-yet-valid certificate");
        using (X509Certificate2 oSigning = Certificate(oKey, "Signing", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1), X509KeyUsageFlags.DigitalSignature))
            Check(!CertificateOperations.CheckCertificateStatus(oSigning), "Reject signing-only certificate");
        using (RSA oWeakKey = new RSACng(1024))
        using (X509Certificate2 oWeak = Certificate(oWeakKey, "Weak", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1)))
            Check(!CertificateOperations.CheckCertificateStatus(oWeak), "Reject short RSA key");
        byte[] oBrokenData = oCert.RawData;
        oBrokenData[oBrokenData.Length - 1] ^= 1;
        using (X509Certificate2 oBroken = X509CertificateLoader.LoadCertificate(oBrokenData))
            Check(!CertificateOperations.CheckCertificateStatus(oBroken), "Reject invalid self-signature");
        CertificateRequest oRequest = new CertificateRequest("CN=Missing issuer", oKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using (X509Certificate2 oUnchained = oRequest.Create(new X500DistinguishedName("CN=Absent CA"),
            X509SignatureGenerator.CreateForRSA(oKey, RSASignaturePadding.Pkcs1), DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1), new byte[] { 1, 2, 3, 4 }))
            Check(!CertificateOperations.CheckCertificateStatus(oUnchained),
                "Reject incomplete chain with one element");
        Crypture.Properties.Settings.Default.AllowSelfSignedCertificates = false;
        Check(!CertificateOperations.CheckCertificateStatus(oCert), "Honor self-signed certificate setting");
        Check(new User { Certificate = new byte[] { 1, 2 } }.Name == "Invalid certificate",
            "Display damaged certificate safely");
    }

    private static void TestPrincipalProtection()
    {
        ProtectionPrincipal oUser = new ProtectionPrincipal(CertificateOperations.CurrentUserSid);
        ProtectionPrincipal oGroup = new ProtectionPrincipal("S-1-5-32-545");
        string sAny = PrincipalProtection.CreateDescriptor(new[] { oUser, oGroup, oUser }, false);
        var oParsed = PrincipalProtection.ParseDescriptor(sAny, out bool bAll);
        Check(!bAll && oParsed.Count == 2 && oParsed.Any(p => p.Sid == oUser.Sid),
            "Build and parse deduplicated OR policies");
        string sAll = PrincipalProtection.CreateDescriptor(new[] { oUser, oGroup }, true);
        Check(PrincipalProtection.ParseDescriptor(sAll, out bAll).Count == 2 && bAll,
            "Build and parse AND policies");
        Check(ProtectionPrincipal.Resolve(oUser.Name).Sid == oUser.Sid, "Resolve a Windows account name to its SID");
        Check(ProtectionPrincipal.Resolve(oUser.Sid).Sid == oUser.Sid, "Accept direct SID entry");
        Reject(() => PrincipalProtection.CreateDescriptor(new ProtectionPrincipal[0], false),
            "Reject an empty principal policy");
        Reject(() => PrincipalProtection.ParseDescriptor("SID=S-1-5-18 OR LOCAL=machine", out _),
            "Reject injected descriptor syntax");
        Reject(() => PrincipalProtection.ParseDescriptor("SID=S-1-5-18 AND SID=S-1-5-19 OR SID=S-1-5-20", out _),
            "Reject mixed policies the editor cannot represent");
        Reject(() => PrincipalProtection.ParseDescriptor(new string('X', 16001), out _),
            "Bound protection policy length");
        Reject(() => PrincipalProtection.CreateDescriptor(Enumerable.Range(1, 101)
            .Select(i => new ProtectionPrincipal("S-1-5-21-1-2-3-" + i, "Test principal")), false),
            "Bound Windows recipient count");
        Reject(() => ProtectionPrincipal.Resolve(" "), "Reject blank principal input");
        Reject(() => PrincipalProtection.Unprotect(new byte[] { 1, 2, 3 }), "Reject damaged native DPAPI key blob");

        Reject(() => PrincipalProtection.ParseDescriptor("LOCAL=logon", out _),
            "Reject session-only protection that would lose access after sign-out");
        if (!PrincipalProtection.IsDomainJoined)
        {
            string sFailure = null;
            try
            {
                PrincipalProtection.Protect(new byte[64], "SID=" + oUser.Sid + " OR SID=S-1-1-0");
            }
            catch (CryptographicException oError)
            {
                sFailure = oError.Message;
            }
            Check(sFailure != null && sFailure.Contains("Active Directory") &&
                sFailure.Contains("Saving Account's Local Windows Profile") &&
                sFailure.Contains("All Users on This Computer"),
                "Standalone SID encryption reports supported scopes instead of native error 0x80090034");
        }

        foreach (string sScope in new[] { PrincipalProtection.LocalUserDescriptor,
            PrincipalProtection.LocalMachineDescriptor })
        foreach (byte[] oPlain in new[] { new byte[0], Encoding.Unicode.GetBytes("Windows secret \u2603"),
            Enumerable.Range(0, 256).Select(i => (byte)i).ToArray() })
        {
            Item oItem = new Item { Label = "Windows protected", ItemType = "text" };
            ItemCryptography.Encrypt(oItem, oPlain, null, sScope);
            Check(oItem.Instances.Count == 0 && oItem.Cipher.CipherParams == ItemCryptography.PrincipalFormat,
                "DPAPI item does not require certificates or certificate recipients");
            Check(ItemCryptography.Decrypt(oItem).SequenceEqual(oPlain),
                "Native DPAPI-NG " + sScope + " round trip, " + oPlain.Length + " bytes");
        }

        Item oProtected = new Item { Label = "Original", ItemType = "text" };
        byte[] oContent = Encoding.Unicode.GetBytes("Authenticated principal content");
        ItemCryptography.Encrypt(oProtected, oContent, null, PrincipalProtection.LocalUserDescriptor);
        oProtected.Cipher.CipherText[0] ^= 1;
        Reject(() => ItemCryptography.Decrypt(oProtected), "Reject DPAPI ciphertext tampering");
        oProtected.Cipher.CipherText[0] ^= 1;
        oProtected.Cipher.CipherVector[0] ^= 1;
        Reject(() => ItemCryptography.Decrypt(oProtected), "Reject DPAPI IV tampering");
        oProtected.Cipher.CipherVector[0] ^= 1;
        oProtected.Cipher.Signature[0] ^= 1;
        Reject(() => ItemCryptography.Decrypt(oProtected), "Reject DPAPI authentication tag tampering");
        oProtected.Cipher.Signature[0] ^= 1;
        oProtected.Label = "Changed";
        Reject(() => ItemCryptography.Decrypt(oProtected), "Authenticate DPAPI item labels");
        oProtected.Label = "Original";
        oProtected.ItemType = ".bin";
        Reject(() => ItemCryptography.Decrypt(oProtected), "Authenticate DPAPI item type");
        oProtected.ItemType = "text";
        oProtected.Cipher.ProtectionDescriptor = sAny;
        Reject(() => ItemCryptography.Decrypt(oProtected), "Reject recipient policy substitution");
        oProtected.Cipher.ProtectionDescriptor = PrincipalProtection.LocalMachineDescriptor;
        Reject(() => ItemCryptography.Decrypt(oProtected), "Reject local profile to machine policy substitution");
        oProtected.Cipher.ProtectionDescriptor = PrincipalProtection.LocalUserDescriptor;
        byte[] oProtectedKey = oProtected.Cipher.ProtectedKey;
        oProtected.Cipher.ProtectedKey = PrincipalProtection.Protect(
            new byte[64], PrincipalProtection.LocalUserDescriptor);
        Reject(() => ItemCryptography.Decrypt(oProtected), "Reject replacement DPAPI key blob");
        oProtected.Cipher.ProtectedKey = oProtectedKey;
        oProtected.Cipher.CipherParams = ItemCryptography.AuthenticatedFormat;
        Reject(() => ItemCryptography.Decrypt(oProtected), "Reject DPAPI format downgrade");
        oProtected.Cipher.CipherParams = ItemCryptography.PrincipalFormat;
        Check(ItemCryptography.Decrypt(oProtected).SequenceEqual(oContent),
            "Tamper checks preserve the valid DPAPI item");

        string sDomainSids = Environment.GetEnvironmentVariable("CRYPTURE_TEST_DOMAIN_SIDS");
        if (String.IsNullOrWhiteSpace(sDomainSids))
        {
            Console.WriteLine("SKIP: Domain SID authorization requires " +
                "CRYPTURE_TEST_DOMAIN_SIDS and AD key distribution.");
            return;
        }
        ProtectionPrincipal[] oDomainPrincipals = sDomainSids.Split(';')
            .Select(s => ProtectionPrincipal.Resolve(s)).ToArray();
        ItemCryptography.Encrypt(oProtected, oContent, null,
            PrincipalProtection.CreateDescriptor(oDomainPrincipals, false));
        Check(ItemCryptography.Decrypt(oProtected).SequenceEqual(oContent), "Domain SID policy round trip");
    }

    private sealed class SequenceRandom : RandomNumberGenerator
    {
        private readonly System.Collections.Generic.Queue<uint> Values;
        internal int Calls { get; private set; }

        internal SequenceRandom(params uint[] oValues)
        {
            Values = new System.Collections.Generic.Queue<uint>(oValues);
        }

        public override void GetBytes(byte[] oData)
        {
            Calls++;
            Buffer.BlockCopy(BitConverter.GetBytes(Values.Dequeue()), 0, oData, 0, oData.Length);
        }

        public override void GetNonZeroBytes(byte[] oData)
        {
            throw new NotSupportedException();
        }
    }

    private static void TestPasswordGeneration()
    {
        using (SequenceRandom oRandom = new SequenceRandom(UInt32.MaxValue, 29))
        {
            Check(PasswordGeneration.NextInt(oRandom, 10) == 9 && oRandom.Calls == 2,
                "Password sampling rejects the incomplete range to prevent modulo bias");
        }
        using (SequenceRandom oRandom = new SequenceRandom(0, UInt32.MaxValue))
        {
            Check(PasswordGeneration.NextInt(oRandom, 8) == 0 && PasswordGeneration.NextInt(oRandom, 8) == 7,
                "Uniform sampler reaches both endpoints of a power-of-two range");
            Reject(() => PasswordGeneration.NextInt(oRandom, 0), "Reject an invalid random range");
        }
        PasswordOptions oDefault = new PasswordOptions();
        var oGroups = oDefault.GetCharacterGroups();
        string[] oPasswords = Enumerable.Range(0, 64).Select(i => PasswordGeneration.Generate(oDefault)).ToArray();
        Check(oPasswords.All(p => p.Length >= 20 && p.Length <= 24 &&
            oGroups.All(g => p.Any(c => g.IndexOf(c) >= 0)) && p.All(c => String.Concat(oGroups).IndexOf(c) >= 0)),
            "Default passwords satisfy length, character coverage, and ambiguity exclusions");
        Check(oPasswords.Distinct().Count() == oPasswords.Length, "Successive password requests produce fresh values");
        PasswordOptions oOptions = new PasswordOptions
        {
            MinimumLength = 4, MaximumLength = 4, ExcludeSimilar = false
        };
        oGroups = oOptions.GetCharacterGroups();
        Check(Enumerable.Range(0, 32).Select(i => PasswordGeneration.Generate(oOptions))
            .All(p => p.Length == 4 && oGroups.All(g => p.Any(c => g.IndexOf(c) >= 0))),
            "Minimum-length passwords contain every required character type");
        oOptions.MinimumLength = oOptions.MaximumLength = 1024;
        Check(PasswordGeneration.Generate(oOptions).Length == 1024, "Support the maximum configured password length");
        oOptions = new PasswordOptions
        {
            MinimumLength = 1, MaximumLength = 1, IncludeUppercase = false, IncludeDigits = false,
            IncludeSymbols = false, ExcludeSimilar = false, ExcludedCharacters = "bcdefghijklmnopqrstuvwxyz"
        };
        Check(PasswordGeneration.Generate(oOptions) == "a", "Apply custom exclusions before sampling");
        oOptions = new PasswordOptions
        {
            MinimumLength = 1, MaximumLength = 1, RequireEachType = false
        };
        Check(PasswordGeneration.Generate(oOptions).Length == 1,
            "Allow short passwords when type coverage is optional");
        oOptions = new PasswordOptions
        {
            MinimumLength = 12, MaximumLength = 12, IncludeUppercase = false, IncludeLowercase = false,
            IncludeDigits = false, SymbolCharacters = "!!##$$", ExcludeSimilar = false
        };
        Check(oOptions.GetCharacterGroups().Single() == "!#$" &&
            PasswordGeneration.Generate(oOptions).All(c => "!#$".IndexOf(c) >= 0),
            "Custom symbol duplicates do not weight character probabilities");
        Reject(() => PasswordGeneration.Generate(new PasswordOptions { MinimumLength = 0 }),
            "Reject zero minimum password length");
        Reject(() => PasswordGeneration.Generate(new PasswordOptions { MinimumLength = 30, MaximumLength = 20 }),
            "Reject inverted password length bounds");
        Reject(() => PasswordGeneration.Generate(new PasswordOptions { MaximumLength = 1025 }),
            "Reject excessive password length");
        Reject(() => PasswordGeneration.Generate(new PasswordOptions { MinimumLength = 3 }),
            "Reject lengths too short for required character types");
        Reject(() => PasswordGeneration.Generate(new PasswordOptions
        {
            IncludeUppercase = false, IncludeLowercase = false, IncludeDigits = false, IncludeSymbols = false
        }), "Reject an empty password alphabet");
        Reject(() => PasswordGeneration.Generate(new PasswordOptions { ExcludedCharacters = "0123456789" }),
            "Reject exclusions that empty a selected character type");
        Reject(() => PasswordGeneration.Generate(new PasswordOptions { SymbolCharacters = " \t" }),
            "Reject whitespace in the custom symbol alphabet");
        Reject(() => PasswordGeneration.Generate(new PasswordOptions { SymbolCharacters = "A1" }),
            "Keep custom symbols disjoint from letters and digits");
    }

    private static void TestCompression(string sDirectory)
    {
        byte[] oInput = Encoding.UTF8.GetBytes("File content with unicode \u2603");
        Check(Utilities.Decompress(Utilities.Compress(oInput)).SequenceEqual(oInput), "File compression round trip");
        Check(Utilities.Decompress(Utilities.Compress(new byte[0])).Length == 0, "Empty file compression round trip");
        Reject(() => Utilities.Decompress(new byte[] { 1, 2, 3, 4 }), "Reject damaged compressed file");
        byte[] oOversized = new byte[Utilities.MaxItemSize + 1];
        Reject(() => Utilities.Compress(oOversized), "Reject oversized upload");
        using (MemoryStream oMemory = new MemoryStream())
        {
            using (System.IO.Compression.GZipStream oZip = new System.IO.Compression.GZipStream(oMemory,
                System.IO.Compression.CompressionMode.Compress, true)) oZip.Write(oOversized, 0, oOversized.Length);
            Reject(() => Utilities.Decompress(oMemory.ToArray()), "Bound expanded file size");
        }
        foreach (string sType in new[] { "text", "totp" })
            Reject(() => ItemCryptography.Encrypt(new Item { ItemType = sType }, oOversized, null,
                PrincipalProtection.LocalUserDescriptor), "Preserve the uncompressed size limit for " + sType);
        Reject(() => ItemCryptography.Encrypt(new Item { ItemType = ".bin" },
            new byte[Utilities.MaxCompressedItemSize + 1], null, PrincipalProtection.LocalUserDescriptor),
            "Bound stored attachment size including compression overhead");

        // Exercise an accepted upload through compression, Vault storage, decryption, and download expansion.
        string sPreviousConnection = CryptureEntities.ConnectionString;
        string sPath = Path.Combine(sDirectory, "maximum-attachment.cryptdb");
        byte[] oFile = RandomNumberGenerator.GetBytes(Utilities.MaxItemSize);
        try
        {
            File.WriteAllBytes(Path.Combine(sDirectory, "maximum-upload.bin"), oFile);
            byte[] oCompressed = Utilities.Compress(Utilities.ReadFile(Path.Combine(sDirectory, "maximum-upload.bin")));
            Check(oCompressed.Length > Utilities.MaxItemSize, "An incompressible 64 MiB upload expands during gzip");
            DatabaseOperations.CreateDatabase(sPath,
                File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
            CryptureEntities.DatabasePath = sPath;
            DatabaseOperations.SaveItem(new Item { Label = "Maximum attachment", ItemType = ".bin" },
                oCompressed, null, PrincipalProtection.LocalUserDescriptor);
            long nItemId;
            using (CryptureEntities oContext = new CryptureEntities()) nItemId = oContext.Items.Single().ItemId;
            byte[] oDownloaded = Utilities.Decompress(ItemCryptography.Decrypt(DatabaseOperations.LoadItem(nItemId)));
            Check(oDownloaded.SequenceEqual(oFile), "A 64 MiB incompressible attachment survives a Vault round trip");
        }
        finally
        {
            CryptureEntities.ConnectionString = sPreviousConnection;
        }
    }

    private static void TestDatabase(string sDirectory, X509Certificate2 oCert, X509Certificate2 oOtherCert)
    {
        string sDatabase = Path.Combine(sDirectory, "Vault ; \u00e9.cryptdb");
        string sSchema = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SQLite.sql"));
        DatabaseOperations.CreateDatabase(sDatabase, sSchema);
        Check(VaultHasNoPreferences(sDatabase), "New SQLite Vaults contain no password generator preferences");
        SqliteVaultStorage oStorage = new SqliteVaultStorage(Path.Combine(sDirectory, "Storage.cryptdb"));
        oStorage.Create();
        oStorage.Validate();
        Check(File.Exists(oStorage.DisplayName), "SQLite storage interface creates a usable Vault");
        byte[] oOriginalDatabase = File.ReadAllBytes(sDatabase);
        Reject(() => DatabaseOperations.CreateDatabase(sDatabase, sSchema), "Refuse to overwrite existing Vault");
        Check(File.ReadAllBytes(sDatabase).SequenceEqual(oOriginalDatabase),
            "Preserve refused overwrite byte for byte");
        string sBadDatabase = Path.Combine(sDirectory, "broken.cryptdb");
        Reject(() => DatabaseOperations.CreateDatabase(sBadDatabase, "invalid sql"), "Report schema creation failure");
        Check(!File.Exists(sBadDatabase), "Remove incomplete new Vault");

        string sLegacySchema = sSchema.Replace("\t[ModifiedByIdentity] nvarchar NULL,\r\n", "")
            .Replace("\t[ContentSuite] integer NULL,\r\n", "")
            .Replace("\t[AuthenticationTag] blob NULL,\r\n", "")
            .Replace("\t[ProtectionDescriptor] nvarchar NULL,\r\n", "")
            .Replace("\t[ProtectedKey] blob NULL,\r\n", "")
            .Replace("\t[Signature] blob NULL\r\n", "")
            .Replace("[CipherParams] integer DEFAULT '0' NOT NULL,", "[CipherParams] integer DEFAULT '0' NOT NULL")
            .Replace("DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))", "DEFAULT CURRENT_TIMESTAMP")
            .Replace("CREATE UNIQUE INDEX [UX_Instance_Item_User] ON [Instance] ([ItemId], [UserId]);\r\n", "")
            .Replace("CREATE INDEX [IX_Instance_User] ON [Instance] ([UserId]);\r\n", "")
            .Replace("CREATE INDEX [IX_Item_ModifiedBy] ON [Item] ([ModifiedBy]);\r\n", "");
        string sLegacyDatabase = Path.Combine(sDirectory, "legacy-schema.cryptdb");
        DatabaseOperations.CreateDatabase(sLegacyDatabase, sLegacySchema +
            "CREATE TABLE PasswordGeneratorSettings (Id integer PRIMARY KEY, MinimumLength integer); " +
            "INSERT INTO PasswordGeneratorSettings VALUES (1, 777);");
        Item oLegacyItem = new Item { Label = "Before upgrade", ItemType = "text" };
        byte[] oLegacyPlain = Encoding.Unicode.GetBytes("Preserved legacy content");
        EncryptPreviousRsaFormat(oLegacyItem, oLegacyPlain, oCert);
        using (SqliteConnection oConnection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = sLegacyDatabase, Mode = SqliteOpenMode.ReadWrite, Pooling = false
        }.ConnectionString))
        {
            oConnection.Open();
            using (SqliteCommand oCommand = new SqliteCommand(
                "INSERT INTO [User] (UserId, Certificate) VALUES (1, @cert); " +
                "INSERT INTO Item (ItemId, Label, ItemType, CreatedDate, ModifiedDate) " +
                "VALUES (1, 'Before upgrade', 'text', '2026-01-01 02:03:04', '2026-01-02 03:04:05'); " +
                "INSERT INTO Cipher (ItemId, CipherParams, CipherText, CipherVector) VALUES (1, 1, @data, @iv); " +
                "INSERT INTO Instance (ItemId, UserId, CipherParams, CipherKey, Signature) " +
                "VALUES (1, 1, 1, @key, @tag);", oConnection))
            {
                oCommand.Parameters.AddWithValue("@cert", oCert.RawData);
                oCommand.Parameters.AddWithValue("@data", oLegacyItem.Cipher.CipherText);
                oCommand.Parameters.AddWithValue("@iv", oLegacyItem.Cipher.CipherVector);
                oCommand.Parameters.AddWithValue("@key", oLegacyItem.Instances.Single().CipherKey);
                oCommand.Parameters.AddWithValue("@tag", oLegacyItem.Instances.Single().Signature);
                oCommand.ExecuteNonQuery();
            }
        }
        // A conflicting recipient must leave the entire upgrade and encrypted data untouched.
        string sDuplicateDatabase = Path.Combine(sDirectory, "duplicate-recipients.cryptdb");
        File.Copy(sLegacyDatabase, sDuplicateDatabase);
        using (SqliteConnection oConnection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = sDuplicateDatabase, Pooling = false
        }.ConnectionString))
        {
            oConnection.Open();
            using SqliteCommand oCommand = new SqliteCommand("INSERT INTO [Instance] " +
                "([ItemId], [UserId], [CipherKey], [CipherParams], [Signature]) " +
                "SELECT [ItemId], [UserId], [CipherKey], [CipherParams], [Signature] FROM [Instance]", oConnection);
            oCommand.ExecuteNonQuery();
        }
        byte[] oDuplicateOriginal = File.ReadAllBytes(sDuplicateDatabase);
        Reject(() => DatabaseOperations.EnsureProtectionSchema(sDuplicateDatabase),
            "Reject a conflicting recipient during the SQLite schema upgrade");
        Check(File.ReadAllBytes(sDuplicateDatabase).SequenceEqual(oDuplicateOriginal),
            "A rejected SQLite upgrade preserves duplicate recipient keys and all schema data byte for byte");
        DatabaseOperations.EnsureProtectionSchema(sLegacyDatabase);
        DatabaseOperations.EnsureProtectionSchema(sLegacyDatabase);
        CryptureEntities.DatabasePath = sLegacyDatabase;
        Check(VaultHasNoPreferences(sLegacyDatabase),
            "Legacy Vault migration leaves preferences outside the database");
        oLegacyItem = DatabaseOperations.LoadItem(1);
        Check(oLegacyItem.Cipher.ProtectionDescriptor == null && oLegacyItem.ModifiedByIdentity == null,
            "Upgrade old Vault schema idempotently");
        Check(ItemCryptography.Decrypt(oLegacyItem, oLegacyItem.Instances.Single(), oCert).SequenceEqual(oLegacyPlain),
            "Schema migration preserves existing ciphertext and recipient keys");
        Check(oLegacyItem.CreatedDate == new DateTime(2026, 1, 1, 2, 3, 4) &&
            oLegacyItem.ModifiedDate == new DateTime(2026, 1, 2, 3, 4, 5) &&
            oLegacyItem.CreatedDate.Kind == DateTimeKind.Unspecified &&
            oLegacyItem.ModifiedDate.Kind == DateTimeKind.Unspecified,
            "Opening a SQLite Vault preserves timestamp values without assuming an unknown offset");
        TestSqliteRecipientIndexes(sLegacyDatabase, 1, 1);
        string sNotVault = Path.Combine(sDirectory, "not-Vault.db");
        DatabaseOperations.CreateDatabase(sNotVault, "CREATE TABLE Other (Id integer)");
        Reject(() => DatabaseOperations.EnsureProtectionSchema(sNotVault), "Do not migrate an unrelated Vault");

        CryptureEntities.DatabasePath = sDatabase;
        PasswordOptions oPasswordOptions = new PasswordOptions
        {
            MinimumLength = 25, MaximumLength = 37, IncludeUppercase = false, IncludeLowercase = true,
            IncludeDigits = false, IncludeSymbols = true, SymbolCharacters = "'\"\\;!",
            ExcludedCharacters = "' DROP TABLE [User]; --", RequireEachType = false, ExcludeSimilar = false
        };
        PasswordOptions.SavePreferences(oPasswordOptions);
        PasswordOptions oLoadedOptions = PasswordOptions.LoadPreferences();
        Check(oLoadedOptions.MinimumLength == 25 && oLoadedOptions.MaximumLength == 37 &&
            !oLoadedOptions.IncludeUppercase && oLoadedOptions.IncludeLowercase && !oLoadedOptions.IncludeDigits &&
            oLoadedOptions.IncludeSymbols && oLoadedOptions.SymbolCharacters == oPasswordOptions.SymbolCharacters &&
            oLoadedOptions.ExcludedCharacters == oPasswordOptions.ExcludedCharacters &&
            !oLoadedOptions.RequireEachType && !oLoadedOptions.ExcludeSimilar,
            "Persist every password option including quoted character lists");
        CryptureEntities.DatabasePath = sLegacyDatabase;
        Check(PasswordOptions.LoadPreferences().MaximumLength == 37,
            "Password settings follow the Windows user across Vault files");
        CryptureEntities.DatabasePath = sDatabase;
        Reject(() => PasswordOptions.SavePreferences(new PasswordOptions { MinimumLength = 0 }),
            "Reject invalid preferences before modifying the user file");
        Check(PasswordOptions.LoadPreferences().MaximumLength == 37,
            "Failed validation preserves saved settings");
        User oUser = new User { Certificate = oCert.RawData };
        User oOtherUser = new User { Certificate = oOtherCert.RawData };
        using (CryptureEntities oContent = new CryptureEntities())
        {
            oContent.Users.Add(oUser);
            oContent.Users.Add(oOtherUser);
            oContent.SaveChanges();
        }
        byte[] oPlainText = Encoding.Unicode.GetBytes("Secret never stored as plaintext");
        Item oItem = new Item { Label = "First", ItemType = "text", ModifiedBy = oUser.UserId };
        DatabaseOperations.SaveItem(oItem, oPlainText, new[] { oUser });
        long nItemId;
        using (CryptureEntities oContent = new CryptureEntities()) nItemId = oContent.Items.Single().ItemId;
        oItem = DatabaseOperations.LoadItem(nItemId);
        Check(oItem.Cipher != null && oItem.Instances.Single().User != null && oItem.User != null,
            "Load a complete detached item graph");
        Check(ItemCryptography.Decrypt(oItem, oItem.Instances.Single(), oCert).SequenceEqual(oPlainText),
            "Decrypt newly saved Vault item");
        Check(oItem.CreatedDate.Kind == DateTimeKind.Utc && oItem.ModifiedDate.Kind == DateTimeKind.Utc &&
            Math.Abs((DateTime.UtcNow - oItem.CreatedDate).TotalSeconds) < 60,
            "SQLite saves and reloads item timestamps as UTC instants");
        TestSqliteRecipientIndexes(sDatabase, nItemId, oUser.UserId);
        DateTime oCreated = oItem.CreatedDate;
        byte[] oOriginalVector = oItem.Cipher.CipherVector.ToArray();
        Item oStale = DatabaseOperations.LoadItem(nItemId);
        oItem.Label = "Updated";
        oItem.ModifiedBy = oOtherUser.UserId;
        DatabaseOperations.SaveItem(oItem, oPlainText, new[] { oUser, oOtherUser });
        oItem = DatabaseOperations.LoadItem(nItemId);
        Check(oItem.CreatedDate == oCreated, "Preserve original creation date on update");
        Check(oItem.ModifiedDate.Kind == DateTimeKind.Utc && oItem.ModifiedDate >= oCreated,
            "SQLite updates retain UTC timestamp kinds and ordering");
        Check(oItem.ModifiedBy == oOtherUser.UserId && oItem.Instances.Count == 2, "Update modifier and recipients");
        Check(!oItem.Cipher.CipherVector.SequenceEqual(oOriginalVector), "Use a fresh IV on save");
        Check(ItemCryptography.Decrypt(oItem, oItem.Instances.First(i => i.UserId == oOtherUser.UserId), oOtherCert)
            .SequenceEqual(oPlainText), "New recipient can decrypt updated item");
        Reject(() => DatabaseOperations.SaveItem(oStale, oPlainText, new[] { oUser }), "Reject stale concurrent edit");
        User oMissing = new User { UserId = Int64.MaxValue, Certificate = oCert.RawData };
        oItem.Label = "Must not be saved";
        Reject(() => DatabaseOperations.SaveItem(oItem, oPlainText, new[] { oMissing }), "Report save failure");
        oItem = DatabaseOperations.LoadItem(nItemId);
        Check(oItem.Label == "Updated" && oItem.Instances.Count == 2,
            "Roll back failed save and recipient replacement");

        DatabaseOperations.RemoveCertificate(oOtherUser.UserId);
        oItem = DatabaseOperations.LoadItem(nItemId);
        Check(oItem.Instances.Count == 1 && oItem.ModifiedBy == null, "Remove certificate with alternate recipient");
        Reject(() => DatabaseOperations.RemoveCertificate(oUser.UserId), "Block deletion of final recipient");
        Check(ItemCryptography.Decrypt(oItem, oItem.Instances.Single(), oCert).SequenceEqual(oPlainText),
            "Retain decryption after certificate deletion");

        string sBackup = Path.Combine(sDirectory, "backup.cryptdb");
        DatabaseOperations.BackupDatabase(sDatabase, sBackup);
        Reject(() => DatabaseOperations.BackupDatabase(sDatabase, sBackup), "Protect existing backup");
        Reject(() => DatabaseOperations.BackupDatabase(sDatabase, sDatabase),
            "Protect active Vault from backup overwrite");
        CryptureEntities.DatabasePath = sBackup;
        Check(VaultHasNoPreferences(sBackup),
            "Vault backups contain no password generator preferences");
        Item oBackedUp = DatabaseOperations.LoadItem(nItemId);
        Check(ItemCryptography.Decrypt(oBackedUp, oBackedUp.Instances.Single(), oCert).SequenceEqual(oPlainText),
            "Open and decrypt Vault backup");
        using (CryptureEntities oContent = new CryptureEntities())
        {
            oContent.Items.Remove(oContent.Items.Single());
            oContent.SaveChanges();
        }
        Reject(() => DatabaseOperations.SaveItem(oBackedUp, oPlainText, new[] { oUser }),
            "Do not resurrect deleted item");

        CryptureEntities.DatabasePath = sDatabase;
        Item oBeforeConversion = DatabaseOperations.LoadItem(nItemId);
        DatabaseOperations.SaveItem(oBeforeConversion, oPlainText, null, PrincipalProtection.LocalUserDescriptor);
        Item oConverted = DatabaseOperations.LoadItem(nItemId);
        Check(oConverted.Instances.Count == 0 && oConverted.ModifiedBy == null &&
            !String.IsNullOrEmpty(oConverted.ModifiedByIdentity), "Convert certificate item to Windows protection");
        Check(ItemCryptography.Decrypt(oConverted).SequenceEqual(oPlainText), "Reload a persisted DPAPI item");
        if (!PrincipalProtection.IsDomainJoined)
        {
            string sDomainPolicy = "SID=" + CertificateOperations.CurrentUserSid + " OR SID=S-1-1-0";
            Reject(() => DatabaseOperations.SaveItem(oConverted, oPlainText, null, sDomainPolicy),
                "Reject standalone saves with local SID and Everyone recipients");
            Item oUnchanged = DatabaseOperations.LoadItem(nItemId);
            Check(oUnchanged.Cipher.ProtectionDescriptor == PrincipalProtection.LocalUserDescriptor &&
                oUnchanged.Cipher.CipherText.SequenceEqual(oConverted.Cipher.CipherText) &&
                ItemCryptography.Decrypt(oUnchanged).SequenceEqual(oPlainText),
                "Failed domain save preserves the existing encryption scope and readable item");
            Reject(() => DatabaseOperations.SaveItem(new Item { Label = "Rejected", ItemType = "text" },
                oPlainText, null, sDomainPolicy), "Reject new standalone SID item without substituting a local scope");
            using (CryptureEntities oContext = new CryptureEntities())
                Check(oContext.Items.Count() == 1, "Failed standalone save does not add an incomplete item");
        }
        Reject(() => DatabaseOperations.SaveItem(oBeforeConversion, oPlainText, new[] { oUser }),
            "Reject stale edits across protection mode changes");
        string sWindowsBackup = Path.Combine(sDirectory, "windows-backup.cryptdb");
        DatabaseOperations.BackupDatabase(sDatabase, sWindowsBackup);
        CryptureEntities.DatabasePath = sWindowsBackup;
        Check(ItemCryptography.Decrypt(DatabaseOperations.LoadItem(nItemId)).SequenceEqual(oPlainText),
            "DPAPI item remains decryptable from its Vault backup");
        CryptureEntities.DatabasePath = sDatabase;
        DatabaseOperations.SaveItem(oConverted, oPlainText, new[] { oUser });
        oConverted = DatabaseOperations.LoadItem(nItemId);
        Check(oConverted.Cipher.ProtectionDescriptor == null && oConverted.Cipher.ProtectedKey == null &&
            oConverted.Cipher.Signature == null && oConverted.Instances.Count == 1,
            "Certificate conversion removes previous Windows policy and wrapped keys");
        Check(ItemCryptography.Decrypt(oConverted, oConverted.Instances.Single(), oCert).SequenceEqual(oPlainText),
            "Converted certificate item remains readable");
        TestVaultIntegration(oConverted, sDirectory);

        string sMissing = Path.Combine(sDirectory, "missing.cryptdb");
        CryptureEntities.DatabasePath = sMissing;
        Reject(() => { using (CryptureEntities oContent = new CryptureEntities()) oContent.Items.ToList(); },
            "Reject missing Vault");
        Check(!File.Exists(sMissing), "Opening a missing path does not create a Vault");
    }

    private static void TestSqliteRecipientIndexes(string sDatabase, long nItemId, long nUserId)
    {
        using SqliteConnection oConnection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = sDatabase, ForeignKeys = true, Pooling = false
        }.ConnectionString);
        oConnection.Open();
        using SqliteCommand oCommand = oConnection.CreateCommand();
        oCommand.Parameters.AddWithValue("@itemId", nItemId);
        oCommand.Parameters.AddWithValue("@userId", nUserId);

        // Recipient lookups and certificate deletion references must use indexed searches.
        foreach ((string Query, string Index) oQuery in new[]
        {
            ("SELECT [CipherKey] FROM [Instance] WHERE [ItemId] = @itemId AND [UserId] = @userId",
                "UX_Instance_Item_User"),
            ("SELECT [ItemId] FROM [Instance] WHERE [UserId] = @userId", "IX_Instance_User"),
            ("SELECT [ItemId] FROM [Item] WHERE [ModifiedBy] = @userId", "IX_Item_ModifiedBy")
        })
        {
            oCommand.CommandText = "EXPLAIN QUERY PLAN " + oQuery.Query;
            using SqliteDataReader oReader = oCommand.ExecuteReader();
            bool bIndexed = false;
            while (oReader.Read()) bIndexed |= oReader.GetString(3).Contains(oQuery.Index, StringComparison.Ordinal);
            Check(bIndexed, "SQLite uses the recipient reference index: " + oQuery.Index);
        }
        oCommand.CommandText = "INSERT INTO [Instance] " +
            "([ItemId], [UserId], [CipherKey], [CipherParams], [Signature]) " +
            "SELECT [ItemId], [UserId], [CipherKey], [CipherParams], [Signature] FROM [Instance] " +
            "WHERE [ItemId] = @itemId AND [UserId] = @userId";
        bool bRejected = false;
        try { oCommand.ExecuteNonQuery(); }
        catch (SqliteException oError) when (oError.SqliteErrorCode == 19) { bRejected = true; }
        Check(bRejected, "SQLite rejects a second encrypted key for the same item and certificate");
        oCommand.CommandText = "SELECT COUNT(*) FROM [Instance] WHERE [ItemId] = @itemId AND [UserId] = @userId";
        Check((long)oCommand.ExecuteScalar() == 1, "A duplicate recipient insert preserves the saved access path");
    }

    private static void CheckItemDateDisplay(ItemEditor oEditor)
    {
        Item oItem = oEditor.ThisItem;
        string sCreated = ((TextBlock)oEditor.FindName("oItemCreatedDate")).Text;
        string sModified = ((TextBlock)oEditor.FindName("oItemModifiedDate")).Text;
        DateTime oCreated = oItem.CreatedDate.Kind == DateTimeKind.Utc
            ? oItem.CreatedDate.ToLocalTime() : oItem.CreatedDate;
        DateTime oModified = oItem.ModifiedDate.Kind == DateTimeKind.Utc
            ? oItem.ModifiedDate.ToLocalTime() : oItem.ModifiedDate;
        Check(sCreated == oCreated.ToString("yyyy-MM-dd HH:mm:ss") &&
            sModified == oModified.ToString("yyyy-MM-dd HH:mm:ss"),
            "Editor date bindings display saved timestamps in local time without shifting unspecified dates");
    }

    private static void TestVaultIntegration(Item oItem, string sDirectory)
    {
        Application oApplication = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        oApplication.Resources = new ResourceDictionary
        {
            Source = new Uri("pack://application:,,,/Crypture;component/Themes/Controls.xaml", UriKind.Absolute)
        };
        string sDatabase = Path.Combine(sDirectory, "Vault ; \u00e9.cryptdb");
        ItemEditor oEditor = null;
        ItemBrowser oBrowser = null;
        try
        {
            TestPopups();

            // Locking must clear secrets even when the Vault cannot be opened.
            oEditor = new ItemEditor(oItem);
            oEditor.SetEditingControls(true);
            TextBox oContent = (TextBox)oEditor.FindName("oItemData");
            oContent.Text = "Sensitive text shown only in the test editor";
            typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                .SetValue(oEditor, false);
            oEditor.BinaryItemData = new byte[] { 1, 2, 3, 4 };
            byte[] oBuffer = oEditor.BinaryItemData;
            CryptureEntities.DatabasePath = Path.Combine(sDirectory, "offline.cryptdb");
            typeof(ItemEditor).GetMethod("oLockItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oEditor, new object[] { null, null });
            Check(oContent.Text.Length == 0 && oEditor.BinaryItemData == null && oBuffer.All(b => b == 0),
                "Lock clears text and binary buffers while Vault is unavailable");
            TestPrivacyConcealment(oEditor);
            TestEditorTextLayout(oEditor);
            oEditor.Close();
            oEditor = null;
            CryptureEntities.DatabasePath = sDatabase;

            // Exercise the recipient list through WPF layout with more than one certificate.
            oEditor = new ItemEditor(oItem)
            {
                Left = -20000, Top = -20000, WindowStartupLocation = WindowStartupLocation.Manual,
                ShowActivated = false, ShowInTaskbar = false
            };
            oEditor.UserListSelected.Add(new User { Certificate = oEditor.UserListSelected.Single().Certificate });
            oEditor.Show();
            PumpUntil(() => oEditor.IsLoaded);
            Check(oEditor.UserListSelected.Count == 2, "Editor displays multiple certificate recipients");
            CheckItemDateDisplay(oEditor);
            oEditor.UserListSelected.RemoveAt(1);
            oEditor.SetEditingControls(true);
            ((ComboBox)oEditor.FindName("oProtectionMode")).SelectedIndex = 1;
            PumpUntil(() => oEditor.CertificateLoading.IsCompleted);
            var oRecipients = (System.Windows.Controls.Ribbon.RibbonMenuButton)oEditor.FindName("oAddCertDropDown");
            oRecipients.IsDropDownOpen = true;
            PumpUntil(() => oRecipients.ItemContainerGenerator.ContainerFromIndex(0) != null);
            var oRecipient = (System.Windows.Controls.Ribbon.RibbonMenuItem)
                oRecipients.ItemContainerGenerator.ContainerFromIndex(0);
            Check(oRecipient.IsChecked && oRecipients.IsVisible,
                "The inline recipient picker shows the saved recipient as selected");
            oRecipient.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.MenuItem.ClickEvent));
            oEditor.UpdateLayout();
            Check(!oRecipient.IsChecked && oEditor.UserListSelected.Count == 0 &&
                !((ListView)oEditor.FindName("oItemSharedWith")).IsVisible &&
                ((TextBlock)oEditor.FindName("oRecipientEmptyState")).IsVisible,
                "Removing the last recipient updates its check mark and the inline empty state");
            oRecipient.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.MenuItem.ClickEvent));
            oEditor.UpdateLayout();
            Check(oRecipient.IsChecked && oEditor.UserListSelected.Count == 1 &&
                ((ListView)oEditor.FindName("oItemSharedWith")).IsVisible &&
                !((TextBlock)oEditor.FindName("oRecipientEmptyState")).IsVisible,
                "Selecting a recipient restores its check mark and the inline recipient list");
            oRecipients.IsDropDownOpen = false;
            typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                .SetValue(oEditor, false);
            oEditor.Close();
            oEditor = null;

            TestRichTextVaultRoundTrip(sDirectory);

            // Keep persistence and security assertions independently of menu and dialog presentation.
            oBrowser = new ItemBrowser();
            DataGrid oItemGrid = (DataGrid)oBrowser.FindName("oItemDataGrid");
            DataGridTextColumn oDateColumn = oItemGrid.Columns.OfType<DataGridTextColumn>()
                .Single(c => ((Binding)c.Binding).Path.Path == "ModifiedDate");
            TextBlock oDateCell = new TextBlock { DataContext = DatabaseOperations.LoadItem(oItem.ItemId) };
            BindingOperations.SetBinding(oDateCell, TextBlock.TextProperty, oDateColumn.Binding);
            Check(oDateCell.Text == oItem.ModifiedDate.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                "The browser's date column displays saved UTC timestamps in local time");

            // Read a released SQLite timestamp through the same editor bindings.
            CryptureEntities.DatabasePath = Path.Combine(sDirectory, "legacy-schema.cryptdb");
            oEditor = new ItemEditor(DatabaseOperations.LoadItem(1));
            CheckItemDateDisplay(oEditor);
            oEditor.Close();
            oEditor = null;
            CryptureEntities.DatabasePath = sDatabase;
            TestRecentVaultHistory(oBrowser, sDatabase, sDirectory);
            TestVaultOperations(sDirectory);
            TestTotpVault(sDirectory);
            TestFidoEditor(sDirectory);
            using (RSA oFidoKey = RSA.Create(2048))
            using (X509Certificate2 oFidoCertificate = Certificate(oFidoKey, "FIDO2 Recovery",
                DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1)))
                TestFidoConfiguration(sDirectory, oFidoCertificate);
            TestCertificateUsageConfiguration(oBrowser, oItem);
            TestEditorCertificateLoading(sDirectory);
            TestPasswordGeneratorLayout();
            TestPasswordGeneratorDefaults(sDirectory);
            TestConfigurationDefaults(sDirectory);
        }
        finally
        {
            oEditor?.Close();
            if (oBrowser != null)
            {
                oBrowser.Closing -= (System.ComponentModel.CancelEventHandler)Delegate.CreateDelegate(
                    typeof(System.ComponentModel.CancelEventHandler), oBrowser, "oItemBrowser_Closing");
                oBrowser.Close();
            }
            oApplication.Shutdown();
            CryptureEntities.DatabasePath = sDatabase;
        }
    }

    private static void TestPasswordGeneratorDefaults(string sDirectory)
    {
        string sConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        byte[] oOriginalConfig = File.ReadAllBytes(sConfigPath);
        string sPreviousConnection = CryptureEntities.ConnectionString;
        var oPreferences = new Crypture.Properties.Settings();
        PasswordOptions oOriginalOptions = oPreferences.PasswordGeneratorOptions;
        PasswordGenerator oGenerator = null;
        MethodInfo oGenerate = typeof(PasswordGenerator).GetMethod("oGenerateButton_Click",
            BindingFlags.Instance | BindingFlags.NonPublic);

        void Configure(params (string Name, string Value)[] oValues)
        {
            XDocument oConfig = XDocument.Parse(Encoding.UTF8.GetString(oOriginalConfig).TrimStart('\uFEFF'),
                LoadOptions.PreserveWhitespace);
            XElement oSettings = oConfig.Root.Element("appSettings");
            oSettings.Elements("add").Where(e => ((string)e.Attribute("key"))
                .StartsWith("PasswordGenerator", StringComparison.Ordinal)).Remove();
            foreach (var oValue in oValues)
                oSettings.Add(new XElement("add", new XAttribute("key", "PasswordGenerator" + oValue.Name),
                    new XAttribute("value", oValue.Value)));
            oConfig.Save(sConfigPath, SaveOptions.DisableFormatting);
        }

        void Invalid(string sDetail)
        {
            try
            {
                PasswordOptions.ReadDefaults();
            }
            catch (InvalidOperationException oError)
            {
                Check(oError.GetBaseException().Message.Contains(sConfigPath) && oError.Message.Contains(sDetail),
                    "Invalid generator configuration identifies the file and error: " + sDetail);
                return;
            }
            throw new Exception("Invalid generator configuration was accepted: " + sDetail);
        }

        try
        {
            oPreferences.PasswordGeneratorOptions = null;
            oPreferences.Save();

            // Exercise the adjacent file through both generator entry paths, including XML punctuation.
            Configure(("MinimumLength", "8"), ("MaximumLength", "12"), ("IncludeUppercase", "False"),
                ("IncludeLowercase", "False"), ("IncludeDigits", "False"), ("IncludeSymbols", "True"),
                ("SymbolCharacters", "!&\"'<>|"), ("ExcludedCharacters", "!&\"'<>"),
                ("ExcludeSimilar", "False"), ("RequireEachType", "False"));
            CryptureEntities.ConnectionString = "";
            oGenerator = new PasswordGenerator();
            Check(((TextBox)oGenerator.FindName("oMinimumLength")).Text == "8" &&
                ((TextBox)oGenerator.FindName("oMaximumLength")).Text == "12" &&
                ((CheckBox)oGenerator.FindName("oUppercase")).IsChecked == false &&
                ((CheckBox)oGenerator.FindName("oLowercase")).IsChecked == false &&
                ((CheckBox)oGenerator.FindName("oDigits")).IsChecked == false &&
                ((CheckBox)oGenerator.FindName("oSymbols")).IsChecked == true &&
                ((TextBox)oGenerator.FindName("oSymbolCharacters")).Text == "!&\"'<>|" &&
                ((TextBox)oGenerator.FindName("oExcludedCharacters")).Text == "!&\"'<>" &&
                ((CheckBox)oGenerator.FindName("oExcludeSimilar")).IsChecked == false &&
                ((CheckBox)oGenerator.FindName("oRequireEachType")).IsChecked == false,
                "Standalone generator loads all ten configured defaults");
            Check(new Crypture.Properties.Settings().PasswordGeneratorOptions == null,
                "Opening the generator does not save application defaults as user preferences");
            oGenerate.Invoke(oGenerator, new object[] { null, null });
            string sPassword = ((TextBox)oGenerator.FindName("oGeneratedPassword")).Text;
            Check(sPassword.Length is >= 8 and <= 12 && sPassword.All(c => c == '|'),
                "Configured symbols, exclusions, lengths, and similar-character choice control generated output");
            oGenerator.Close();
            Check(PasswordOptions.LoadPreferences().GetCharacterGroups().Single() == "|",
                "Generating without a Vault saves the user's preferences");

            string sVault = Path.Combine(sDirectory, "password-defaults.cryptdb");
            DatabaseOperations.CreateDatabase(sVault,
                File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
            CryptureEntities.DatabasePath = sVault;
            oGenerator = new PasswordGenerator();
            Check(((TextBox)oGenerator.FindName("oMinimumLength")).Text == "8" &&
                ((TextBox)oGenerator.FindName("oMaximumLength")).Text == "12",
                "Opening a different Vault retains the user's generator preferences");
            Check(VaultHasNoPreferences(sVault), "Opening a generator leaves the Vault free of preferences");
            oGenerate.Invoke(oGenerator, new object[] { null, null });
            oGenerator.Close();
            Check(VaultHasNoPreferences(sVault), "Generating a password leaves the Vault free of preferences");

            // A saved user selection takes precedence when application defaults change.
            Configure(("MinimumLength", "1"), ("MaximumLength", "1"), ("IncludeUppercase", "True"),
                ("IncludeLowercase", "True"), ("IncludeDigits", "False"), ("IncludeSymbols", "False"),
                ("RequireEachType", "False"));
            CryptureEntities.ConnectionString = "";
            oGenerator = new PasswordGenerator();
            oGenerate.Invoke(oGenerator, new object[] { null, null });
            sPassword = ((TextBox)oGenerator.FindName("oGeneratedPassword")).Text;
            Check(sPassword.Length is >= 8 and <= 12 && sPassword.All(c => c == '|'),
                "Standalone generator preserves saved user preferences when application defaults change");
            oGenerator.Close();
            CryptureEntities.DatabasePath = sVault;
            oGenerator = new PasswordGenerator();
            oGenerate.Invoke(oGenerator, new object[] { null, null });
            sPassword = ((TextBox)oGenerator.FindName("oGeneratedPassword")).Text;
            Check(sPassword.Length is >= 8 and <= 12 && sPassword.All(c => c == '|'),
                "Saved user preferences override changed application defaults with a Vault open");
            oGenerator.Close();

            Configure(("IncludeDigits", "yes"));
            Invalid("PasswordGeneratorIncludeDigits");
            Check(PasswordOptions.LoadPreferences().GetCharacterGroups().Single() == "|",
                "Invalid unused defaults do not prevent loading saved user preferences");
            Configure(("MinimumLength", "twenty"));
            Invalid("PasswordGeneratorMinimumLength");
            Configure(("MinimumLength", "32"), ("MaximumLength", "16"));
            Invalid("Lengths must be between");
            Configure(("IncludeUppercase", "False"), ("IncludeLowercase", "False"),
                ("IncludeDigits", "False"), ("IncludeSymbols", "False"));
            Invalid("Select at least one character type");
            Configure(("SymbolCharacters", "not punctuation"));
            Invalid("Allowed symbols must be ASCII punctuation");
            Configure(("ExcludedCharacters", "0123456789"));
            Invalid("Each selected character type must have at least one allowed character");

            // Missing settings use built-in defaults; explicit empty lists retain their meaning.
            Configure(("IncludeSymbols", "False"), ("SymbolCharacters", ""), ("ExcludedCharacters", ""));
            PasswordOptions oDefaults = PasswordOptions.ReadDefaults();
            Check(oDefaults.MinimumLength == 20 && oDefaults.MaximumLength == 24 &&
                oDefaults.IncludeUppercase && oDefaults.IncludeLowercase && oDefaults.IncludeDigits &&
                !oDefaults.IncludeSymbols && oDefaults.ExcludeSimilar && oDefaults.RequireEachType &&
                oDefaults.SymbolCharacters == "" && oDefaults.ExcludedCharacters == "",
                "Partial configuration preserves omitted defaults and explicit empty character lists");
            File.WriteAllText(sConfigPath, "<configuration><appSettings>");
            Invalid("Invalid password generator defaults");
            File.Delete(sConfigPath);
            oDefaults = PasswordOptions.ReadDefaults();
            Check(oDefaults.MinimumLength == 20 && oDefaults.MaximumLength == 24 &&
                oDefaults.GetCharacterGroups().Count == 4 && !File.Exists(sConfigPath),
                "Missing configuration uses built-in defaults without creating a file");
            Check(PasswordOptions.LoadPreferences().GetCharacterGroups().Single() == "|",
                "Saved user preferences survive removal of the adjacent configuration");
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            Configure(("MinimumLength", "1"), ("MaximumLength", "1"), ("IncludeUppercase", "True"),
                ("IncludeLowercase", "True"), ("IncludeDigits", "False"), ("IncludeSymbols", "False"),
                ("RequireEachType", "False"));
            oPreferences.PasswordGeneratorOptions = null;
            oPreferences.Save();
            CryptureEntities.ConnectionString = "";
            oGenerator = new PasswordGenerator();
            oGenerate.Invoke(oGenerator, new object[] { null, null });
            sPassword = ((TextBox)oGenerator.FindName("oGeneratedPassword")).Text;
            Check(sPassword.Length == 1 && Char.IsAsciiLetter(sPassword[0]),
                "A user without saved preferences receives current defaults and optional character-type coverage");
            oGenerator.Close();
        }
        finally
        {
            oGenerator?.Close();
            File.WriteAllBytes(sConfigPath, oOriginalConfig);
            oPreferences.PasswordGeneratorOptions = oOriginalOptions;
            oPreferences.Save();
            CryptureEntities.ConnectionString = sPreviousConnection;
        }
    }

    private static TextBlock FindEditorGlyph(DependencyObject oElement)
    {
        if (oElement is TextBlock oText && oText.FontFamily.Source == "Segoe MDL2 Assets") return oText;
        for (int nChild = 0; nChild < VisualTreeHelper.GetChildrenCount(oElement); nChild++)
        {
            TextBlock oGlyph = FindEditorGlyph(VisualTreeHelper.GetChild(oElement, nChild));
            if (oGlyph != null) return oGlyph;
        }
        return null;
    }

    private static void TestEditorTextLayout(ItemEditor oEditor)
    {
        Button oCopy = (Button)oEditor.FindName("oCopyContentButton");
        TextBox oPlain = (TextBox)oEditor.FindName("oItemData");
        RichTextBox oRich = (RichTextBox)oEditor.FindName("oRichItemData");
        Grid oContent = (Grid)oEditor.FindName("oTextContentPanel");
        FrameworkElement oRoot = (FrameworkElement)oEditor.Content;
        ComboBox oType = (ComboBox)oEditor.FindName("oItemTypeSelector");
        string sOriginalType = oEditor.ThisItem.ItemType;
        double nOriginalWidth = oEditor.Width, nOriginalFontSize = oEditor.FontSize;
        try
        {
            // Check the rendered copy action and metadata glyphs at the minimum width and enlarged text.
            Border oShield = (Border)oEditor.FindName("oPrivacyShield");
            if (oShield.Visibility == Visibility.Visible)
                ((Button)oEditor.FindName("oRevealButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            oEditor.SetEditingControls(true);
            oPlain.Text = "Plain secret for formatting\r\nsecond line";
            oEditor.Width = oEditor.MinWidth;
            foreach (double nFontSize in new[] { 12d, 18d })
            {
                oEditor.FontSize = nFontSize;
                oEditor.UpdateLayout();
                Rect oCopyBounds = oCopy.TransformToAncestor(oContent).TransformBounds(new Rect(oCopy.RenderSize));
                Check(oCopy.IsVisible && oPlain.IsVisible && oCopyBounds.Left >= oContent.ActualWidth - 48 &&
                    oCopyBounds.Right <= oContent.ActualWidth - 4 && oCopyBounds.Top >= 4 &&
                    oCopyBounds.Bottom <= 48 && oPlain.Padding.Right >= 46,
                    "Editor copy action stays inside the plain text box at font size " + nFontSize);

                string[] oNames = ["oItemLabelTitle", "oItemTypeTitle", "oCreatedTitle",
                    "oModifiedTitle", "oModifiedByTitle"];
                double[] oLeftEdges = oNames.Select(sName => FindEditorGlyph((DependencyObject)oEditor.FindName(sName)))
                    .Select(oGlyph => oGlyph.TransformToAncestor(oRoot)
                        .TransformBounds(new Rect(oGlyph.RenderSize)).Left).ToArray();
                Check(oLeftEdges.All(nLeft => Math.Abs(nLeft - oLeftEdges[0]) <= 1),
                    "Editor metadata icons share one left edge at font size " + nFontSize);
                Label oModifiedBy = (Label)oEditor.FindName("oModifiedByTitle");
                TextBlock oModifier = (TextBlock)oEditor.FindName("oItemModifiedBy");
                Rect oLabelBounds = oModifiedBy.TransformToAncestor(oRoot)
                    .TransformBounds(new Rect(oModifiedBy.RenderSize));
                Rect oValueBounds = oModifier.TransformToAncestor(oRoot)
                    .TransformBounds(new Rect(oModifier.RenderSize));
                Check(oLabelBounds.Right + 4 <= oValueBounds.Left && oValueBounds.Width > 0,
                    "Editor metadata label and value do not overlap at font size " + nFontSize);
            }
            string sOriginalText = oPlain.Text;
            oType.SelectedIndex = 1;
            oEditor.UpdateLayout();
            Check(oEditor.ThisItem.ItemType == "richtext" && Utilities.GetRichText(oRich) == sOriginalText &&
                oCopy.IsVisible && oRich.IsVisible && !oPlain.IsVisible &&
                oCopy.CommandTarget == oRich &&
                ((StackPanel)oEditor.FindName("oRichTextToolbar")).IsVisible,
                "Changing to rich text keeps the secret and shows its editor and in-box copy action");

            // Encrypted RTF retains character formatting and copies only visible plain text.
            oRich.Document.Blocks.Clear();
            Paragraph oParagraph = new Paragraph { Margin = new Thickness(0) };
            oParagraph.Inlines.Add(new Run("Bold ") { FontWeight = FontWeights.Bold });
            oParagraph.Inlines.Add(new Run("ordinary"));
            oRich.Document.Blocks.Add(oParagraph);
            byte[] oRtf;
            App.ApplyTheme(true);
            try
            {
                oRtf = (byte[])typeof(ItemEditor).GetMethod("SaveRichText",
                    BindingFlags.Instance | BindingFlags.NonPublic).Invoke(oEditor, null);
            }
            finally
            {
                App.ApplyTheme(false);
            }
            byte[] oDecrypted = null;
            try
            {
                Item oProtected = new Item { Label = "Rich text", ItemType = "richtext" };
                ItemCryptography.Encrypt(oProtected, oRtf, null, PrincipalProtection.LocalUserDescriptor);
                oDecrypted = ItemCryptography.Decrypt(oProtected);
                RichTextBox oReloaded = new RichTextBox
                {
                    Style = (Style)Application.Current.Resources["Crypture.SecretRichText"]
                };
                using (MemoryStream oStream = new MemoryStream(oDecrypted, false))
                    new TextRange(oReloaded.Document.ContentStart, oReloaded.Document.ContentEnd)
                        .Load(oStream, DataFormats.Rtf);
                Utilities.NormalizeRichTextAppearance(oReloaded);
                string sCopied = null;
                Utilities.EnableClipboardTimeout(oReloaded, sText => { sCopied = sText; return true; });
                ApplicationCommands.Copy.Execute("All", oReloaded);
                TextPointer oFirstText = oReloaded.Document.ContentStart;
                while (oFirstText.GetPointerContext(LogicalDirection.Forward) != TextPointerContext.Text)
                    oFirstText = oFirstText.GetNextContextPosition(LogicalDirection.Forward);
                object oWeight = new TextRange(oFirstText, oFirstText.GetPositionAtOffset(1))
                    .GetPropertyValue(TextElement.FontWeightProperty);
                object oForeground = new TextRange(oFirstText, oFirstText.GetPositionAtOffset(1))
                    .GetPropertyValue(TextElement.ForegroundProperty);
                Color oLightText = ((SolidColorBrush)Application.Current.Resources["Crypture.TextBrush"]).Color;
                Check(Utilities.GetRichText(oReloaded) == "Bold ordinary" &&
                    oWeight is FontWeight nWeight && nWeight == FontWeights.Bold &&
                    oForeground is SolidColorBrush oBrush && oBrush.Color == oLightText &&
                    sCopied == "Bold ordinary" && oRtf.SequenceEqual(oDecrypted),
                    "Rich text keeps formatting but adopts the current theme after encryption");
            }
            finally
            {
                Array.Clear(oRtf, 0, oRtf.Length);
                if (oDecrypted != null) Array.Clear(oDecrypted, 0, oDecrypted.Length);
            }

            oType.SelectedIndex = 2;
            oEditor.UpdateLayout();
            Check(!oCopy.IsVisible && !oRich.IsVisible && !oPlain.IsVisible,
                "Copy is hidden when the item displays an authenticator");

            // Toggling the primary action must preserve its bounds and the neighboring ribbon positions.
            var oUnlock = (System.Windows.Controls.Ribbon.RibbonButton)oEditor.FindName("oLoadItemButton");
            var oSave = (System.Windows.Controls.Ribbon.RibbonButton)oEditor.FindName("oSaveItemButton");
            var oGenerate = (System.Windows.Controls.Ribbon.RibbonButton)oEditor.FindName("oGeneratePasswordButton");
            var oUpload = (System.Windows.Controls.Ribbon.RibbonButton)oEditor.FindName("oUploadAFile");
            foreach (double nFontSize in new[] { 12d, 18d, 24d })
            {
                oEditor.FontSize = nFontSize;
                oEditor.SetEditingControls(false);
                oEditor.UpdateLayout();
                Check(!oCopy.IsVisible && !oRich.IsVisible && !oPlain.IsVisible,
                    "Copy is hidden when secret text is locked at font size " + nFontSize);
                Check(oUnlock.IsVisible && oUnlock.IsEnabled && oUnlock.ActualWidth >= 28 && !oSave.IsVisible,
                    "Locking restores a visible unlock action and hides saving at font size " + nFontSize);
                Size oUnlockSize = oUnlock.RenderSize;
                Point oUnlockPosition = oUnlock.TranslatePoint(new Point(), oRoot);
                Point oGeneratePosition = oGenerate.TranslatePoint(new Point(), oRoot);
                Point oUploadPosition = oUpload.TranslatePoint(new Point(), oRoot);
                oEditor.SetEditingControls(true);
                oEditor.UpdateLayout();
                Check(!oUnlock.IsVisible && oSave.IsVisible && oSave.ActualWidth >= 28,
                    "Unlocking restores a visible save action and hides unlocking at font size " + nFontSize);
                Check(oSave.RenderSize == oUnlockSize &&
                    (oSave.TranslatePoint(new Point(), oRoot) - oUnlockPosition).Length < 0.1 &&
                    (oGenerate.TranslatePoint(new Point(), oRoot) - oGeneratePosition).Length < 0.1 &&
                    (oUpload.TranslatePoint(new Point(), oRoot) - oUploadPosition).Length < 0.1,
                    "Primary action toggles without moving ribbon controls at font size " + nFontSize);
            }
        }
        finally
        {
            oEditor.ThisItem.ItemType = sOriginalType;
            oEditor.SetEditingControls(true);
            typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                .SetValue(oEditor, false);
            oEditor.Width = nOriginalWidth;
            oEditor.FontSize = nOriginalFontSize;
        }
    }

    private static void TestPasswordGeneratorLayout()
    {
        string sConnection = CryptureEntities.ConnectionString;
        CryptureEntities.ConnectionString = "";
        PasswordGenerator oGenerator = new PasswordGenerator
        {
            Width = 520, Height = 600, Left = -20000, Top = -20000,
            WindowStartupLocation = WindowStartupLocation.Manual,
            ShowActivated = false, ShowInTaskbar = false
        };
        try
        {
            // Exercise the real scroll viewport at minimum size with normal and enlarged text.
            oGenerator.Show();
            PumpUntil(() => oGenerator.IsLoaded);
            ScrollViewer oScroll = (ScrollViewer)((Grid)oGenerator.Content).Children[0];
            Border oResult = (Border)oGenerator.FindName("oPasswordResult");
            TextBox oPassword = (TextBox)oGenerator.FindName("oGeneratedPassword");
            MethodInfo oGenerate = typeof(PasswordGenerator).GetMethod("oGenerateButton_Click",
                BindingFlags.Instance | BindingFlags.NonPublic);
            foreach (double nFontSize in new[] { 12d, 18d })
            {
                oGenerator.FontSize = nFontSize;
                foreach (int nLength in new[] { 24, 1024 })
                {
                    ((TextBox)oGenerator.FindName("oMinimumLength")).Text = nLength.ToString();
                    ((TextBox)oGenerator.FindName("oMaximumLength")).Text = nLength.ToString();
                    oScroll.ScrollToTop();
                    oGenerator.UpdateLayout();
                    oGenerate.Invoke(oGenerator, new object[] { null, null });
                    oGenerator.UpdateLayout();
                    Rect oBounds = oResult.TransformToAncestor(oScroll).TransformBounds(
                        new Rect(oResult.RenderSize));
                    Check(oBounds.Top >= -1 && oBounds.Bottom <= oScroll.ViewportHeight + 1 &&
                        oPassword.Text.Length == nLength &&
                        ((Button)oGenerator.FindName("oCopyButton")).IsEnabled,
                        "Generated password and copy action stay visible at font size " + nFontSize +
                        " and " + nLength + " characters");
                }
            }
        }
        finally
        {
            oGenerator.Close();
            CryptureEntities.ConnectionString = sConnection;
        }
    }

    private static void TestClipboardTimeout()
    {
        DataObject oProtectedCopy = App.CreateProtectedClipboardData("Private clipboard value");
        Check(oProtectedCopy.GetText() == "Private clipboard value" &&
            oProtectedCopy.GetDataPresent(App.ClipboardExclusionFormat),
            "Protected copies retain text and carry the Windows history and cloud exclusion format");

        DateTime oNow = new DateTime(2026, 9, 28, 12, 0, 0, DateTimeKind.Utc);
        uint nCurrent = 1;
        int nClears = 0, nAttempts = 0;
        bool bBusy = false, bOwned = true;
        using (ClipboardExpiration oExpiry = new ClipboardExpiration(() => bOwned ? nCurrent : 0, nExpected =>
        {
            nAttempts++;
            if (bBusy) return false;
            if (nExpected == nCurrent) { nClears++; nCurrent++; }
            return true;
        }, () => oNow))
        {
            Check(ClipboardExpiration.Timeout == TimeSpan.FromMinutes(5),
                "Clipboard protection defaults to five minutes");
            oExpiry.ClearExpired();
            Check(nAttempts == 0, "Clipboard is untouched before a protected copy");
            oExpiry.TrackCopy();
            oNow = oNow.AddMinutes(5).AddMilliseconds(-1);
            oExpiry.ClearExpired();
            Check(nClears == 0 && nAttempts == 0, "Clipboard remains available before its timeout");
            oNow = oNow.AddMilliseconds(1);
            oExpiry.ClearExpired();
            Check(nClears == 1, "Unchanged copied content clears at five minutes");
            oExpiry.ClearExpired();
            Check(nAttempts == 1, "Successful clearing cancels further expiration attempts");

            oExpiry.TrackCopy();
            oNow = oNow.AddMinutes(4);
            nCurrent++;
            oExpiry.TrackCopy();
            oNow = oNow.AddMinutes(1);
            oExpiry.ClearExpired();
            Check(nClears == 1, "A later protected copy gets its own full five-minute timeout");
            oNow = oNow.AddMinutes(4);
            oExpiry.ClearExpired();
            Check(nClears == 2, "The most recent protected copy expires at its new deadline");

            oExpiry.TrackCopy();
            nCurrent++;
            oNow = oNow.AddMinutes(5);
            oExpiry.ClearExpired();
            Check(nClears == 2, "A newer clipboard sequence is preserved even if its text is identical");
            int nStopped = nAttempts;
            oExpiry.ClearExpired();
            Check(nAttempts == nStopped, "Replaced clipboard content cancels the old expiration");

            bOwned = false;
            oExpiry.TrackCopy();
            oNow = oNow.AddMinutes(5);
            oExpiry.ClearExpired();
            Check(nAttempts == nStopped, "Another process's clipboard content never starts an expiration");
            bOwned = true;
            oExpiry.TrackCopy();
            oNow = oNow.AddMinutes(5);
            bBusy = true;
            oExpiry.ClearExpired();
            Check(nClears == 2, "A busy clipboard is retried without clearing or losing the pending timeout");
            bBusy = false;
            PumpUntil(() => nClears == 3);
            Check(nClears == 3, "The dispatcher timer retries and clears overdue clipboard content");

            oExpiry.TrackCopy();
            oExpiry.Dispose();
            Check(nClears == 4, "Application exit clears tracked content before its deadline");
            oExpiry.Dispose();
            Check(nClears == 4, "Repeated cleanup does not touch later clipboard content");
        }
        using (ClipboardExpiration oExit = new ClipboardExpiration(() => nCurrent, nExpected =>
        {
            if (nExpected == nCurrent) nClears++;
            return true;
        }, () => oNow))
        {
            oExit.TrackCopy();
            nCurrent++;
        }
        Check(nClears == 4, "Application exit preserves content copied afterward");
    }

    private static void PumpUntil(Func<bool> oCompleted)
    {
        System.Diagnostics.Stopwatch oWatch = System.Diagnostics.Stopwatch.StartNew();
        System.Windows.Threading.DispatcherFrame oFrame = new System.Windows.Threading.DispatcherFrame();
        System.Windows.Threading.DispatcherTimer oTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(25)
        };
        oTimer.Tick += (s, e) =>
        {
            if (oCompleted() || oWatch.Elapsed > TimeSpan.FromSeconds(30)) oFrame.Continue = false;
        };
        oTimer.Start();
        try
        {
            System.Windows.Threading.Dispatcher.PushFrame(oFrame);
        }
        finally
        {
            oTimer.Stop();
        }
        if (!oCompleted()) throw new TimeoutException("The asynchronous operation did not finish.");
    }
}
