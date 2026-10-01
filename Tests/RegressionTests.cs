using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
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
        if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_CONCURRENCY_ROLE") is string sRole)
            return RunConcurrencyWorker(sRole);
        string sDirectory = Path.Combine(Path.GetTempPath(), "Crypture.Tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sDirectory);
        try
        {
            if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_CONFIG_STARTUP") == "1")
            {
                TestCertificateUsageStartup();
                return 0;
            }
            using (RSA oKey = new RSACng(2048))
            using (RSA oOtherKey = new RSACng(2048))
            using (X509Certificate2 oCert = Certificate(oKey, "Test", DateTimeOffset.Now.AddDays(-1),
                DateTimeOffset.Now.AddDays(1)))
            using (X509Certificate2 oOtherCert = Certificate(oOtherKey, "Other", DateTimeOffset.Now.AddDays(-1),
                DateTimeOffset.Now.AddDays(1)))
            {
                TestConcurrentDatabase(sDirectory, oCert, oOtherCert);
                if (Environment.GetEnvironmentVariable("CRYPTURE_TEST_CONCURRENCY_ONLY") == "1") return 0;
                TestEncryption(oCert, oOtherCert);
                TestTotpAlgorithms(oCert);
                TestPrincipalProtection();
                TestPasswordGeneration();
                TestClipboardTimeout();
                TestDirectoryResolution();
                TestCertificates(oKey, oCert);
                TestCertificateVisibility(oKey);
                TestCertificateAlgorithms(sDirectory, oCert);
                TestCertificateUsageFilters(oKey);
                TestCompression();
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

    private static void TestCompression()
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
    }

    private static void TestDatabase(string sDirectory, X509Certificate2 oCert, X509Certificate2 oOtherCert)
    {
        string sDatabase = Path.Combine(sDirectory, "Vault ; \u00e9.cryptdb");
        string sSchema = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SQLite.sql"));
        DatabaseOperations.CreateDatabase(sDatabase, sSchema);
        byte[] oOriginalDatabase = File.ReadAllBytes(sDatabase);
        Reject(() => DatabaseOperations.CreateDatabase(sDatabase, sSchema), "Refuse to overwrite existing Vault");
        Check(File.ReadAllBytes(sDatabase).SequenceEqual(oOriginalDatabase),
            "Preserve refused overwrite byte for byte");
        string sBadDatabase = Path.Combine(sDirectory, "broken.cryptdb");
        Reject(() => DatabaseOperations.CreateDatabase(sBadDatabase, "invalid sql"), "Report schema creation failure");
        Check(!File.Exists(sBadDatabase), "Remove incomplete new Vault");

        string sLegacySchema = sSchema.Replace("\t[ModifiedByIdentity] nvarchar NULL,\r\n", "")
            .Replace("\t[ProtectionDescriptor] nvarchar NULL,\r\n", "")
            .Replace("\t[ProtectedKey] blob NULL,\r\n", "")
            .Replace("\t[Signature] blob NULL\r\n", "")
            .Replace("[CipherParams] integer DEFAULT '0' NOT NULL,", "[CipherParams] integer DEFAULT '0' NOT NULL");
        sLegacySchema = sLegacySchema.Substring(0,
            sLegacySchema.IndexOf("CREATE TABLE IF NOT EXISTS [PasswordGeneratorSettings]", StringComparison.Ordinal));
        string sLegacyDatabase = Path.Combine(sDirectory, "legacy-schema.cryptdb");
        DatabaseOperations.CreateDatabase(sLegacyDatabase, sLegacySchema);
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
                "INSERT INTO Item (ItemId, Label, ItemType) VALUES (1, 'Before upgrade', 'text'); " +
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
        DatabaseOperations.EnsureProtectionSchema(sLegacyDatabase);
        DatabaseOperations.EnsureProtectionSchema(sLegacyDatabase);
        CryptureEntities.DatabasePath = sLegacyDatabase;
        Check(DatabaseOperations.LoadPasswordOptions().MinimumLength == 20,
            "Old Vault migration adds generator settings with safe defaults");
        oLegacyItem = DatabaseOperations.LoadItem(1);
        Check(oLegacyItem.Cipher.ProtectionDescriptor == null && oLegacyItem.ModifiedByIdentity == null,
            "Upgrade old Vault schema idempotently");
        Check(ItemCryptography.Decrypt(oLegacyItem, oLegacyItem.Instances.Single(), oCert).SequenceEqual(oLegacyPlain),
            "Schema migration preserves existing ciphertext and recipient keys");
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
        DatabaseOperations.SavePasswordOptions(oPasswordOptions);
        PasswordOptions oLoadedOptions = DatabaseOperations.LoadPasswordOptions();
        Check(oLoadedOptions.MinimumLength == 25 && oLoadedOptions.MaximumLength == 37 &&
            !oLoadedOptions.IncludeUppercase && oLoadedOptions.IncludeLowercase && !oLoadedOptions.IncludeDigits &&
            oLoadedOptions.IncludeSymbols && oLoadedOptions.SymbolCharacters == oPasswordOptions.SymbolCharacters &&
            oLoadedOptions.ExcludedCharacters == oPasswordOptions.ExcludedCharacters &&
            !oLoadedOptions.RequireEachType && !oLoadedOptions.ExcludeSimilar,
            "Persist every password option including quoted character lists");
        CryptureEntities.DatabasePath = sLegacyDatabase;
        Check(DatabaseOperations.LoadPasswordOptions().MaximumLength == 24,
            "Password settings belong to each Vault file independently");
        CryptureEntities.DatabasePath = sDatabase;
        Reject(() => DatabaseOperations.SavePasswordOptions(new PasswordOptions { MinimumLength = 0 }),
            "Reject invalid settings before modifying the Vault");
        Check(DatabaseOperations.LoadPasswordOptions().MaximumLength == 37,
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
        DateTime oCreated = oItem.CreatedDate;
        byte[] oOriginalVector = oItem.Cipher.CipherVector.ToArray();
        Item oStale = DatabaseOperations.LoadItem(nItemId);
        oItem.Label = "Updated";
        oItem.ModifiedBy = oOtherUser.UserId;
        DatabaseOperations.SaveItem(oItem, oPlainText, new[] { oUser, oOtherUser });
        oItem = DatabaseOperations.LoadItem(nItemId);
        Check(oItem.CreatedDate == oCreated, "Preserve original creation date on update");
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
        Check(DatabaseOperations.LoadPasswordOptions().MaximumLength == 37,
            "Vault backups include password generator preferences");
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
            oEditor.Close();
            oEditor = null;
            CryptureEntities.DatabasePath = sDatabase;

            // Keep persistence and security assertions independently of menu and dialog presentation.
            oBrowser = new ItemBrowser();
            TestRecentVaultHistory(oBrowser, sDatabase, sDirectory);
            TestTotpVault(sDirectory);
            TestCertificateUsageConfiguration(oBrowser, oItem);
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

    private static void TestClipboardTimeout()
    {
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
