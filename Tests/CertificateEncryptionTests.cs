using System;
using System.IO;
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
                using (X509Certificate2 oCert = new X509Certificate2(oOriginal.RawData))
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
        return new X509Certificate2(oCertificate.Encode());
    }

    private static void TestRecipientEnvelope(X509Certificate2 oCert, X509Certificate2 oRsaCert, string sName)
    {
        byte[] oPlain = Encoding.UTF8.GetBytes("ECC and post-quantum recipient test\n\u2603");
        User[] oRecipients = { new User { UserId = 8, Certificate = oCert.RawData },
            new User { UserId = 9, Certificate = oRsaCert.RawData } };
        Item oItem = new Item { Label = "Algorithm test", ItemType = "text" };
        ItemCryptography.Encrypt(oItem, oPlain, oRecipients);
        Instance oInstance = oItem.Instances.First();
        Check(oItem.Cipher.CipherParams == ItemCryptography.CertificateFormat &&
            ItemCryptography.Decrypt(oItem, oInstance, oCert).SequenceEqual(oPlain), sName + " round trip");
        Check(ItemCryptography.Decrypt(oItem, oItem.Instances.Last(), oRsaCert).SequenceEqual(oPlain),
            sName + " mixed RSA recipient round trip");
        byte[] oFirstEnvelope = oInstance.CipherKey.ToArray();
        ItemCryptography.Encrypt(oItem, oPlain, oRecipients);
        oInstance = oItem.Instances.First();
        Check(!oFirstEnvelope.SequenceEqual(oInstance.CipherKey), sName + " fresh encapsulation per save");
        using (X509Certificate2 oPublicOnly = new X509Certificate2(oCert.RawData))
            RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oPublicOnly),
                sName + " requires a private key");
        RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oRsaCert),
            sName + " rejects incorrect recipient algorithm");
        foreach (int nOffset in new[] { 0, 4, 8, oInstance.CipherKey.Length - 17, oInstance.CipherKey.Length - 1 })
        {
            oInstance.CipherKey[nOffset] ^= 1;
            RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
                sName + " rejects modified key envelope at " + nOffset);
            oInstance.CipherKey[nOffset] ^= 1;
        }
        byte[] oSaved = oInstance.CipherKey;
        foreach (byte[] oBadEnvelope in new[] { new byte[0], oSaved.Take(oSaved.Length - 1).ToArray(),
            oSaved.Concat(new byte[1]).ToArray(), new byte[4097] })
        {
            oInstance.CipherKey = oBadEnvelope;
            RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
                sName + " rejects malformed envelope of " + oBadEnvelope.Length + " bytes");
        }
        oInstance.CipherKey = oSaved;
        oInstance.UserId++;
        RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
            sName + " authenticates the recipient identity");
        oInstance.UserId--;
        oItem.Cipher.CipherParams = oInstance.CipherParams = ItemCryptography.AuthenticatedFormat;
        RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
            sName + " rejects a format downgrade");
        oItem.Cipher.CipherParams = oInstance.CipherParams = ItemCryptography.CertificateFormat;
        oItem.Label = "Tampered";
        RejectCryptography(() => ItemCryptography.Decrypt(oItem, oInstance, oCert),
            sName + " authenticates item metadata");
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
        Check(oStored.ProtectionDisplay == "Certificates" &&
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
