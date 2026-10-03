using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Formats.Asn1;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Crypture
{
    internal enum RecipientAlgorithm
    {
        Rsa = 1,
        EcdhP256 = 2,
        EcdhP384 = 3,
        EcdhP521 = 4,
        MlKem512 = 5,
        MlKem768 = 6,
        MlKem1024 = 7
    }

    internal static class CertificateKeyProtection
    {
        // Minimum RSA certificate strength.
        internal const int MinimumRsaKeyBits = 2048;

        // ECC public points contain X and Y coordinates.
        private const int EccCoordinateCount = 2;

        // Recipient envelope framing and authenticated wrapping sizes.
        private const int EnvelopeHeaderBytes = sizeof(int) * 2;
        private const int WrappingKeyBytes = 32;
        private const int GcmNonceBytes = 12;
        private const int GcmTagBytes = 16;
        private static readonly byte[] KeyLabel = Encoding.ASCII.GetBytes("Crypture Recipient Key v3");
        internal static bool IsPostQuantumSupported => MLKem.IsSupported;
        public static string AvailabilityDescription => IsPostQuantumSupported
            ? "RSA, ECC (ECDH), and ML-KEM encryption are available on this computer."
            : "RSA and ECC (ECDH) encryption are available. ML-KEM requires a Windows version with ML-KEM support.";

        internal static RecipientAlgorithm GetAlgorithm(X509Certificate2 oCert)
        {
            // Public-key algorithm identifiers.
            const string RsaPublicKeyOid = "1.2.840.113549.1.1.1";
            const string EcPublicKeyOid = "1.2.840.10045.2.1";

            // Supported named ECC curves.
            const string P256CurveOid = "1.2.840.10045.3.1.7";
            const string P384CurveOid = "1.3.132.0.34";
            const string P521CurveOid = "1.3.132.0.35";

            // ML-KEM parameter-set identifiers.
            const string MlKem512Oid = "2.16.840.1.101.3.4.4.1";
            const string MlKem768Oid = "2.16.840.1.101.3.4.4.2";
            const string MlKem1024Oid = "2.16.840.1.101.3.4.4.3";
            switch (oCert.PublicKey.Oid.Value)
            {
                case RsaPublicKeyOid:
                    using (RSA oRsa = oCert.GetRSAPublicKey())
                    {
                        if (oRsa == null || oRsa.KeySize < MinimumRsaKeyBits)
                            throw new CryptographicException("RSA encryption certificates need at least 2048 bits.");
                    }
                    return RecipientAlgorithm.Rsa;
                case EcPublicKeyOid:
                    string sCurve = GetCurveOid(oCert);
                    if (sCurve == P256CurveOid) return RecipientAlgorithm.EcdhP256;
                    if (sCurve == P384CurveOid) return RecipientAlgorithm.EcdhP384;
                    if (sCurve == P521CurveOid) return RecipientAlgorithm.EcdhP521;
                    throw new CryptographicException("ECC encryption requires the P-256, P-384, or P-521 curve.");
                case MlKem512Oid: return RecipientAlgorithm.MlKem512;
                case MlKem768Oid: return RecipientAlgorithm.MlKem768;
                case MlKem1024Oid: return RecipientAlgorithm.MlKem1024;
                default:
                    throw new CryptographicException("Select an RSA, ECDH, or ML-KEM encryption certificate. " +
                        "Signature-only algorithms cannot encrypt Vault items.");
            }
        }

        internal static string GetAlgorithmDisplay(X509Certificate2 oCert)
        {
            try
            {
                switch (GetAlgorithm(oCert))
                {
                    case RecipientAlgorithm.Rsa: return "RSA";
                    case RecipientAlgorithm.EcdhP256: return "ECC P-256 (ECDH)";
                    case RecipientAlgorithm.EcdhP384: return "ECC P-384 (ECDH)";
                    case RecipientAlgorithm.EcdhP521: return "ECC P-521 (ECDH)";
                    case RecipientAlgorithm.MlKem512: return "ML-KEM-512";
                    case RecipientAlgorithm.MlKem768: return "ML-KEM-768";
                    case RecipientAlgorithm.MlKem1024: return "ML-KEM-1024";
                    default: return "Unsupported";
                }
            }
            catch (CryptographicException)
            {
                return "Unsupported";
            }
        }

        internal static void ValidateForEncryption(X509Certificate2 oCert)
        {
            RecipientAlgorithm oAlgorithm = GetAlgorithm(oCert);
            bool bEcdh = IsEcdh(oAlgorithm);
            X509KeyUsageExtension oUsage = oCert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            X509KeyUsageFlags oRequired = bEcdh ? X509KeyUsageFlags.KeyAgreement : X509KeyUsageFlags.KeyEncipherment;
            if (oUsage != null && ((oUsage.KeyUsages & oRequired) == 0 ||
                (bEcdh && (oUsage.KeyUsages & X509KeyUsageFlags.EncipherOnly) != 0)))
                throw new CryptographicException(bEcdh
                    ? "ECC recipients need Key Agreement permission and a private key that supports ECDH."
                    : "RSA and ML-KEM recipients need Key Encipherment permission.");

            if (oAlgorithm >= RecipientAlgorithm.MlKem512)
            {
                using (MLKem oPublic = GetMlKemPublicKey(oCert, oAlgorithm)) { }
            }
        }

        internal static bool IsEcdh(RecipientAlgorithm oAlgorithm) =>
            oAlgorithm >= RecipientAlgorithm.EcdhP256 && oAlgorithm <= RecipientAlgorithm.EcdhP521;

        private static int GetEcdhCoordinateBytes(RecipientAlgorithm oAlgorithm)
        {
            const int P256CoordinateBytes = 32;
            const int P384CoordinateBytes = 48;
            const int P521CoordinateBytes = 66;
            return oAlgorithm switch
            {
                RecipientAlgorithm.EcdhP256 => P256CoordinateBytes,
                RecipientAlgorithm.EcdhP384 => P384CoordinateBytes,
                RecipientAlgorithm.EcdhP521 => P521CoordinateBytes,
                _ => throw new CryptographicException("Unsupported ECDH curve.")
            };
        }

        internal static MLKemAlgorithm GetMlKemAlgorithm(RecipientAlgorithm oAlgorithm)
        {
            if (!IsPostQuantumSupported)
                throw new PlatformNotSupportedException("ML-KEM encryption is unavailable on this computer. " +
                    "Update Windows to a version with ML-KEM support. The selected protection has not been changed.");
            switch (oAlgorithm)
            {
                case RecipientAlgorithm.MlKem512: return MLKemAlgorithm.MLKem512;
                case RecipientAlgorithm.MlKem768: return MLKemAlgorithm.MLKem768;
                case RecipientAlgorithm.MlKem1024: return MLKemAlgorithm.MLKem1024;
                default: throw new CryptographicException("Unsupported ML-KEM parameter set.");
            }
        }

        private static MLKem GetMlKemPublicKey(X509Certificate2 oCert, RecipientAlgorithm oAlgorithm)
        {
            MLKemAlgorithm oParameters = GetMlKemAlgorithm(oAlgorithm);
            if (oCert.PublicKey.EncodedParameters?.RawData?.Length > 0)
                throw new CryptographicException("The ML-KEM certificate has invalid algorithm parameters.");
            return MLKem.ImportEncapsulationKey(oParameters, oCert.GetPublicKey());
        }

        internal static ECDiffieHellmanCng GetEcdhPublicKey(X509Certificate2 oCert)
        {
            const int UncompressedPointPrefixBytes = 1;
            const byte UncompressedPointMarker = 4;
            RecipientAlgorithm oAlgorithm = GetAlgorithm(oCert);
            int nSize = GetEcdhCoordinateBytes(oAlgorithm);
            byte[] oPoint = oCert.GetPublicKey();
            if (oPoint.Length != UncompressedPointPrefixBytes + EccCoordinateCount * nSize ||
                oPoint[0] != UncompressedPointMarker)
                throw new CryptographicException("The ECC certificate has an invalid public key.");
            ECDiffieHellmanCng oKey = new ECDiffieHellmanCng();
            try
            {
                oKey.ImportParameters(new ECParameters
                {
                    Curve = ECCurve.CreateFromValue(GetCurveOid(oCert)),
                    Q = new ECPoint
                    {
                        X = oPoint.Skip(UncompressedPointPrefixBytes).Take(nSize).ToArray(),
                        Y = oPoint.Skip(UncompressedPointPrefixBytes + nSize).ToArray()
                    }
                });
                return oKey;
            }
            catch
            {
                oKey.Dispose();
                throw;
            }
        }

        private static string GetCurveOid(X509Certificate2 oCert)
        {
            try
            {
                AsnReader oReader = new AsnReader(oCert.PublicKey.EncodedParameters.RawData, AsnEncodingRules.DER);
                string sOid = oReader.ReadObjectIdentifier();
                oReader.ThrowIfNotEmpty();
                return sOid;
            }
            catch (AsnContentException oError)
            {
                throw new CryptographicException("The ECC certificate must specify a supported named curve.", oError);
            }
        }

        internal static CngKey GetPrivateKey(X509Certificate2 oCert)
        {
            // Acquisition flags require a cached CNG key handle.
            const uint CacheAcquiredKey = 0x00000001;
            const uint RequireCngKey = 0x00040000;
            if (!oCert.HasPrivateKey)
                throw new CryptographicException("The certificate's private key is unavailable in your Windows store.");
            SafeNCryptKeyHandle oHandle;
            uint nKeySpec;
            bool bCallerFrees;
            bool bAcquired = NativeMethods.CryptAcquireCertificatePrivateKey(oCert.Handle,
                CacheAcquiredKey | RequireCngKey, IntPtr.Zero, out oHandle, out nKeySpec, out bCallerFrees);
            int nError = Marshal.GetLastWin32Error();
            using (oHandle)
            {
                try
                {
                    if (!bAcquired)
                        throw new CryptographicException("Windows could not open the certificate's CNG private key.",
                            new CryptographicException(nError));
                    const uint KeyProviderInfoProperty = 2;
                    uint nSize = 0;
                    bool bPersisted = NativeMethods.CertGetCertificateContextProperty(oCert.Handle, KeyProviderInfoProperty,
                        IntPtr.Zero, ref nSize);
                    return CngKey.Open(oHandle, bPersisted
                        ? CngKeyHandleOpenOptions.None : CngKeyHandleOpenOptions.EphemeralKey);
                }
                finally
                {
                    if (!bCallerFrees) oHandle?.SetHandleAsInvalid();
                    GC.KeepAlive(oCert);
                }
            }
        }

        internal static byte[] Wrap(X509Certificate2 oCert, byte[] oKeys)
        {
            ValidateForEncryption(oCert);
            RecipientAlgorithm oAlgorithm = GetAlgorithm(oCert);
            byte[] oSecret = null;
            byte[] oWrappingKey = null;
            try
            {
                using (MemoryStream oStream = new MemoryStream())
                using (BinaryWriter oWriter = new BinaryWriter(oStream))
                {
                    oWriter.Write((int)oAlgorithm);
                    if (oAlgorithm == RecipientAlgorithm.Rsa)
                    {
                        using (RSA oPublic = oCert.GetRSAPublicKey())
                        {
                            byte[] oWrapped = oPublic.Encrypt(oKeys, RSAEncryptionPadding.OaepSHA1);
                            oWriter.Write(oWrapped.Length);
                            oWriter.Write(oWrapped);
                            return oStream.ToArray();
                        }
                    }

                    byte[] oEncapsulation;
                    if (IsEcdh(oAlgorithm))
                    {
                        using (ECDiffieHellmanCng oPublic = GetEcdhPublicKey(oCert))
                        using (ECDiffieHellmanCng oEphemeral = new ECDiffieHellmanCng(oPublic.KeySize))
                        using (ECDiffieHellmanPublicKey oRecipientPublic = oPublic.PublicKey)
                        {
                            oSecret = oEphemeral.DeriveKeyFromHash(oRecipientPublic, HashAlgorithmName.SHA256);
                            oEncapsulation = oEphemeral.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                        }
                    }
                    else
                    {
                        using (MLKem oPublic = GetMlKemPublicKey(oCert, oAlgorithm))
                            oPublic.Encapsulate(out oEncapsulation, out oSecret);
                    }
                    oWriter.Write(oEncapsulation.Length);
                    oWriter.Write(oEncapsulation);
                    byte[] oContext = GetContext(oCert, oStream.ToArray());
                    oWrappingKey = SP800108HmacCounterKdf.DeriveBytes(oSecret, HashAlgorithmName.SHA256,
                        KeyLabel, oContext, WrappingKeyBytes);
                    byte[] oNonce = new byte[GcmNonceBytes];
                    byte[] oTag = new byte[GcmTagBytes];
                    byte[] oCipherText = new byte[oKeys.Length];
                    using (RandomNumberGenerator oRandom = RandomNumberGenerator.Create()) oRandom.GetBytes(oNonce);
                    using (AesGcm oAes = new AesGcm(oWrappingKey, oTag.Length))
                        oAes.Encrypt(oNonce, oKeys, oCipherText, oTag, oContext);
                    oWriter.Write(oNonce);
                    oWriter.Write(oCipherText);
                    oWriter.Write(oTag);
                    return oStream.ToArray();
                }
            }
            finally
            {
                if (oSecret != null) Array.Clear(oSecret, 0, oSecret.Length);
                if (oWrappingKey != null) Array.Clear(oWrappingKey, 0, oWrappingKey.Length);
            }
        }

        internal static byte[] Unwrap(X509Certificate2 oCert, byte[] oEnvelope)
        {
            const int MaximumEnvelopeBytes = 4096;
            if (oEnvelope == null || oEnvelope.Length < EnvelopeHeaderBytes ||
                oEnvelope.Length > MaximumEnvelopeBytes)
                throw new CryptographicException("The recipient key envelope is damaged.");
            byte[] oSecret = null;
            byte[] oWrappingKey = null;
            byte[] oKeys = new byte[ItemCryptography.ContentKeyBytes];
            bool bSuccess = false;
            try
            {
                using (MemoryStream oStream = new MemoryStream(oEnvelope, false))
                using (BinaryReader oReader = new BinaryReader(oStream))
                {
                    RecipientAlgorithm oAlgorithm = (RecipientAlgorithm)oReader.ReadInt32();
                    int nLength = oReader.ReadInt32();
                    if (oAlgorithm != GetAlgorithm(oCert) || nLength <= 0 ||
                        nLength > oEnvelope.Length - EnvelopeHeaderBytes)
                        throw new CryptographicException("The recipient algorithm or key envelope is invalid.");
                    if (oAlgorithm == RecipientAlgorithm.Rsa)
                    {
                        const int BitsPerByte = 8;
                        using (RSA oPrivate = oCert.GetRSAPrivateKey())
                        {
                            if (oPrivate == null || nLength != oPrivate.KeySize / BitsPerByte ||
                                oEnvelope.Length != nLength + EnvelopeHeaderBytes)
                                throw new CryptographicException("The RSA private key or recipient envelope is invalid.");
                            return oPrivate.Decrypt(oReader.ReadBytes(nLength), RSAEncryptionPadding.OaepSHA1);
                        }
                    }
                    const int EccPublicBlobHeaderBytes = 8;
                    int nExpected = IsEcdh(oAlgorithm)
                        ? EccPublicBlobHeaderBytes + EccCoordinateCount * GetEcdhCoordinateBytes(oAlgorithm)
                        : GetMlKemAlgorithm(oAlgorithm).CiphertextSizeInBytes;
                    if (nLength != nExpected || oEnvelope.Length != EnvelopeHeaderBytes + nLength +
                        GcmNonceBytes + ItemCryptography.ContentKeyBytes + GcmTagBytes)
                        throw new CryptographicException("The recipient key envelope is damaged.");
                    byte[] oEncapsulation = oReader.ReadBytes(nLength);
                    byte[] oContext = GetContext(oCert, oEnvelope.Take(EnvelopeHeaderBytes + nLength).ToArray());
                    using (CngKey oPrivate = GetPrivateKey(oCert))
                    {
                        if (IsEcdh(oAlgorithm))
                        {
                            if (oPrivate.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
                                throw new CryptographicException("The certificate's private key only supports signing. " +
                                    "Use an ECC certificate with an ECDH private key and Key Agreement permission.");
                            using (ECDiffieHellmanCng oAgreement = new ECDiffieHellmanCng(oPrivate))
                            using (ECDiffieHellmanPublicKey oPublic = ECDiffieHellmanCngPublicKey.FromByteArray(
                                oEncapsulation, CngKeyBlobFormat.EccPublicBlob))
                                oSecret = oAgreement.DeriveKeyFromHash(oPublic, HashAlgorithmName.SHA256);
                        }
                        else
                        {
                            using (MLKem oKem = new MLKemCng(oPrivate))
                                oSecret = oKem.Decapsulate(oEncapsulation);
                        }
                    }
                    oWrappingKey = SP800108HmacCounterKdf.DeriveBytes(oSecret, HashAlgorithmName.SHA256,
                        KeyLabel, oContext, WrappingKeyBytes);
                    byte[] oNonce = oReader.ReadBytes(GcmNonceBytes);
                    byte[] oCipherText = oReader.ReadBytes(ItemCryptography.ContentKeyBytes);
                    byte[] oTag = oReader.ReadBytes(GcmTagBytes);
                    using (AesGcm oAes = new AesGcm(oWrappingKey, oTag.Length))
                        oAes.Decrypt(oNonce, oCipherText, oTag, oKeys, oContext);
                    bSuccess = true;
                    return oKeys;
                }
            }
            finally
            {
                if (!bSuccess) Array.Clear(oKeys, 0, oKeys.Length);
                if (oSecret != null) Array.Clear(oSecret, 0, oSecret.Length);
                if (oWrappingKey != null) Array.Clear(oWrappingKey, 0, oWrappingKey.Length);
            }
        }

        private static byte[] GetContext(X509Certificate2 oCert, byte[] oHeader)
        {
            using (SHA256 oHash = SHA256.Create())
                return oHeader.Concat(oHash.ComputeHash(oCert.RawData)).ToArray();
        }
    }
}
