using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Crypture
{
    internal enum ContentEncryptionSuite : long
    {
        Aes256Gcm = 1,
        Aes256CbcHmacSha256 = 2
    }

    internal static class ItemCryptography
    {
        internal const long AuthenticatedFormat = 1;
        internal const long PrincipalFormat = 2;
        internal const long CertificateFormat = 3;
        internal const long RecoveryFormat = 4;

        internal static bool UsesWindowsProtection(Cipher oCipher) => oCipher?.CipherParams == PrincipalFormat ||
            oCipher?.CipherParams == RecoveryFormat && oCipher.ProtectionDescriptor != null;

        internal static ContentEncryptionSuite ReadContentEncryptionSuite()
        {
            // Read the adjacent deployment policy at the save boundary without affecting stored-item access.
            string sPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
            try
            {
                Configuration oConfig = ConfigurationManager.OpenMappedExeConfiguration(
                    new ExeConfigurationFileMap { ExeConfigFilename = sPath }, ConfigurationUserLevel.None);
                string sSuite = oConfig.AppSettings.Settings["ContentEncryptionSuite"]?.Value.Trim();
                ContentEncryptionSuite nSuite = sSuite switch
                {
                    null or nameof(ContentEncryptionSuite.Aes256Gcm) => ContentEncryptionSuite.Aes256Gcm,
                    nameof(ContentEncryptionSuite.Aes256CbcHmacSha256) => ContentEncryptionSuite.Aes256CbcHmacSha256,
                    _ => throw new InvalidOperationException("The ContentEncryptionSuite setting in " + sPath +
                        " must be Aes256Gcm or Aes256CbcHmacSha256.")
                };
                if (nSuite == ContentEncryptionSuite.Aes256Gcm && !AesGcm.IsSupported)
                    throw new PlatformNotSupportedException("AES-256-GCM is unavailable on this computer.");
                return nSuite;
            }
            catch (ConfigurationErrorsException oError)
            {
                throw new InvalidOperationException("The encryption settings in " + sPath +
                    " could not be read. Correct the configuration before saving.", oError);
            }
        }

        // An absent suite identifies CBC content with format-specific authentication.
        internal static bool HasSupportedContentSuite(Cipher oCipher) => oCipher.ContentSuite == null ||
            (oCipher.ContentSuite == (long)ContentEncryptionSuite.Aes256Gcm ||
                oCipher.ContentSuite == (long)ContentEncryptionSuite.Aes256CbcHmacSha256) &&
            oCipher.CipherParams is PrincipalFormat or CertificateFormat or RecoveryFormat;

        internal static void Encrypt(Item oItem, byte[] oPlainText, IEnumerable<User> oRecipients,
            string sProtectionDescriptor = null, string sRecoveryDescriptor = null,
            ContentEncryptionSuite nContentSuite = ContentEncryptionSuite.Aes256Gcm)
        {
            int nMaxSize = oItem.ItemType is "text" or "richtext" or "totp"
                ? Utilities.MaxItemSize : Utilities.MaxCompressedItemSize;
            if (oPlainText == null || oPlainText.Length > nMaxSize)
                throw new InvalidDataException("Items must be no larger than 64 MB.");
            if (nContentSuite is not (ContentEncryptionSuite.Aes256Gcm or ContentEncryptionSuite.Aes256CbcHmacSha256))
                throw new CryptographicException("The content encryption suite is unsupported.");

            // Content encryption and recipient access are independent parts of the stored format.
            bool bPrincipals = sProtectionDescriptor != null;
            if (bPrincipals) PrincipalProtection.ParseDescriptor(sProtectionDescriptor, out _, false);
            List<User> oUsers = (oRecipients ?? Enumerable.Empty<User>()).GroupBy(u => u.UserId)
                .Select(g => g.First()).ToList();
            bool bRecovery = sRecoveryDescriptor != null || bPrincipals && oUsers.Count != 0;
            long nFormat = bRecovery ? RecoveryFormat : bPrincipals ? PrincipalFormat : CertificateFormat;
            byte[] oKeys = new byte[64];
            byte[] oEncryptionKey = new byte[32];
            byte[] oAuthenticationKey = new byte[32];
            try
            {
                using (RandomNumberGenerator oRandom = RandomNumberGenerator.Create()) oRandom.GetBytes(oKeys);
                Buffer.BlockCopy(oKeys, 0, oEncryptionKey, 0, 32);
                Buffer.BlockCopy(oKeys, 32, oAuthenticationKey, 0, 32);
                oItem.Cipher = new Cipher
                {
                    CipherParams = nFormat,
                    ContentSuite = (long)nContentSuite,
                    ProtectionDescriptor = sProtectionDescriptor
                };

                // Encrypt once with fresh keys and a fresh nonce, then share the keys with each recipient.
                if (nContentSuite == ContentEncryptionSuite.Aes256Gcm)
                {
                    oItem.Cipher.CipherVector = RandomNumberGenerator.GetBytes(12);
                    oItem.Cipher.CipherText = new byte[oPlainText.Length];
                    oItem.Cipher.AuthenticationTag = new byte[16];
                    using (AesGcm oAes = new AesGcm(oEncryptionKey, 16))
                        oAes.Encrypt(oItem.Cipher.CipherVector, oPlainText, oItem.Cipher.CipherText,
                            oItem.Cipher.AuthenticationTag, GetAssociatedData(oItem));
                }
                else
                {
                    using (Aes oAes = new AesCng())
                    {
                        oAes.Key = oEncryptionKey;
                        oAes.Mode = CipherMode.CBC;
                        oAes.Padding = PaddingMode.PKCS7;
                        oAes.GenerateIV();
                        oItem.Cipher.CipherVector = oAes.IV;
                        using (ICryptoTransform oEncryptor = oAes.CreateEncryptor())
                            oItem.Cipher.CipherText = oEncryptor.TransformFinalBlock(oPlainText, 0, oPlainText.Length);
                    }
                }

                // Authenticate the protected keys and access policy independently for each access path.
                oItem.Instances.Clear();
                if (bPrincipals && !bRecovery)
                {
                    oItem.Cipher.ProtectedKey = PrincipalProtection.Protect(oKeys, sProtectionDescriptor);
                    oItem.Cipher.Signature = ComputeSignature(oItem, oAuthenticationKey);
                    return;
                }
                if (bRecovery)
                {
                    // Wrap the same keys independently for normal access and emergency recovery.
                    oItem.Cipher.ProtectedKey = RecoveryProtection.WrapWindowsKeys(
                        oKeys, sProtectionDescriptor, sRecoveryDescriptor);
                    oItem.Cipher.Signature = ComputeSignature(oItem, oAuthenticationKey);
                }
                foreach (User oUser in oUsers)
                {
                    using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oUser.Certificate))
                    {
                        Instance oInstance = new Instance
                        {
                            UserId = oUser.UserId,
                            CipherParams = nFormat,
                            CipherKey = CertificateKeyProtection.Wrap(oCert, oKeys)
                        };
                        oInstance.Signature = ComputeSignature(oItem, oAuthenticationKey, oInstance);
                        oItem.Instances.Add(oInstance);
                    }
                }
                if (!bPrincipals && oItem.Instances.Count == 0)
                    throw new InvalidOperationException("Select at least one recipient certificate.");
            }
            finally
            {
                Array.Clear(oKeys, 0, oKeys.Length);
                Array.Clear(oEncryptionKey, 0, oEncryptionKey.Length);
                Array.Clear(oAuthenticationKey, 0, oAuthenticationKey.Length);
            }
        }

        internal static byte[] Decrypt(Item oItem, Instance oInstance = null, X509Certificate2 oCert = null)
        {
            Cipher oCipher = oItem.Cipher;
            int nMaxSize = oItem.ItemType is "text" or "richtext" or "totp"
                ? Utilities.MaxItemSize : Utilities.MaxCompressedItemSize;
            bool bPrincipals = oCipher?.CipherParams == PrincipalFormat;
            bool bRecovery = oCipher?.CipherParams == RecoveryFormat;
            bool bCertificate = oInstance != null && oCert != null;
            bool bGcm = oCipher?.ContentSuite == (long)ContentEncryptionSuite.Aes256Gcm;

            // Validate the stored suite and its lengths before opening any private or Windows-protected keys.
            if ((oInstance == null) != (oCert == null) ||
                oCipher == null || !HasSupportedContentSuite(oCipher) || oCipher.CipherVector == null ||
                oCipher.CipherVector.Length != (bGcm ? 12 : 16) || oCipher.CipherText == null ||
                (bGcm ? oCipher.CipherText.Length > nMaxSize || oCipher.AuthenticationTag?.Length != 16
                    : oCipher.CipherText.Length == 0 || oCipher.CipherText.Length % 16 != 0 ||
                        oCipher.CipherText.Length > nMaxSize + 16 || oCipher.AuthenticationTag != null) ||
                ((!bPrincipals && !bRecovery || bRecovery && bCertificate) &&
                (oInstance == null || oCert == null ||
                oCipher.CipherParams != oInstance.CipherParams ||
                (oCipher.CipherParams != 0 && oCipher.CipherParams != AuthenticatedFormat &&
                    oCipher.CipherParams != CertificateFormat && oCipher.CipherParams != RecoveryFormat))))
                throw new CryptographicException("The encrypted item is damaged or uses an unsupported format.");
            if (bPrincipals) PrincipalProtection.ParseDescriptor(oCipher.ProtectionDescriptor, out _, false);

            byte[] oKeys = null;
            byte[] oEncryptionKey = new byte[32];
            byte[] oAuthenticationKey = new byte[32];
            try
            {
                if (bRecovery) RecoveryProtection.ReadWindowsKeys(oCipher);
                if (bPrincipals) oKeys = PrincipalProtection.Unprotect(oCipher.ProtectedKey);
                else if (bRecovery && !bCertificate) oKeys = RecoveryProtection.UnwrapWindowsKeys(oCipher);
                else if (oCipher.CipherParams == CertificateFormat || bRecovery)
                    oKeys = CertificateKeyProtection.Unwrap(oCert, oInstance.CipherKey);
                else
                {
                    using (RSA oRsa = oCert.GetRSAPrivateKey())
                    {
                        if (oRsa == null) throw new CryptographicException("The RSA private key is unavailable.");
                        oKeys = oRsa.Decrypt(oInstance.CipherKey, oCipher.CipherParams == AuthenticatedFormat
                            ? RSAEncryptionPadding.OaepSHA1 : RSAEncryptionPadding.Pkcs1);
                    }
                }

                bool bAuthenticated = oCipher.CipherParams != 0;
                byte[] oSignature = bPrincipals || bRecovery && !bCertificate
                    ? oCipher.Signature : oInstance.Signature;
                if (oKeys.Length != (bAuthenticated ? 64 : 32) || oSignature == null ||
                    oSignature.Length != (bAuthenticated ? 32 : 0))
                    throw new CryptographicException("The encrypted item is damaged.");

                Buffer.BlockCopy(oKeys, 0, oEncryptionKey, 0, 32);
                if (bAuthenticated)
                {
                    Buffer.BlockCopy(oKeys, 32, oAuthenticationKey, 0, 32);
                    byte[] oExpected = ComputeSignature(oItem, oAuthenticationKey,
                        bRecovery && !bCertificate ? null : oInstance);
                    int nDifference = 0;
                    for (int nIndex = 0; nIndex < oExpected.Length; nIndex++)
                        nDifference |= oExpected[nIndex] ^ oSignature[nIndex];
                    if (nDifference != 0)
                        throw new CryptographicException(
                            "The item failed its integrity check. It may have been altered.");
                }

                // Release plaintext only after authenticating the metadata, recipient envelope, and content.
                if (bGcm)
                {
                    byte[] oPlainText = new byte[oCipher.CipherText.Length];
                    using (AesGcm oAes = new AesGcm(oEncryptionKey, 16))
                        oAes.Decrypt(oCipher.CipherVector, oCipher.CipherText, oCipher.AuthenticationTag,
                            oPlainText, GetAssociatedData(oItem));
                    return oPlainText;
                }
                using (Aes oAes = new AesCng())
                {
                    oAes.Key = oEncryptionKey;
                    oAes.Mode = CipherMode.CBC;
                    oAes.Padding = PaddingMode.PKCS7;
                    oAes.IV = oCipher.CipherVector;
                    using (ICryptoTransform oDecryptor = oAes.CreateDecryptor())
                    {
                        byte[] oPlainText = oDecryptor.TransformFinalBlock(
                            oCipher.CipherText, 0, oCipher.CipherText.Length);
                        if (oPlainText.Length <= nMaxSize) return oPlainText;
                        Array.Clear(oPlainText, 0, oPlainText.Length);
                        throw new CryptographicException("The decrypted item exceeds the size limit.");
                    }
                }
            }
            finally
            {
                if (oKeys != null) Array.Clear(oKeys, 0, oKeys.Length);
                Array.Clear(oEncryptionKey, 0, oEncryptionKey.Length);
                Array.Clear(oAuthenticationKey, 0, oAuthenticationKey.Length);
            }
        }

        private static byte[] GetAssociatedData(Item oItem)
        {
            // Domain-separated, length-prefixed metadata binds the content to its suite and protection format.
            using (MemoryStream oStream = new MemoryStream())
            using (BinaryWriter oWriter = new BinaryWriter(oStream, Encoding.UTF8, true))
            {
                oWriter.Write("Crypture Content");
                oWriter.Write(oItem.Cipher.CipherParams);
                oWriter.Write(oItem.Cipher.ContentSuite.Value);
                oWriter.Write(oItem.Label);
                oWriter.Write(oItem.ItemType);
                oWriter.Flush();
                return oStream.ToArray();
            }
        }

        private static byte[] ComputeSignature(Item oItem, byte[] oKey, Instance oInstance = null)
        {
            using (HMACSHA256 oHmac = new HMACSHA256(oKey))
            using (CryptoStream oStream = new CryptoStream(Stream.Null, oHmac, CryptoStreamMode.Write))
            using (BinaryWriter oWriter = new BinaryWriter(oStream, Encoding.UTF8, true))
            {
                // Length-prefixed metadata and ciphertext prevent ambiguous authenticated messages.
                if (oItem.Cipher.ContentSuite != null) oWriter.Write(GetAssociatedData(oItem));
                else
                {
                    oWriter.Write("Crypture");
                    oWriter.Write(oItem.Cipher.CipherParams);
                    oWriter.Write(oItem.Label);
                    oWriter.Write(oItem.ItemType);
                }
                oWriter.Write(oItem.Cipher.CipherVector);
                if (oItem.Cipher.ContentSuite == (long)ContentEncryptionSuite.Aes256Gcm)
                    oWriter.Write(oItem.Cipher.AuthenticationTag);
                if (oItem.Cipher.CipherParams == PrincipalFormat)
                {
                    oWriter.Write(oItem.Cipher.ProtectionDescriptor);
                    oWriter.Write(oItem.Cipher.ProtectedKey.Length);
                    oWriter.Write(oItem.Cipher.ProtectedKey);
                }
                if (oItem.Cipher.CipherParams == RecoveryFormat)
                {
                    oWriter.Write(oItem.Cipher.ProtectionDescriptor ?? "");
                    oWriter.Write(oItem.Cipher.ProtectedKey.Length);
                    oWriter.Write(oItem.Cipher.ProtectedKey);
                    oWriter.Write(oInstance != null);
                }
                if (oItem.Cipher.CipherParams == CertificateFormat ||
                    oItem.Cipher.CipherParams == RecoveryFormat && oInstance != null)
                {
                    oWriter.Write(oInstance.UserId);
                    oWriter.Write(oInstance.CipherKey.Length);
                    oWriter.Write(oInstance.CipherKey);
                }
                oWriter.Write(oItem.Cipher.CipherText.Length);
                oWriter.Write(oItem.Cipher.CipherText);
                oWriter.Flush();
                oStream.FlushFinalBlock();
                return oHmac.Hash;
            }
        }
    }
}
