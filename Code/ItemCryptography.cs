using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Crypture
{
    internal static class ItemCryptography
    {
        internal const long AuthenticatedFormat = 1;
        internal const long PrincipalFormat = 2;
        internal const long CertificateFormat = 3;
        internal const long RecoveryFormat = 4;

        internal static bool UsesWindowsProtection(Cipher oCipher) => oCipher?.CipherParams == PrincipalFormat ||
            oCipher?.CipherParams == RecoveryFormat && oCipher.ProtectionDescriptor != null;

        internal static void Encrypt(Item oItem, byte[] oPlainText, IEnumerable<User> oRecipients,
            string sProtectionDescriptor = null, string sRecoveryDescriptor = null)
        {
            int nMaxSize = oItem.ItemType is "text" or "totp"
                ? Utilities.MaxItemSize : Utilities.MaxCompressedItemSize;
            if (oPlainText == null || oPlainText.Length > nMaxSize)
                throw new InvalidDataException("Items must be no larger than 64 MB.");

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
                using (Aes oAes = new AesCng())
                {
                    oAes.Key = oEncryptionKey;
                    oAes.GenerateIV();
                    using (ICryptoTransform oEncryptor = oAes.CreateEncryptor())
                    {
                        oItem.Cipher = new Cipher
                        {
                            CipherParams = nFormat,
                            ProtectionDescriptor = sProtectionDescriptor,
                            CipherVector = oAes.IV,
                            CipherText = oEncryptor.TransformFinalBlock(oPlainText, 0, oPlainText.Length)
                        };
                    }
                }

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
            int nMaxSize = oItem.ItemType is "text" or "totp"
                ? Utilities.MaxItemSize : Utilities.MaxCompressedItemSize;
            bool bPrincipals = oCipher?.CipherParams == PrincipalFormat;
            bool bRecovery = oCipher?.CipherParams == RecoveryFormat;
            bool bCertificate = oInstance != null && oCert != null;
            if ((oInstance == null) != (oCert == null) ||
                oCipher == null || oCipher.CipherVector == null || oCipher.CipherVector.Length != 16 ||
                oCipher.CipherText == null || oCipher.CipherText.Length == 0 ||
                oCipher.CipherText.Length % 16 != 0 || oCipher.CipherText.Length > nMaxSize + 16 ||
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

                using (Aes oAes = new AesCng())
                {
                    oAes.Key = oEncryptionKey;
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

        private static byte[] ComputeSignature(Item oItem, byte[] oKey, Instance oInstance = null)
        {
            using (HMACSHA256 oHmac = new HMACSHA256(oKey))
            using (CryptoStream oStream = new CryptoStream(Stream.Null, oHmac, CryptoStreamMode.Write))
            using (BinaryWriter oWriter = new BinaryWriter(oStream, Encoding.UTF8, true))
            {
                // Length-prefixed metadata and ciphertext prevent ambiguous authenticated messages.
                oWriter.Write("Crypture");
                oWriter.Write(oItem.Cipher.CipherParams);
                oWriter.Write(oItem.Label);
                oWriter.Write(oItem.ItemType);
                oWriter.Write(oItem.Cipher.CipherVector);
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
