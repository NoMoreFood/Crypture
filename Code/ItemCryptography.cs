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

        internal static void Encrypt(Item oItem, byte[] oPlainText, IEnumerable<User> oRecipients,
            string sProtectionDescriptor = null)
        {
            if (oPlainText == null || oPlainText.Length > Utilities.MaxItemSize)
                throw new InvalidDataException("Items must be no larger than 64 MB.");

            bool bPrincipals = sProtectionDescriptor != null;
            if (bPrincipals) PrincipalProtection.ParseDescriptor(sProtectionDescriptor, out _, false);
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
                            CipherParams = bPrincipals ? PrincipalFormat : CertificateFormat,
                            ProtectionDescriptor = sProtectionDescriptor,
                            CipherVector = oAes.IV,
                            CipherText = oEncryptor.TransformFinalBlock(oPlainText, 0, oPlainText.Length)
                        };
                    }
                }

                oItem.Instances.Clear();
                if (bPrincipals)
                {
                    oItem.Cipher.ProtectedKey = PrincipalProtection.Protect(oKeys, sProtectionDescriptor);
                    oItem.Cipher.Signature = ComputeSignature(oItem, oAuthenticationKey);
                    return;
                }
                foreach (User oUser in oRecipients.GroupBy(u => u.UserId).Select(g => g.First()))
                {
                    using (X509Certificate2 oCert = new X509Certificate2(oUser.Certificate))
                    {
                        Instance oInstance = new Instance
                        {
                            UserId = oUser.UserId,
                            CipherParams = CertificateFormat,
                            CipherKey = CertificateKeyProtection.Wrap(oCert, oKeys)
                        };
                        oInstance.Signature = ComputeSignature(oItem, oAuthenticationKey, oInstance);
                        oItem.Instances.Add(oInstance);
                    }
                }
                if (oItem.Instances.Count == 0)
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
            bool bPrincipals = oCipher?.CipherParams == PrincipalFormat;
            if (oCipher == null || oCipher.CipherVector == null || oCipher.CipherVector.Length != 16 ||
                oCipher.CipherText == null || oCipher.CipherText.Length == 0 ||
                oCipher.CipherText.Length % 16 != 0 || oCipher.CipherText.Length > Utilities.MaxItemSize + 16 ||
                (!bPrincipals && (oInstance == null || oCert == null ||
                oCipher.CipherParams != oInstance.CipherParams ||
                (oCipher.CipherParams != 0 && oCipher.CipherParams != AuthenticatedFormat &&
                    oCipher.CipherParams != CertificateFormat))))
                throw new CryptographicException("The encrypted item is damaged or uses an unsupported format.");
            if (bPrincipals) PrincipalProtection.ParseDescriptor(oCipher.ProtectionDescriptor, out _, false);

            byte[] oKeys = null;
            byte[] oEncryptionKey = new byte[32];
            byte[] oAuthenticationKey = new byte[32];
            try
            {
                if (bPrincipals) oKeys = PrincipalProtection.Unprotect(oCipher.ProtectedKey);
                else if (oCipher.CipherParams == CertificateFormat)
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
                byte[] oSignature = bPrincipals ? oCipher.Signature : oInstance.Signature;
                if (oKeys.Length != (bAuthenticated ? 64 : 32) || oSignature == null ||
                    oSignature.Length != (bAuthenticated ? 32 : 0))
                    throw new CryptographicException("The encrypted item is damaged.");

                Buffer.BlockCopy(oKeys, 0, oEncryptionKey, 0, 32);
                if (bAuthenticated)
                {
                    Buffer.BlockCopy(oKeys, 32, oAuthenticationKey, 0, 32);
                    byte[] oExpected = ComputeSignature(oItem, oAuthenticationKey, oInstance);
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
                        return oDecryptor.TransformFinalBlock(oCipher.CipherText, 0, oCipher.CipherText.Length);
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
                if (oItem.Cipher.CipherParams == CertificateFormat)
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
