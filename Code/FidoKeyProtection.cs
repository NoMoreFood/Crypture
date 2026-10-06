using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Crypture
{
    internal sealed class FidoKeyAccess : IDisposable
    {
        internal byte[] CredentialId { get; }
        internal byte[] Salt { get; }
        internal byte[] Secret { get; }
        internal bool IsDisposed { get; private set; }

        internal FidoKeyAccess(byte[] oCredentialId, byte[] oSalt, byte[] oSecret)
        {
            if (oCredentialId == null || oCredentialId.Length is < 1 or > FidoKeyProtection.MaxCredentialIdBytes ||
                oSalt?.Length != FidoKeyProtection.SaltBytes || oSecret?.Length != FidoKeyProtection.SecretBytes)
                throw new CryptographicException("The FIDO2 key returned invalid encryption data.");
            CredentialId = oCredentialId.ToArray();
            Salt = oSalt.ToArray();
            Secret = oSecret;
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Secret);
            IsDisposed = true;
        }
    }

    internal sealed class FidoKeyEnvelope
    {
        internal byte[] CredentialId { get; init; }
        internal byte[] Salt { get; init; }
        internal byte[] Nonce { get; init; }
        internal byte[] WrappedKey { get; init; }
        internal byte[] Tag { get; init; }
        internal byte[] RecoveryKey { get; init; }
    }

    internal static class FidoKeyProtection
    {
        // Bound credential identifiers and recovery data before processing a saved envelope.
        internal const int MaxCredentialIdBytes = 1024;
        internal const int SaltBytes = 32;
        internal const int SecretBytes = 32;
        private const int EnvelopeVersion = 1;
        private const int NonceBytes = 12;
        private const int TagBytes = 16;
        private const int MaxRecoveryBytes = RecoveryProtection.MaxEnvelopeLength;
        private const int MaxEnvelopeBytes = MaxRecoveryBytes + MaxCredentialIdBytes + 256;
        private static readonly byte[] KeyLabel = Encoding.UTF8.GetBytes("Crypture FIDO2 Key Wrap");

        internal static bool IsEnabled(IVaultStorage oStorage) =>
            Properties.Settings.Default.EnableFidoProtection && !oStorage.IsSqlServer && FidoNative.IsAvailable;

        internal static byte[] Wrap(byte[] oKeys, FidoKeyAccess oAccess, byte[] oRecoveryKey)
        {
            if (oKeys?.Length != ItemCryptography.ContentKeyBytes || oAccess == null || oAccess.IsDisposed)
                throw new CryptographicException("The FIDO2 encryption key is unavailable.");
            byte[] oWrappingKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, oAccess.Secret,
                ItemCryptography.AesKeyBytes, oAccess.Salt, KeyLabel);
            try
            {
                // Bind the credential and salt to the authenticated content-key envelope.
                using MemoryStream oStream = new MemoryStream();
                using BinaryWriter oWriter = new BinaryWriter(oStream);
                oWriter.Write(EnvelopeVersion);
                oWriter.Write(oAccess.CredentialId.Length);
                oWriter.Write(oAccess.CredentialId);
                oWriter.Write(oAccess.Salt);
                oWriter.Flush();
                byte[] oAssociatedData = oStream.ToArray();
                byte[] oNonce = RandomNumberGenerator.GetBytes(NonceBytes);
                byte[] oWrapped = new byte[ItemCryptography.ContentKeyBytes];
                byte[] oTag = new byte[TagBytes];
                using (AesGcm oAes = new AesGcm(oWrappingKey, TagBytes))
                    oAes.Encrypt(oNonce, oKeys, oWrapped, oTag, oAssociatedData);
                oWriter.Write(oNonce);
                oWriter.Write(oWrapped);
                oWriter.Write(oTag);
                oWriter.Write(oRecoveryKey?.Length ?? 0);
                if (oRecoveryKey != null) oWriter.Write(oRecoveryKey);
                return oStream.ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oWrappingKey);
            }
        }

        internal static FidoKeyEnvelope Read(Cipher oCipher)
        {
            try
            {
                byte[] oData = oCipher?.ProtectedKey;
                if (oCipher?.CipherParams != ItemCryptography.FidoFormat || oCipher.ProtectionDescriptor != null ||
                    oData == null || oData.Length > MaxEnvelopeBytes)
                    throw new CryptographicException("The FIDO2 key envelope is missing or invalid.");
                using MemoryStream oStream = new MemoryStream(oData, false);
                using BinaryReader oReader = new BinaryReader(oStream);
                if (oReader.ReadInt32() != EnvelopeVersion)
                    throw new CryptographicException("The FIDO2 key envelope version is unsupported.");
                int nLength = oReader.ReadInt32();
                if (nLength is < 1 or > MaxCredentialIdBytes ||
                    oStream.Length - oStream.Position < nLength + SaltBytes + NonceBytes +
                        ItemCryptography.ContentKeyBytes + TagBytes + sizeof(int))
                    throw new CryptographicException("The FIDO2 key envelope is damaged.");
                FidoKeyEnvelope oEnvelope = new FidoKeyEnvelope
                {
                    CredentialId = oReader.ReadBytes(nLength),
                    Salt = oReader.ReadBytes(SaltBytes),
                    Nonce = oReader.ReadBytes(NonceBytes),
                    WrappedKey = oReader.ReadBytes(ItemCryptography.ContentKeyBytes),
                    Tag = oReader.ReadBytes(TagBytes),
                    RecoveryKey = ReadRecoveryKey(oReader)
                };
                if (oStream.Position != oStream.Length)
                    throw new CryptographicException("The FIDO2 key envelope has trailing data.");
                if (oEnvelope.RecoveryKey != null)
                    RecoveryProtection.ReadWindowsKeys(new Cipher { ProtectedKey = oEnvelope.RecoveryKey });
                return oEnvelope;
            }
            catch (EndOfStreamException oError)
            {
                throw new CryptographicException("The FIDO2 key envelope is damaged.", oError);
            }
        }

        private static byte[] ReadRecoveryKey(BinaryReader oReader)
        {
            int nLength = oReader.ReadInt32();
            if (nLength < 0 || nLength > MaxRecoveryBytes ||
                nLength != oReader.BaseStream.Length - oReader.BaseStream.Position)
                throw new CryptographicException("The FIDO2 recovery key envelope is damaged.");
            return nLength == 0 ? null : oReader.ReadBytes(nLength);
        }

        internal static byte[] Unwrap(Cipher oCipher, FidoKeyAccess oAccess)
        {
            FidoKeyEnvelope oEnvelope = Read(oCipher);
            if (oAccess == null)
            {
                if (oEnvelope.RecoveryKey == null)
                    throw new CryptographicException("Use the FIDO2 security key that protected this item.");
                return RecoveryProtection.UnwrapWindowsKeys(new Cipher { ProtectedKey = oEnvelope.RecoveryKey });
            }
            if (oAccess.IsDisposed || !oAccess.CredentialId.SequenceEqual(oEnvelope.CredentialId) ||
                !oAccess.Salt.SequenceEqual(oEnvelope.Salt))
                throw new CryptographicException("This FIDO2 credential does not match the saved item.");
            byte[] oWrappingKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, oAccess.Secret,
                ItemCryptography.AesKeyBytes, oEnvelope.Salt, KeyLabel);
            byte[] oKeys = new byte[ItemCryptography.ContentKeyBytes];
            try
            {
                int nAssociatedDataBytes = sizeof(int) * 2 + oEnvelope.CredentialId.Length + SaltBytes;
                using AesGcm oAes = new AesGcm(oWrappingKey, TagBytes);
                oAes.Decrypt(oEnvelope.Nonce, oEnvelope.WrappedKey, oEnvelope.Tag, oKeys,
                    oCipher.ProtectedKey.AsSpan(0, nAssociatedDataBytes));
                return oKeys;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(oKeys);
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oWrappingKey);
            }
        }
    }
}
