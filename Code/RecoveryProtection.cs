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
    internal sealed class RecoveryPolicy
    {
        internal string Descriptor { get; private set; }
        internal byte[] Certificate { get; private set; }
        internal bool IsEnabled => Descriptor != null || Certificate != null;

        internal static RecoveryPolicy Read(string sPath = null)
        {
            sPath = sPath ?? Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
            try
            {
                Configuration oConfig = ConfigurationManager.OpenMappedExeConfiguration(
                    new ExeConfigurationFileMap { ExeConfigFilename = sPath }, ConfigurationUserLevel.None);
                KeyValueConfigurationCollection oSettings = oConfig.AppSettings.Settings;
                string sDescriptor = oSettings["RecoveryProtectionDescriptor"]?.Value.Trim();
                string sCertificate = oSettings["RecoveryCertificateBase64"]?.Value.Trim();
                RecoveryPolicy oPolicy = new RecoveryPolicy
                {
                    Descriptor = String.IsNullOrEmpty(sDescriptor) ? null : sDescriptor
                };

                // Reject invalid configured recipients before allowing a save without recovery.
                if (oPolicy.Descriptor != null) PrincipalProtection.ValidateCustomDescriptor(oPolicy.Descriptor);
                if (String.IsNullOrEmpty(sCertificate)) return oPolicy;
                if (sCertificate.Length > PrincipalProtection.MaxProtectedKeyLength)
                    throw new CryptographicException("The recovery certificate is too large.");
                byte[] oData = Convert.FromBase64String(sCertificate);
                if (X509Certificate2.GetCertContentType(oData) != X509ContentType.Cert)
                    throw new CryptographicException("Use a Base64 X.509 public certificate, without a private key.");
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oData))
                {
                    CertificateKeyProtection.ValidateForEncryption(oCert);
                    oPolicy.Certificate = oCert.RawData;
                }
                return oPolicy;
            }
            catch (Exception oError) when (oError is ConfigurationErrorsException || oError is FormatException ||
                oError is CryptographicException || oError is PlatformNotSupportedException)
            {
                throw new InvalidOperationException("The emergency recovery settings in " + sPath +
                    " are invalid. Correct RecoveryProtectionDescriptor or RecoveryCertificateBase64 before saving. " +
                    oError.Message);
            }
        }
    }

    internal static class RecoveryProtection
    {
        private const int EnvelopeVersion = 1;
        private const int MaxEnvelopeLength = PrincipalProtection.MaxProtectedKeyLength * 2 +
            PrincipalProtection.MaxDescriptorLength * 8 + 32;
        private static readonly UTF8Encoding DescriptorEncoding = new UTF8Encoding(false, true);

        internal static byte[] WrapWindowsKeys(byte[] oKeys, string sPrimaryDescriptor, string sRecoveryDescriptor)
        {
            using (MemoryStream oStream = new MemoryStream())
            using (BinaryWriter oWriter = new BinaryWriter(oStream, DescriptorEncoding))
            {
                string[] oDescriptors = new[] { sPrimaryDescriptor, sRecoveryDescriptor }
                    .Where(s => s != null).Distinct(StringComparer.Ordinal).ToArray();
                oWriter.Write(EnvelopeVersion);
                oWriter.Write(oDescriptors.Length);
                foreach (string sDescriptor in oDescriptors)
                {
                    byte[] oDescriptor = DescriptorEncoding.GetBytes(sDescriptor);
                    byte[] oWrapped = PrincipalProtection.Protect(oKeys, sDescriptor,
                        sDescriptor != sPrimaryDescriptor);
                    oWriter.Write(oDescriptor.Length);
                    oWriter.Write(oDescriptor);
                    oWriter.Write(oWrapped.Length);
                    oWriter.Write(oWrapped);
                }
                return oStream.ToArray();
            }
        }

        internal static List<KeyValuePair<string, byte[]>> ReadWindowsKeys(Cipher oCipher)
        {
            try
            {
                byte[] oData = oCipher.ProtectedKey;
                if (oData == null || oData.Length < 8 || oData.Length > MaxEnvelopeLength)
                    throw new CryptographicException("The recovery key envelope is missing or invalid.");
                using (MemoryStream oStream = new MemoryStream(oData, false))
                using (BinaryReader oReader = new BinaryReader(oStream, DescriptorEncoding))
                {
                    if (oReader.ReadInt32() != EnvelopeVersion)
                        throw new CryptographicException("The recovery key envelope version is unsupported.");
                    int nCount = oReader.ReadInt32();
                    if (nCount < 1 || nCount > 2)
                        throw new CryptographicException("The recovery key envelope has invalid recipients.");
                    List<KeyValuePair<string, byte[]>> oEntries = new List<KeyValuePair<string, byte[]>>();
                    for (int nIndex = 0; nIndex < nCount; nIndex++)
                    {
                        int nLength = oReader.ReadInt32();
                        if (nLength < 1 || nLength > PrincipalProtection.MaxDescriptorLength * 4 ||
                            nLength > oStream.Length - oStream.Position)
                            throw new CryptographicException("The recovery protection descriptor is damaged.");
                        string sDescriptor = DescriptorEncoding.GetString(oReader.ReadBytes(nLength));
                        if (sDescriptor.Length > PrincipalProtection.MaxDescriptorLength || sDescriptor.Contains("\0"))
                            throw new CryptographicException("The recovery protection descriptor is damaged.");
                        nLength = oReader.ReadInt32();
                        if (nLength < 1 || nLength > PrincipalProtection.MaxProtectedKeyLength ||
                            nLength > oStream.Length - oStream.Position)
                            throw new CryptographicException("The recovery protected key is damaged.");
                        oEntries.Add(new KeyValuePair<string, byte[]>(sDescriptor, oReader.ReadBytes(nLength)));
                    }
                    if (oStream.Position != oStream.Length || oCipher.ProtectionDescriptor != null &&
                        oEntries[0].Key != oCipher.ProtectionDescriptor)
                        throw new CryptographicException("The recovery key envelope has inconsistent metadata.");
                    return oEntries;
                }
            }
            catch (Exception oError) when (oError is EndOfStreamException || oError is DecoderFallbackException)
            {
                throw new CryptographicException("The recovery key envelope is damaged.", oError);
            }
        }

        internal static byte[] UnwrapWindowsKeys(Cipher oCipher)
        {
            CryptographicException oLastError = null;
            foreach (var oEntry in ReadWindowsKeys(oCipher))
            {
                try
                {
                    return PrincipalProtection.Unprotect(oEntry.Value);
                }
                catch (CryptographicException oError)
                {
                    oLastError = oError;
                }
            }
            throw new CryptographicException("Neither the original Windows scope nor the emergency recovery " +
                "policy granted access to this item.", oLastError);
        }
    }
}
