using System;
using System.Collections.Generic;
using System.Configuration;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Crypture
{
    internal class CertificateOperations
    {
        internal static string CurrentUserSid
        {
            get
            {
                using (WindowsIdentity oIdentity = WindowsIdentity.GetCurrent())
                    return oIdentity.User.Value;
            }
        }

        internal static bool CheckCertificateStatus(X509Certificate2 oCert, bool bForSelection = false)
        {
            try
            {
                CertificateKeyProtection.ValidateForEncryption(oCert);
            }
            catch (Exception oError) when (oError is CryptographicException || oError is PlatformNotSupportedException)
            {
                return false;
            }

            using (X509Chain oChain = new X509Chain())
            {
                const int ChainRetrievalTimeoutSeconds = 10;
                Properties.Settings oSettings = Properties.Settings.Default;
                oChain.ChainPolicy.TrustMode = X509ChainTrustMode.System;
                oChain.ChainPolicy.RevocationMode = oSettings.PerformCertificateRevocationCheck
                    ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
                oChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                oChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(ChainRetrievalTimeoutSeconds);

                // build the chain based on the specified policy
                if (oChain.Build(oCert)) return true;

                // Selection settings waive only expiry and missing trust anchors, never future validity.
                X509ChainStatusFlags oAllowed = X509ChainStatusFlags.NoError;
                if (bForSelection && oSettings.ShowExpiredCertificates &&
                    oChain.ChainElements.Cast<X509ChainElement>().All(e =>
                    e.Certificate.NotBefore <= oChain.ChainPolicy.VerificationTime))
                    oAllowed |= X509ChainStatusFlags.NotTimeValid;

                // check for self signed
                bool bSelfSigned = IsSelfSigned(oCert);
                if (bForSelection && oSettings.ShowUntrustedCertificates)
                {
                    if (oCert.SubjectName.RawData.SequenceEqual(oCert.IssuerName.RawData) && !bSelfSigned)
                        return false;
                    oAllowed |= X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain;
                }
                else if (oSettings.AllowSelfSignedCertificates && bSelfSigned && oChain.ChainElements.Count == 1)
                    oAllowed |= X509ChainStatusFlags.UntrustedRoot;
                return oAllowed != X509ChainStatusFlags.NoError && oChain.ChainStatus.All(s =>
                    (s.Status & ~oAllowed) == X509ChainStatusFlags.NoError);
            }
        }

        internal static bool CanSelectCertificate(byte[] oData, CertificateUsageFilter oUsageFilter)
        {
            if (oUsageFilter == null || oData == null || oData.Length == 0) return false;
            try
            {
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oData))
                    return oUsageFilter.Matches(oCert) && CheckCertificateStatus(oCert, true);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        internal static bool IsSelfSigned(X509Certificate2 oCert)
        {
            // Wincrypt signature verification encoding and certificate subject types.
            const uint X509AsnEncoding = 1;
            const uint CertificateSubjectType = 2;
            const uint CertificateIssuerType = 2;
            return oCert.SubjectName.RawData.SequenceEqual(oCert.IssuerName.RawData) &&
                NativeMethods.CryptVerifyCertificateSignatureEx(IntPtr.Zero, X509AsnEncoding,
                    CertificateSubjectType, oCert.Handle, CertificateIssuerType,
                    oCert.Handle, 0, IntPtr.Zero);
        }

        internal static X509Certificate2Collection GetPersonalCertificates()
        {
            // The caller owns the certificate contexts from both personal stores.
            X509Certificate2Collection oCertificates = new X509Certificate2Collection();
            try
            {
                foreach (StoreLocation oLocation in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
                {
                    using (X509Store oStore = new X509Store(StoreName.My, oLocation))
                    {
                        oStore.Open(OpenFlags.ReadOnly);
                        oCertificates.AddRange(oStore.Certificates);
                    }
                }
                return oCertificates;
            }
            catch
            {
                foreach (X509Certificate2 oCert in oCertificates) oCert.Dispose();
                throw;
            }
        }

        internal static HashSet<string> GetPrivateCertificateData()
        {
            X509Certificate2Collection oCertificates = GetPersonalCertificates();
            try
            {
                return oCertificates.Cast<X509Certificate2>().Where(c => c.HasPrivateKey)
                    .Select(c => Convert.ToBase64String(c.RawData)).ToHashSet();
            }
            finally
            {
                foreach (X509Certificate2 oCert in oCertificates) oCert.Dispose();
            }
        }

        internal static List<byte[]> GetAutomaticCertificates()
        {
            // return empty list if no property is set
            List<byte[]> oList = new List<byte[]>();
            if (Properties.Settings.Default.AutomaticallyAddedCertificatesList == null) return oList;

            // convert the strings to certificate strings to byte arrays
            foreach (string sCertText in Properties.Settings.Default.AutomaticallyAddedCertificatesList)
            {
                oList.Add(Convert.FromBase64String(sCertText));
            }

            return oList;
        }
    }

    internal sealed class CertificateUsageFilter
    {
        private readonly X509KeyUsageFlags oIncludedKeyUsages;
        private readonly X509KeyUsageFlags oExcludedKeyUsages;
        private readonly HashSet<string> oIncludedEnhancedUsages;
        private readonly HashSet<string> oExcludedEnhancedUsages;
        private readonly bool bAllowUnrestrictedKeyUsage;
        private readonly bool bAllowUnrestrictedEnhancedUsage;

        internal CertificateUsageFilter(string sKeyInclude, string sKeyExclude, string sEnhancedInclude,
            string sEnhancedExclude, bool bAllowKeyUsage = true, bool bAllowEnhancedUsage = true)
        {
            oIncludedKeyUsages = ParseKeyUsages(sKeyInclude, "CertificateKeyUsageInclude");
            oExcludedKeyUsages = ParseKeyUsages(sKeyExclude, "CertificateKeyUsageExclude");
            oIncludedEnhancedUsages = ParseEnhancedUsages(sEnhancedInclude, "CertificateEnhancedKeyUsageInclude");
            oExcludedEnhancedUsages = ParseEnhancedUsages(sEnhancedExclude, "CertificateEnhancedKeyUsageExclude");
            bAllowUnrestrictedKeyUsage = bAllowKeyUsage;
            bAllowUnrestrictedEnhancedUsage = bAllowEnhancedUsage;
        }

        internal static CertificateUsageFilter Read()
        {
            Properties.Settings oSettings = Properties.Settings.Default;
            return new CertificateUsageFilter(oSettings.CertificateKeyUsageInclude, oSettings.CertificateKeyUsageExclude,
                oSettings.CertificateEnhancedKeyUsageInclude, oSettings.CertificateEnhancedKeyUsageExclude,
                oSettings.AllowUnrestrictedCertificateKeyUsage, oSettings.AllowUnrestrictedCertificateEnhancedKeyUsage);
        }

        internal bool Matches(X509Certificate2 oCert)
        {
            // Each include list accepts any match; a declared excluded usage always takes precedence.
            X509KeyUsageExtension oKeyUsage = oCert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (oKeyUsage == null)
            {
                if (!bAllowUnrestrictedKeyUsage) return false;
            }
            else if ((oKeyUsage.KeyUsages & oExcludedKeyUsages) != 0 ||
                (oIncludedKeyUsages != X509KeyUsageFlags.None && (oKeyUsage.KeyUsages & oIncludedKeyUsages) == 0))
                return false;
            X509EnhancedKeyUsageExtension oEnhancedUsage = oCert.Extensions
                .OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            HashSet<string> oUsages = oEnhancedUsage == null ? new HashSet<string>() :
                oEnhancedUsage.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ToHashSet(StringComparer.Ordinal);
            if (oExcludedEnhancedUsages.Overlaps(oUsages)) return false;
            const string AnyExtendedKeyUsageOid = "2.5.29.37.0";
            bool bUnrestricted = oUsages.Count == 0 || oUsages.Contains(AnyExtendedKeyUsageOid);
            return bUnrestricted ? bAllowUnrestrictedEnhancedUsage :
                oIncludedEnhancedUsages.Count == 0 || oIncludedEnhancedUsages.Overlaps(oUsages);
        }

        internal bool Matches(byte[] oData)
        {
            if (oData == null || oData.Length == 0) return false;
            try
            {
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oData)) return Matches(oCert);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        internal static X509KeyUsageFlags ParseKeyUsages(string sValue, string sSetting)
        {
            X509KeyUsageFlags oResult = X509KeyUsageFlags.None;
            foreach (string sName in SplitList(sValue))
            {
                if (!Enum.GetNames<X509KeyUsageFlags>().Contains(sName, StringComparer.OrdinalIgnoreCase))
                    throw new ConfigurationErrorsException(sSetting + " in Crypture.exe.config contains an invalid " +
                        "Key Usage: '" + sName + "'. Use Key Usage names separated by commas or semicolons.");
                oResult |= Enum.Parse<X509KeyUsageFlags>(sName, true);
            }
            return oResult;
        }

        internal static HashSet<string> ParseEnhancedUsages(string sValue, string sSetting)
        {
            HashSet<string> oResult = new HashSet<string>(StringComparer.Ordinal);
            foreach (string sOid in SplitList(sValue))
            {
                try
                {
                    AsnWriter oWriter = new AsnWriter(AsnEncodingRules.DER);
                    oWriter.WriteObjectIdentifier(sOid);
                    oResult.Add(new AsnReader(oWriter.Encode(), AsnEncodingRules.DER).ReadObjectIdentifier());
                }
                catch (ArgumentException)
                {
                    throw new ConfigurationErrorsException(sSetting + " in Crypture.exe.config contains an invalid " +
                        "Enhanced Key Usage OID: '" + sOid + "'. Use OIDs separated by commas or semicolons.");
                }
            }
            return oResult;
        }

        private static string[] SplitList(string sValue) => (sValue ?? "").Split([',', ';'],
            StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    }

    public partial class User
    {
        public string Name
        {
            get
            {
                try
                {
                    using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(Certificate))
                        return oCert.GetNameInfo(X509NameType.SimpleName, false);
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    return "Invalid certificate";
                }
            }
        }

        public string AlgorithmDisplay
        {
            get
            {
                try
                {
                    using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(Certificate))
                        return CertificateKeyProtection.GetAlgorithmDisplay(oCert);
                }
                catch (CryptographicException)
                {
                    return "Unsupported";
                }
            }
        }

        public bool IsSelfSigned
        {
            get
            {
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(Certificate))
                {
                    return CertificateOperations.IsSelfSigned(oCert);
                }
            }
        }

        public bool IsOwnedByCurrentUser
        {
            get
            {
                return CertificateOperations.CurrentUserSid.Equals(Sid);
            }
        }

    }
}
