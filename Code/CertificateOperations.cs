using System;
using System.Collections.Generic;
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

        internal static bool CheckCertificateStatus(X509Certificate2 oCert)
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
                oChain.ChainPolicy.RevocationMode = Properties.Settings.Default.PerformCertificateRevocationCheck
                    ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
                oChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                oChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

                // build the chain based on the specified policy
                if (oChain.Build(oCert)) return true;

                // check for self signed
                return Properties.Settings.Default.AllowSelfSignedCertificates && IsSelfSigned(oCert) &&
                    oChain.ChainElements.Count == 1 && oChain.ChainStatus.All(s =>
                    (s.Status & ~X509ChainStatusFlags.UntrustedRoot) == X509ChainStatusFlags.NoError);
            }
        }

        internal static bool IsSelfSigned(X509Certificate2 oCert)
        {
            return oCert.SubjectName.RawData.SequenceEqual(oCert.IssuerName.RawData) &&
                NativeMethods.CryptVerifyCertificateSignatureEx(IntPtr.Zero, 1, 2, oCert.Handle, 2,
                    oCert.Handle, 0, IntPtr.Zero);
        }

        internal static HashSet<string> GetPrivateCertificateData()
        {
            HashSet<string> oResult = new HashSet<string>();
            using (X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                oStore.Open(OpenFlags.ReadOnly);
                foreach (X509Certificate2 oCert in oStore.Certificates)
                {
                    using (oCert)
                    {
                        if (oCert.HasPrivateKey) oResult.Add(Convert.ToBase64String(oCert.RawData));
                    }
                }
            }
            return oResult;
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
