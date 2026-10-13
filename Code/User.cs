using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Crypture
{
    public class User
    {
        private byte[] oDescribedCertificate;
        private string sName;
        private string sAlgorithmDisplay;

        public long UserId { get; set; }
        public byte[] Certificate { get; set; }
        public string Sid { get; set; }
        public bool IsEscrow { get; set; }

        public virtual ICollection<Instance> Instances { get; set; } = new HashSet<Instance>();
        public virtual ICollection<Item> Items { get; set; } = new HashSet<Item>();

        public string Name
        {
            get
            {
                DescribeCertificate();
                return sName;
            }
        }

        public string AlgorithmDisplay
        {
            get
            {
                DescribeCertificate();
                return sAlgorithmDisplay;
            }
        }

        public string AffiliationDisplay => Sid == null ? "Needs verification" :
            IsEscrow ? "Escrow" : "Verified";

        private void DescribeCertificate()
        {
            // Lists sort, filter, and bind these values repeatedly, so parse each certificate once.
            if (oDescribedCertificate == Certificate && sName != null) return;
            oDescribedCertificate = Certificate;
            try
            {
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(Certificate))
                {
                    sName = oCert.GetNameInfo(X509NameType.SimpleName, false);
                    sAlgorithmDisplay = CertificateKeyProtection.GetAlgorithmDisplay(oCert);
                }
            }
            catch (CryptographicException)
            {
                sName = "Invalid certificate";
                sAlgorithmDisplay = "Unsupported";
            }
        }
    }
}
