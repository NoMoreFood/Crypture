using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Crypture
{
    internal class CertificateOperations
    {
        internal static bool CheckCertificateStatus(X509Certificate2 oCert)
        {
            using (X509Chain oChain = new X509Chain())
            {
                oChain.ChainPolicy.RevocationMode = (Properties.Settings.Default.PerformCertificateRevocationCheck) ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
                oChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

                // build the chain based on the specified policy
                oChain.Build(oCert);

                // check for self signed
                if (Properties.Settings.Default.AllowSelfSignedCertificates && oChain.ChainElements.Count == 1)
                {
                    return true;
                }

                // check for a valid certificate
                foreach (X509ChainStatus oStatus in oChain.ChainStatus)
                {
                    if (oStatus.Status != X509ChainStatusFlags.NoError) return false;
                }
            }

            // all checks successful -- looks good
            return true;
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
}
