using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace Crypture
{
    internal sealed class SqlServerEscrowChoice
    {
        internal byte[] Certificate { get; }
        internal string Sid { get; }
        internal string Descriptor => Certificate == null ? "SID=" + Sid : null;
        internal string Label { get; }

        private SqlServerEscrowChoice(byte[] oCertificate, string sSid, string sLabel)
        {
            if (String.IsNullOrWhiteSpace(sLabel) || sLabel.Length > 450)
                throw new InvalidOperationException("Choose an escrow identity with a short display name.");
            Sid = new SecurityIdentifier(sSid).Value;
            Certificate = oCertificate;
            Label = sLabel;
        }

        internal static SqlServerEscrowChoice ForCertificate(byte[] oCertificate, string sSid, string sLabel)
        {
            using X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oCertificate);
            CertificateKeyProtection.ValidateForEncryption(oCert);
            return new SqlServerEscrowChoice(oCert.RawData, sSid, sLabel);
        }

        internal static SqlServerEscrowChoice ForPrincipal(string sSid, string sLabel) =>
            new SqlServerEscrowChoice(null, sSid, sLabel);
    }

    internal sealed record SqlServerEscrowPolicy(long? CertificateUserId, byte[] Certificate,
        string Descriptor, string Label);
}
