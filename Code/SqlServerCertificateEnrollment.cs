using System;
using System.Data;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Microsoft.Data.SqlClient;

namespace Crypture
{
    internal static class SqlServerCertificateEnrollment
    {
        internal static void EnrollOwn(SqlServerVaultStorage oStorage, X509Certificate2 oCertificate,
            long? nUnboundUserId = null)
        {
            // Prove the current Windows account can use the matching private key before binding its SID.
            byte[] oChallenge = RandomNumberGenerator.GetBytes(32);
            X509Certificate2Collection oPersonal = CertificateOperations.GetPersonalCertificates();
            try
            {
                X509Certificate2 oPrivate = oPersonal.Cast<X509Certificate2>().FirstOrDefault(c =>
                    c.HasPrivateKey && c.RawData.AsSpan().SequenceEqual(oCertificate.RawData));
                if (oPrivate == null)
                    throw new InvalidOperationException("Import the matching private key into your personal " +
                        "certificate store before enrolling this certificate in SQL Server.");
                byte[] oWrapped = CertificateKeyProtection.Wrap(oCertificate, oChallenge);
                byte[] oUnwrapped = CertificateKeyProtection.Unwrap(oPrivate, oWrapped);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(oChallenge, oUnwrapped))
                        throw new CryptographicException("The certificate private key did not match.");
                }
                finally { CryptographicOperations.ZeroMemory(oUnwrapped); }
                Enroll(oStorage, oCertificate.RawData, CertificateOperations.CurrentUserSid, nUnboundUserId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oChallenge);
                foreach (X509Certificate2 oCert in oPersonal) oCert.Dispose();
            }
        }

        internal static void EnrollFromDirectory(SqlServerVaultStorage oStorage, X509Certificate2 oCertificate,
            string sSid, long? nUnboundUserId = null)
        {
            VerifyDirectoryBinding(oCertificate.RawData, sSid);
            Enroll(oStorage, oCertificate.RawData, sSid, nUnboundUserId);
        }

        internal static void MarkEscrow(SqlServerVaultStorage oStorage, User oUser)
        {
            // Escrow must remain published on the same AD identity before the owner designates it.
            VerifyDirectoryBinding(oUser.Certificate, oUser.Sid);
            using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand("[dbo].[MarkEscrowCertificate]", oConnection)
            {
                CommandType = CommandType.StoredProcedure
            };
            oCommand.Parameters.Add("@userId", SqlDbType.BigInt).Value = oUser.UserId;
            oCommand.Parameters.Add("@label", SqlDbType.NVarChar, 450).Value =
                "Certificate: " + oUser.Name + " (" + oUser.Sid + ")";
            oCommand.ExecuteNonQuery();
            oStorage.RefreshEscrow();
        }

        internal static void VerifyDirectoryBinding(byte[] oCertificate, string sSid)
        {
            if (String.IsNullOrWhiteSpace(sSid))
                throw new InvalidOperationException("Choose an Active Directory user with a Windows SID.");
            VerifyDirectoryBinding(oCertificate, sSid,
                ForestDirectory.Search(sSid, true, CancellationToken.None, true));
        }

        internal static void VerifyDirectoryBinding(byte[] oCertificate, string sSid,
            DirectorySearchResult oResult)
        {
            if (oResult.Truncated || oResult.Accounts.Count != 1 || oResult.Accounts[0].Sid != sSid ||
                !oResult.Accounts[0].Certificates.Any(c => c.AsSpan().SequenceEqual(oCertificate)))
                throw new InvalidOperationException("This certificate is not published on the selected " +
                    "Active Directory user. Publish it there before enrolling or designating escrow.");
            using X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oCertificate);
            string sCertificateUpn = oCert.GetNameInfo(X509NameType.UpnName, false);
            if (String.IsNullOrWhiteSpace(sCertificateUpn) ||
                !sCertificateUpn.Equals(oResult.Accounts[0].Account, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The certificate UPN must match the selected " +
                    "Active Directory user's UPN.");
            if (!CertificateOperations.CheckCertificateStatus(oCert))
                throw new InvalidOperationException("The Active Directory certificate is not valid for encryption.");
        }

        private static void Enroll(SqlServerVaultStorage oStorage, byte[] oCertificate, string sSid,
            long? nUnboundUserId)
        {
            using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand(nUnboundUserId.HasValue
                ? "[dbo].[VerifyUnboundCertificate]" : "[dbo].[EnrollCertificate]", oConnection)
            {
                CommandType = CommandType.StoredProcedure
            };
            oCommand.Parameters.Add("@certificate", SqlDbType.VarBinary, -1).Value = oCertificate;
            oCommand.Parameters.Add("@sid", SqlDbType.NVarChar, 450).Value = sSid;
            SqlParameter oUserId = oCommand.Parameters.Add("@userId", SqlDbType.BigInt);
            oUserId.Direction = nUnboundUserId.HasValue ? ParameterDirection.Input : ParameterDirection.Output;
            if (nUnboundUserId.HasValue) oUserId.Value = nUnboundUserId.Value;
            oCommand.ExecuteNonQuery();
        }
    }
}
