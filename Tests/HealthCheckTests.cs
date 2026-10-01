using System;
using Microsoft.Data.Sqlite;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestHealthChecks(string sDirectory, RSA oKey, X509Certificate2 oCert)
    {
        DateTime oNow = DateTime.UtcNow;
        Item[] oItems = { new Item { ItemId = 1, Label = "Example Item" } };
        HealthCheckFinding oPrincipal = VaultHealthCheck.CheckPrincipal(CertificateOperations.CurrentUserSid, oItems);
        Check(oPrincipal.Severity == HealthStatus.Passed && oPrincipal.Recipient != oPrincipal.Identifier,
            "Health check locates the current Windows account");
        oPrincipal = VaultHealthCheck.CheckPrincipal("S-1-1-0", oItems);
        Check(oPrincipal.Severity == HealthStatus.Passed, "Health check locates well-known Windows groups");
        oPrincipal = VaultHealthCheck.CheckPrincipal("S-1-5-21-4294967000-4294967001-4294967002-999999", oItems);
        Check(oPrincipal.Severity == HealthStatus.Warning && oPrincipal.Details.Contains("unreachable"),
            "Unresolved SID is unverified rather than reported as definitively deleted");
        Check(VaultHealthCheck.CheckPrincipal("invalid SID", oItems).Severity == HealthStatus.Error,
            "Malformed principal identifiers are health errors");
        Check(VaultHealthCheck.CheckCertificate(new User { UserId = 1, Certificate = new byte[] { 1, 2, 3 } },
            oItems, true, false, oNow).Severity == HealthStatus.Error,
            "Malformed certificate data is reported without stopping the check");
        Check(VaultHealthCheck.CheckCertificate(new User { UserId = 1 }, oItems, true, false, oNow)
            .Severity == HealthStatus.Error, "Missing certificate data is a health error");

        using (X509Certificate2 oValid = Certificate(oKey, "Health Valid", DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(120)))
        using (X509Certificate2 oExpired = Certificate(oKey, "Health Expired", DateTimeOffset.UtcNow.AddDays(-5),
            DateTimeOffset.UtcNow.AddDays(-1)))
        using (X509Certificate2 oFuture = Certificate(oKey, "Health Future", DateTimeOffset.UtcNow.AddDays(2),
            DateTimeOffset.UtcNow.AddDays(120)))
        using (X509Certificate2 oSoon = Certificate(oKey, "Health Expiring Soon", DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(20)))
        using (X509Certificate2 oSigning = Certificate(oKey, "Health Signing Only", DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(120), X509KeyUsageFlags.DigitalSignature))
        {
            HealthCheckFinding oResult = VaultHealthCheck.CheckCertificate(
                new User { UserId = 1, Certificate = oValid.RawData }, oItems, true, false, oNow);
            Check(oResult.Severity == HealthStatus.Warning && oResult.Details.Contains("Revocation was not checked") &&
                oResult.Details.Contains("self-signed") && !oResult.Details.Contains("chain validation failed"),
                "Allowed self-signed certificates retain an explicit skipped-revocation warning");
            Check(oResult.Identifier.Contains(oValid.Thumbprint) && oResult.AffectedItems.Contains("Example Item (#1)"),
                "Certificate health results identify the exact certificate and affected item");
            Check(VaultHealthCheck.CheckCertificate(new User { Certificate = oValid.RawData }, oItems,
                false, false, oNow).Severity == HealthStatus.Error,
                "Untrusted self-signed certificates are errors when the policy disallows them");
            oResult = VaultHealthCheck.CheckCertificate(new User { Certificate = oExpired.RawData },
                oItems, true, false, oNow);
            Check(oResult.Severity == HealthStatus.Error && oResult.Details.Contains("has expired"),
                "Health check detects expired certificates even when self-signed certificates are allowed");
            oResult = VaultHealthCheck.CheckCertificate(new User { Certificate = oFuture.RawData },
                oItems, true, false, oNow);
            Check(oResult.Severity == HealthStatus.Error && oResult.Details.Contains("not yet valid"),
                "Health check detects certificates before their validity period");
            oResult = VaultHealthCheck.CheckCertificate(new User { Certificate = oSoon.RawData },
                oItems, true, false, oNow);
            Check(oResult.Severity == HealthStatus.Warning && oResult.Details.Contains("within 30 days"),
                "Health check warns before recipient certificates expire");
            oResult = VaultHealthCheck.CheckCertificate(new User { Certificate = oSigning.RawData },
                oItems, true, false, oNow);
            Check(oResult.Severity == HealthStatus.Error && oResult.Details.Contains("cannot be used for encryption"),
                "Health check rejects signing-only recipient certificates");
        }

        string sPath = Path.Combine(sDirectory, "health-check.cryptdb");
        DatabaseOperations.CreateDatabase(sPath,
            File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SQLite.sql")));
        using (SqliteConnection oConnection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = sPath, Pooling = false, ForeignKeys = false
        }.ConnectionString))
        {
            oConnection.Open();
            using (SqliteCommand oCommand = oConnection.CreateCommand())
            {
                oCommand.CommandText =
                    "INSERT INTO [User] (UserId, Certificate, Sid) VALUES (1, @cert, @sid), (2, X'010203', NULL);" +
                    "INSERT INTO Item (ItemId, Label) VALUES (1, 'Certificate Item'), (2, 'Windows Item'), " +
                    "(3, 'Missing Certificate'), (4, 'Missing Policy'), (5, 'Local Scope'), " +
                    "(6, 'Broken Policy'), (7, 'No Recipients'), (8, 'Unsupported Policy');" +
                    "INSERT INTO Cipher (ItemId, CipherText, CipherVector, CipherParams, ProtectionDescriptor) " +
                    "VALUES (1, X'00', X'00', 3, NULL), (2, X'00', X'00', 2, @descriptor), " +
                    "(3, X'00', X'00', 3, NULL), (5, X'00', X'00', 2, 'LOCAL=user'), " +
                    "(6, X'00', X'00', 2, 'SID=bad'), (7, X'00', X'00', 3, NULL), (8, X'00', X'00', 99, NULL);" +
                    "INSERT INTO Instance (ItemId, UserId, CipherKey, Signature, CipherParams) " +
                    "VALUES (1, 1, X'00', X'00', 3), (3, 99, X'00', X'00', 3);";
                oCommand.Parameters.AddWithValue("@cert", oCert.RawData);
                oCommand.Parameters.AddWithValue("@sid", CertificateOperations.CurrentUserSid);
                oCommand.Parameters.AddWithValue("@descriptor", "SID=" + CertificateOperations.CurrentUserSid +
                    " OR SID=S-1-1-0");
                oCommand.ExecuteNonQuery();
            }
        }
        byte[] oBefore = File.ReadAllBytes(sPath);
        string sConnectionBefore = CryptureEntities.ConnectionString;
        FileAttributes oAttributes = File.GetAttributes(sPath);
        VaultHealthReport oReport;
        try
        {
            File.SetAttributes(sPath, oAttributes | FileAttributes.ReadOnly);
            oReport = VaultHealthCheck.Run(sPath, true, false, CancellationToken.None);
        }
        finally
        {
            File.SetAttributes(sPath, oAttributes);
        }
        Check(oReport.ItemCount == 8 && oReport.Findings.Count(f => f.Kind == "Certificate") == 2,
            "Health scan checks every stored certificate, including unused malformed entries");
        Check(oReport.Findings.Count(f => f.Kind == "Windows Principal") == 2 &&
            oReport.Findings.Single(f => f.Identifier == CertificateOperations.CurrentUserSid).ItemCount == 2,
            "Repeated principal SIDs are checked once and include Windows recipients and certificate owners");
        Check(oReport.Findings.Any(f => f.Recipient == "Missing Certificate" &&
            f.Details.Contains("missing from the Vault")), "Health scan finds broken certificate references");
        Check(oReport.Findings.Any(f => f.Recipient == "No Recipients" && f.Severity == HealthStatus.Error),
            "Certificate items without recipients are reported");
        Check(oReport.Findings.Any(f => f.Recipient == "Broken Policy" && f.Severity == HealthStatus.Error) &&
            oReport.Findings.Any(f => f.Recipient == "Unsupported Policy" && f.Severity == HealthStatus.Error) &&
            oReport.Findings.Any(f => f.Recipient == "Missing Policy" && f.Severity == HealthStatus.Error),
            "Damaged protection policies do not stop the remaining health checks");
        Check(oReport.Findings.Single(f => f.Kind == "Windows Scope").Severity == HealthStatus.Information,
            "Local Windows scopes are informational instead of falsely verified recipients");
        Check(File.ReadAllBytes(sPath).SequenceEqual(oBefore) && CryptureEntities.ConnectionString == sConnectionBefore,
            "Health check runs on a read-only Vault without decrypting or changing it or the active connection");
        Check(oReport.Findings.First().Severity == HealthStatus.Error, "Health report lists errors first");
        Check(VaultHealthCheck.Scan(new Item[0], new User[0], true, true, CancellationToken.None)
            .Findings.Count == 0, "Empty Vaults report no recipients rather than claiming verified access");
        using (CancellationTokenSource oCancellation = new CancellationTokenSource())
        {
            oCancellation.Cancel();
            try
            {
                VaultHealthCheck.Run(sPath, true, true, oCancellation.Token);
                throw new Exception("Canceled health check unexpectedly ran.");
            }
            catch (OperationCanceledException)
            {
                Check(true, "Health checks honor cancellation before opening the Vault");
            }
        }
        string sMissing = Path.Combine(sDirectory, "missing-health-check.cryptdb");
        Reject(() => VaultHealthCheck.Run(sMissing, true, true, CancellationToken.None),
            "Health check reports an unavailable Vault");
        Check(!File.Exists(sMissing), "Health check never creates a missing Vault");
    }
}
