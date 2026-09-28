using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;

namespace Crypture
{
    internal enum HealthStatus
    {
        Passed, Information, Warning, Error
    }

    internal sealed class HealthCheckFinding
    {
        public HealthStatus Severity { get; private set; }
        public string Status => Severity.ToString();
        public string Kind { get; set; }
        public string Recipient { get; set; }
        public string Identifier { get; set; }
        public int ItemCount { get; set; }
        public string AffectedItems { get; set; }
        public string Details { get; private set; } = "";
        public string Glyph => Severity == HealthStatus.Error ? "\uEA39" :
            Severity == HealthStatus.Warning ? "\uE7BA" : Severity == HealthStatus.Information ? "\uE946" : "\uE73E";
        public string FullDetails => Recipient + Environment.NewLine + Identifier + Environment.NewLine +
            Environment.NewLine + Details + Environment.NewLine + Environment.NewLine +
            "Affected Items:" + Environment.NewLine + (ItemCount == 0 ? "No saved items." : AffectedItems);

        internal void Add(HealthStatus oStatus, string sDetail)
        {
            if (oStatus > Severity) Severity = oStatus;
            Details += (Details.Length == 0 ? "" : Environment.NewLine) + sDetail;
        }
    }

    internal sealed class VaultHealthReport
    {
        public DateTime CheckedAt { get; } = DateTime.UtcNow;
        public int ItemCount { get; set; }
        public List<HealthCheckFinding> Findings { get; set; } = new List<HealthCheckFinding>();
        public string Summary => "Errors: " + Findings.Count(f => f.Severity == HealthStatus.Error) +
            ", Warnings: " + Findings.Count(f => f.Severity == HealthStatus.Warning) +
            ", Informational: " + Findings.Count(f => f.Severity == HealthStatus.Information) +
            ", Passed: " + Findings.Count(f => f.Severity == HealthStatus.Passed);
    }

    internal static class VaultHealthCheck
    {
        internal static VaultHealthReport Run(string sPath, bool bAllowSelfSigned, bool bCheckRevocation,
            CancellationToken oCancellation, IProgress<string> oProgress = null)
        {
            oCancellation.ThrowIfCancellationRequested();
            oProgress?.Report("Reading saved Vault recipients...");
            List<User> oUsers = new List<User>();
            Dictionary<long, Item> oItems = new Dictionary<long, Item>();
            SQLiteConnectionStringBuilder oBuilder = new SQLiteConnectionStringBuilder
            {
                DataSource = sPath, ReadOnly = true, FailIfMissing = true, Pooling = false
            };
            using (SQLiteConnection oConnection = new SQLiteConnection(oBuilder.ConnectionString))
            {
                oConnection.Open();
                using (SQLiteTransaction oTransaction = oConnection.BeginTransaction(IsolationLevel.ReadCommitted))
                using (SQLiteCommand oCommand = oConnection.CreateCommand())
                {
                    oCommand.Transaction = oTransaction;
                    oCommand.CommandText = "SELECT i.ItemId, i.Label, c.CipherParams, c.ProtectionDescriptor " +
                        "FROM Item i LEFT JOIN Cipher c ON i.ItemId = c.ItemId";
                    using (SQLiteDataReader oReader = oCommand.ExecuteReader())
                    {
                        while (oReader.Read())
                        {
                            oCancellation.ThrowIfCancellationRequested();
                            Item oItem = new Item { ItemId = oReader.GetInt64(0), Label = oReader.GetString(1) };
                            if (!oReader.IsDBNull(2)) oItem.Cipher = new Cipher
                            {
                                CipherParams = oReader.GetInt64(2),
                                ProtectionDescriptor = oReader.IsDBNull(3) ? null : oReader.GetString(3)
                            };
                            oItems.Add(oItem.ItemId, oItem);
                        }
                    }
                    oCommand.CommandText = "SELECT UserId, Certificate, Sid FROM [User]";
                    using (SQLiteDataReader oReader = oCommand.ExecuteReader())
                    {
                        while (oReader.Read())
                        {
                            oCancellation.ThrowIfCancellationRequested();
                            oUsers.Add(new User
                            {
                                UserId = oReader.GetInt64(0),
                                Certificate = oReader.IsDBNull(1) ? null : (byte[])oReader.GetValue(1),
                                Sid = oReader.IsDBNull(2) ? null : oReader.GetString(2)
                            });
                        }
                    }
                    oCommand.CommandText = "SELECT ItemId, UserId FROM Instance";
                    using (SQLiteDataReader oReader = oCommand.ExecuteReader())
                    {
                        while (oReader.Read())
                        {
                            oCancellation.ThrowIfCancellationRequested();
                            if (oItems.TryGetValue(oReader.GetInt64(0), out Item oItem))
                                oItem.Instances.Add(new Instance { UserId = oReader.GetInt64(1) });
                        }
                    }
                    oTransaction.Commit();
                }
            }
            return Scan(oItems.Values.ToList(), oUsers, bAllowSelfSigned, bCheckRevocation,
                oCancellation, oProgress);
        }

        internal static VaultHealthReport Scan(IReadOnlyList<Item> oItems, IReadOnlyList<User> oUsers,
            bool bAllowSelfSigned, bool bCheckRevocation, CancellationToken oCancellation,
            IProgress<string> oProgress = null)
        {
            VaultHealthReport oReport = new VaultHealthReport { ItemCount = oItems.Count };
            Dictionary<string, HashSet<Item>> oPrincipals = new Dictionary<string, HashSet<Item>>(
                StringComparer.OrdinalIgnoreCase);
            HashSet<long> oUserIds = new HashSet<long>(oUsers.Select(u => u.UserId));
            foreach (Item oItem in oItems)
            {
                oCancellation.ThrowIfCancellationRequested();
                HealthCheckFinding oPolicy = Finding("Protection Policy", oItem.Label,
                    "Item #" + oItem.ItemId, new[] { oItem });
                if (oItem.Cipher == null)
                {
                    oPolicy.Add(HealthStatus.Error, "The saved protection policy is missing.");
                    oReport.Findings.Add(oPolicy);
                    continue;
                }
                if (oItem.Cipher.CipherParams == ItemCryptography.PrincipalFormat)
                {
                    try
                    {
                        string sDescriptor = oItem.Cipher.ProtectionDescriptor;
                        List<ProtectionPrincipal> oRecipients = PrincipalProtection.ParseDescriptor(
                            sDescriptor, out _, false);
                        foreach (ProtectionPrincipal oPrincipal in oRecipients)
                            AddPrincipal(oPrincipals, oPrincipal.Sid, new[] { oItem });
                        if (oRecipients.Count != 0) continue;
                        oPolicy.Kind = "Windows Scope";
                        oPolicy.Recipient = sDescriptor == PrincipalProtection.LocalUserDescriptor
                            ? "Saving Account's Local Windows Profile" : "All Users on This Computer";
                        oPolicy.Identifier = sDescriptor;
                        oPolicy.Add(HealthStatus.Information,
                            "This local scope records no recipient SID to look up. Access requires the original " +
                            (sDescriptor == PrincipalProtection.LocalUserDescriptor
                                ? "Windows profile." : "computer.") +
                            " This check does not verify that the original profile or computer is available.");
                    }
                    catch (Exception oError) when (oError is ArgumentException || oError is CryptographicException)
                    {
                        oPolicy.Add(HealthStatus.Error, "The Windows recipient policy is invalid. " + oError.Message);
                    }
                    oReport.Findings.Add(oPolicy);
                    continue;
                }
                if (oItem.Cipher.CipherParams != 0 &&
                    oItem.Cipher.CipherParams != ItemCryptography.AuthenticatedFormat &&
                    oItem.Cipher.CipherParams != ItemCryptography.CertificateFormat)
                    oPolicy.Add(HealthStatus.Error, "The saved protection format is not supported.");
                if (oItem.Instances.Count == 0)
                    oPolicy.Add(HealthStatus.Error, "No certificate recipients are saved for this item.");
                if (oItem.Instances.Any(i => !oUserIds.Contains(i.UserId)))
                    oPolicy.Add(HealthStatus.Error, "A recipient refers to a certificate missing from the Vault.");
                if (oPolicy.Severity != HealthStatus.Passed) oReport.Findings.Add(oPolicy);
            }
            int nCertificate = 0;
            foreach (User oUser in oUsers)
            {
                oCancellation.ThrowIfCancellationRequested();
                List<Item> oAffected = oItems.Where(i => i.Instances.Any(j => j.UserId == oUser.UserId)).ToList();
                if (!String.IsNullOrWhiteSpace(oUser.Sid)) AddPrincipal(oPrincipals, oUser.Sid, oAffected);
                oProgress?.Report("Checking certificate " + (++nCertificate) + " of " + oUsers.Count + "...");
                oReport.Findings.Add(CheckCertificate(oUser, oAffected, bAllowSelfSigned,
                    bCheckRevocation, oReport.CheckedAt));
            }
            int nChecked = 0;
            foreach (var oPrincipal in oPrincipals)
            {
                oCancellation.ThrowIfCancellationRequested();
                oProgress?.Report("Locating Windows principal " + (++nChecked) + " of " + oPrincipals.Count + "...");
                oReport.Findings.Add(CheckPrincipal(oPrincipal.Key, oPrincipal.Value));
            }
            oCancellation.ThrowIfCancellationRequested();
            oReport.Findings = oReport.Findings.OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Kind).ThenBy(f => f.Recipient).ToList();
            return oReport;
        }

        private static void AddPrincipal(Dictionary<string, HashSet<Item>> oPrincipals, string sSid,
            IEnumerable<Item> oItems)
        {
            if (!oPrincipals.TryGetValue(sSid, out HashSet<Item> oAffected))
                oPrincipals.Add(sSid, oAffected = new HashSet<Item>());
            oAffected.UnionWith(oItems);
        }

        private static HealthCheckFinding Finding(string sKind, string sRecipient, string sIdentifier,
            IEnumerable<Item> oItems)
        {
            List<Item> oAffected = oItems.GroupBy(i => i.ItemId).Select(g => g.First()).OrderBy(i => i.Label).ToList();
            return new HealthCheckFinding
            {
                Kind = sKind, Recipient = sRecipient, Identifier = sIdentifier, ItemCount = oAffected.Count,
                AffectedItems = String.Join(Environment.NewLine,
                    oAffected.Select(i => i.Label + " (#" + i.ItemId + ")"))
            };
        }

        internal static HealthCheckFinding CheckPrincipal(string sSid, IEnumerable<Item> oItems)
        {
            HealthCheckFinding oResult = Finding("Windows Principal", sSid, sSid, oItems);
            try
            {
                SecurityIdentifier oSid = new SecurityIdentifier(sSid);
                oResult.Recipient = oSid.Translate(typeof(NTAccount)).Value;
                oResult.Add(HealthStatus.Passed, "Windows resolved this SID to " + oResult.Recipient + ".");
                if (!oSid.IsAccountSid() || oResult.Recipient.StartsWith(Environment.MachineName + "\\",
                    StringComparison.OrdinalIgnoreCase)) return oResult;
                if (!PrincipalProtection.IsDomainJoined)
                {
                    oResult.Add(HealthStatus.Warning, "Windows may have used cached account information. " +
                        "Live directory verification requires a domain-connected computer.");
                    return oResult;
                }
                try
                {
                    using (DirectoryEntry oEntry = new DirectoryEntry("LDAP://<SID=" + oSid.Value + ">"))
                    {
                        oEntry.RefreshCache(new[] { "objectSid", "distinguishedName", "userAccountControl" });
                        byte[] oDirectorySid = oEntry.Properties["objectSid"].Value as byte[];
                        if (oDirectorySid == null || !oSid.Equals(new SecurityIdentifier(oDirectorySid, 0)))
                        {
                            oResult.Add(HealthStatus.Warning, "The directory did not return the requested SID.");
                            return oResult;
                        }
                        oResult.Add(HealthStatus.Passed, "Located in Active Directory: " +
                            oEntry.Properties["distinguishedName"].Value);
                        if (oEntry.Properties["userAccountControl"].Value is int nFlags && (nFlags & 2) != 0)
                            oResult.Add(HealthStatus.Warning, "The directory account is disabled.");
                    }
                }
                catch (SystemException oError)
                {
                    oResult.Add(HealthStatus.Warning, "Windows resolved the name, but live directory verification " +
                        "failed. The account may have been removed, or the directory may be unreachable. " +
                        oError.Message);
                }
            }
            catch (ArgumentException)
            {
                oResult.Add(HealthStatus.Error, "The saved security identifier is malformed.");
            }
            catch (SystemException oError)
            {
                oResult.Add(HealthStatus.Warning, "The principal could not be located. It may have been removed, " +
                    "or its directory may be unreachable. Recheck with domain connectivity " +
                    "before changing recipients. " +
                    oError.Message);
            }
            return oResult;
        }

        internal static HealthCheckFinding CheckCertificate(User oUser, IEnumerable<Item> oItems,
            bool bAllowSelfSigned, bool bCheckRevocation, DateTime oNow)
        {
            HealthCheckFinding oResult = Finding("Certificate", "Certificate #" + oUser.UserId,
                "Certificate #" + oUser.UserId, oItems);
            try
            {
                if (oUser.Certificate == null || oUser.Certificate.Length == 0 ||
                    X509Certificate2.GetCertContentType(oUser.Certificate) != X509ContentType.Cert)
                    throw new CryptographicException("Stored data is not a public X.509 certificate.");
                using (X509Certificate2 oCert = new X509Certificate2(oUser.Certificate))
                {
                    string sName = oCert.GetNameInfo(X509NameType.SimpleName, false);
                    if (!String.IsNullOrWhiteSpace(sName)) oResult.Recipient = sName;
                    oResult.Identifier += Environment.NewLine + "Thumbprint: " + oCert.Thumbprint;
                    oResult.Add(HealthStatus.Passed, "Validity: " + oCert.NotBefore.ToString("yyyy-MM-dd HH:mm") +
                        " through " + oCert.NotAfter.ToString("yyyy-MM-dd HH:mm") + " (local time).");
                    if (oCert.NotBefore.ToUniversalTime() > oNow)
                        oResult.Add(HealthStatus.Error, "The certificate is not yet valid.");
                    if (oCert.NotAfter.ToUniversalTime() < oNow)
                        oResult.Add(HealthStatus.Error, "The certificate has expired.");
                    else if (oCert.NotAfter.ToUniversalTime() <= oNow.AddDays(30))
                        oResult.Add(HealthStatus.Warning, "The certificate expires within 30 days.");
                    try
                    {
                        CertificateKeyProtection.ValidateForEncryption(oCert);
                        oResult.Add(HealthStatus.Passed,
                            "Encryption: " + CertificateKeyProtection.GetAlgorithmDisplay(oCert));
                    }
                    catch (PlatformNotSupportedException oError)
                    {
                        oResult.Add(HealthStatus.Warning, oError.Message);
                    }
                    catch (CryptographicException oError)
                    {
                        oResult.Add(HealthStatus.Error,
                            "The certificate cannot be used for encryption. " + oError.Message);
                    }
                    using (X509Chain oChain = new X509Chain())
                    {
                        oChain.ChainPolicy.RevocationMode = bCheckRevocation
                            ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
                        oChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                        oChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
                        oChain.ChainPolicy.VerificationTime = oNow;
                        bool bValid = oChain.Build(oCert);
                        bool bAllowedSelfSigned = bAllowSelfSigned && oChain.ChainElements.Count == 1 &&
                            CertificateOperations.IsSelfSigned(oCert);
                        if (bAllowedSelfSigned)
                            oResult.Add(HealthStatus.Information,
                                "This self-signed certificate is allowed by your certificate validation settings.");
                        foreach (X509ChainStatus oStatus in oChain.ChainStatus)
                        {
                            X509ChainStatusFlags oFlags = oStatus.Status;
                            if (bAllowedSelfSigned) oFlags &= ~X509ChainStatusFlags.UntrustedRoot;
                            if (oFlags == X509ChainStatusFlags.NoError) continue;
                            X509ChainStatusFlags oUnknown = X509ChainStatusFlags.OfflineRevocation |
                                X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.PartialChain;
                            oResult.Add((oFlags & ~oUnknown) == 0 ? HealthStatus.Warning : HealthStatus.Error,
                                ((oFlags & ~oUnknown) == 0 ? "Could not fully verify the certificate chain: " :
                                "Certificate chain validation failed: ") + oFlags + ". " +
                                oStatus.StatusInformation.Trim());
                        }
                        if (!bValid && oChain.ChainStatus.Length == 0)
                            oResult.Add(HealthStatus.Warning, "Windows could not verify the certificate chain.");
                        if (bValid) oResult.Add(HealthStatus.Passed, "Windows accepted the certificate chain.");
                    }
                    if (!bCheckRevocation)
                        oResult.Add(HealthStatus.Warning,
                            "Revocation was not checked because Do Revocation Check is disabled in Certificates.");
                }
            }
            catch (CryptographicException oError)
            {
                oResult.Add(HealthStatus.Error, "Certificate validation failed. " + oError.Message);
            }
            return oResult;
        }
    }
}
