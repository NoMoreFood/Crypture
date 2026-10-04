using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;
using System.Text.RegularExpressions;

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
            CancellationToken oCancellation, IProgress<string> oProgress = null) =>
            Run(new SqliteVaultStorage(sPath), bAllowSelfSigned, bCheckRevocation, oCancellation, oProgress);

        internal static VaultHealthReport Run(IVaultStorage oStorage, bool bAllowSelfSigned, bool bCheckRevocation,
            CancellationToken oCancellation, IProgress<string> oProgress = null)
        {
            oCancellation.ThrowIfCancellationRequested();
            oProgress?.Report("Reading saved Vault recipients...");
            List<User> oUsers = new List<User>();
            Dictionary<long, Item> oItems = new Dictionary<long, Item>();
            using (DbConnection oConnection = oStorage.OpenHealthConnection())
            {
                oConnection.Open();
                using (DbTransaction oTransaction = oStorage.BeginHealthSnapshot(oConnection))
                using (DbCommand oCommand = oConnection.CreateCommand())
                {
                    oCommand.Transaction = oTransaction;
                    oCommand.CommandText = "SELECT i.ItemId, i.Label, c.CipherParams, " +
                        "c.ProtectionDescriptor, c.ProtectedKey, c.ContentSuite " +
                        "FROM Item i LEFT JOIN " + (oStorage.IsSqlServer ? "AuthorizedCipher" : "Cipher") +
                        " c ON i.ItemId = c.ItemId";
                    using (DbDataReader oReader = oCommand.ExecuteReader())
                    {
                        const int ItemIdColumn = 0;
                        const int LabelColumn = 1;
                        const int CipherFormatColumn = 2;
                        const int ProtectionDescriptorColumn = 3;
                        const int ProtectedKeyColumn = 4;
                        const int ContentSuiteColumn = 5;
                        while (oReader.Read())
                        {
                            oCancellation.ThrowIfCancellationRequested();
                            Item oItem = new Item
                            {
                                ItemId = oReader.GetInt64(ItemIdColumn), Label = oReader.GetString(LabelColumn)
                            };
                            if (!oReader.IsDBNull(CipherFormatColumn)) oItem.Cipher = new Cipher
                            {
                                CipherParams = oReader.GetInt64(CipherFormatColumn),
                                ProtectionDescriptor = oReader.IsDBNull(ProtectionDescriptorColumn) ? null
                                    : oReader.GetString(ProtectionDescriptorColumn),
                                ProtectedKey = oReader.IsDBNull(ProtectedKeyColumn) ? null
                                    : (byte[])oReader.GetValue(ProtectedKeyColumn),
                                ContentSuite = oReader.IsDBNull(ContentSuiteColumn) ? null
                                    : oReader.GetInt64(ContentSuiteColumn)
                            };
                            oItems.Add(oItem.ItemId, oItem);
                        }
                    }
                    oCommand.CommandText = "SELECT UserId, Certificate, Sid FROM [User]";
                    using (DbDataReader oReader = oCommand.ExecuteReader())
                    {
                        const int RecipientIdColumn = 0;
                        const int CertificateColumn = 1;
                        const int SidColumn = 2;
                        while (oReader.Read())
                        {
                            oCancellation.ThrowIfCancellationRequested();
                            oUsers.Add(new User
                            {
                                UserId = oReader.GetInt64(RecipientIdColumn),
                                Certificate = oReader.IsDBNull(CertificateColumn) ? null
                                    : (byte[])oReader.GetValue(CertificateColumn),
                                Sid = oReader.IsDBNull(SidColumn) ? null : oReader.GetString(SidColumn)
                            });
                        }
                    }
                    oCommand.CommandText = "SELECT ItemId, UserId FROM " +
                        (oStorage.IsSqlServer ? "AuthorizedInstance" : "Instance");
                    using (DbDataReader oReader = oCommand.ExecuteReader())
                    {
                        const int ItemIdColumn = 0;
                        const int RecipientIdColumn = 1;
                        while (oReader.Read())
                        {
                            oCancellation.ThrowIfCancellationRequested();
                            if (oItems.TryGetValue(oReader.GetInt64(ItemIdColumn), out Item oItem))
                                oItem.Instances.Add(new Instance { UserId = oReader.GetInt64(RecipientIdColumn) });
                        }
                    }
                    oTransaction.Commit();
                }
            }
            return Scan(oItems.Values.ToList(), oUsers, bAllowSelfSigned, bCheckRevocation,
                oCancellation, oProgress, oStorage);
        }

        internal static VaultHealthReport Scan(IReadOnlyList<Item> oItems, IReadOnlyList<User> oUsers,
            bool bAllowSelfSigned, bool bCheckRevocation, CancellationToken oCancellation,
            IProgress<string> oProgress = null, IVaultStorage oStorage = null)
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
                if (!ItemCryptography.HasSupportedContentSuite(oItem.Cipher) ||
                    oItem.Cipher.ContentSuite == (long)ContentEncryptionSuite.Aes256Gcm && !AesGcm.IsSupported)
                {
                    oPolicy.Add(HealthStatus.Error,
                        "The saved content encryption suite is unsupported on this computer.");
                    oReport.Findings.Add(oPolicy);
                    continue;
                }
                if (oItem.Cipher.CipherParams == ItemCryptography.RecoveryFormat)
                {
                    try
                    {
                        foreach (var oEntry in RecoveryProtection.ReadWindowsKeys(oItem.Cipher))
                        {
                            PrincipalProtection.ValidateCustomDescriptor(oEntry.Key);
                            foreach (Match oMatch in Regex.Matches(oEntry.Key, @"S-\d+(?:-\d+)+"))
                                AddPrincipal(oPrincipals, oMatch.Value, new[] { oItem });
                            oPolicy.Add(HealthStatus.Information, "Saved Windows Policy: " + oEntry.Key +
                                ". This metadata check does not verify decryption access.");
                        }
                    }
                    catch (CryptographicException oError)
                    {
                        oPolicy.Add(HealthStatus.Error, "The saved recovery policy is invalid. " + oError.Message);
                    }
                    if (oItem.Cipher.ProtectionDescriptor == null && oItem.Instances.Count == 0)
                        oPolicy.Add(HealthStatus.Error, "No primary certificate recipients are saved for this item.");
                    if (oItem.Instances.Any(i => !oUserIds.Contains(i.UserId)))
                        oPolicy.Add(HealthStatus.Error, "A recipient refers to a certificate missing from the Vault.");
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
                if (oItem.Cipher.CipherParams != ItemCryptography.LegacyFormat &&
                    oItem.Cipher.CipherParams != ItemCryptography.AuthenticatedFormat &&
                    oItem.Cipher.CipherParams != ItemCryptography.CertificateFormat)
                    oPolicy.Add(HealthStatus.Error, "The saved protection format is not supported.");
                if (oItem.Instances.Count == 0)
                    oPolicy.Add(HealthStatus.Error, "No certificate recipients are saved for this item.");
                if (oItem.Instances.Any(i => !oUserIds.Contains(i.UserId)))
                    oPolicy.Add(HealthStatus.Error, "A recipient refers to a certificate missing from the Vault.");
                if (oPolicy.Severity != HealthStatus.Passed) oReport.Findings.Add(oPolicy);
            }

            // Report items that predate the configured recovery recipients without decrypting them.
            try
            {
                RecoveryPolicy oRecovery = oStorage == null ? RecoveryPolicy.Read() :
                    RecoveryPolicy.ReadForStorage(oStorage, true);
                if (oRecovery.IsEnabled)
                {
                    HashSet<long> oRecoveryUsers = new HashSet<long>(oUsers.Where(u =>
                        oRecovery.Certificate != null && u.Certificate != null &&
                        u.Certificate.SequenceEqual(oRecovery.Certificate)).Select(u => u.UserId));
                    foreach (Item oItem in oItems.Where(i => i.Cipher != null))
                    {
                        oCancellation.ThrowIfCancellationRequested();
                        bool bWindows = oRecovery.Descriptor == null ||
                            oItem.Cipher.CipherParams == ItemCryptography.PrincipalFormat &&
                            oItem.Cipher.ProtectionDescriptor == oRecovery.Descriptor;
                        if (!bWindows && oItem.Cipher.CipherParams == ItemCryptography.RecoveryFormat)
                        {
                            try
                            {
                                bWindows = RecoveryProtection.ReadWindowsKeys(oItem.Cipher)
                                    .Any(e => e.Key == oRecovery.Descriptor);
                            }
                            catch (CryptographicException)
                            {
                                // The invalid envelope is reported by the saved-policy check above.
                            }
                        }
                        if (bWindows && (oRecovery.Certificate == null ||
                            oItem.Instances.Any(i => oRecoveryUsers.Contains(i.UserId)))) continue;
                        HealthCheckFinding oMissing = Finding("Emergency Recovery", oItem.Label,
                            "Item #" + oItem.ItemId, new[] { oItem });
                        oMissing.Add(HealthStatus.Warning, "Configured emergency recovery access is missing. " +
                            "Decrypt and save this item to apply the current recovery policy.");
                        oReport.Findings.Add(oMissing);
                    }
                }
            }
            catch (InvalidOperationException oError)
            {
                HealthCheckFinding oInvalid = Finding("Emergency Recovery",
                    "Configuration", "Crypture.exe.config", oItems);
                oInvalid.Add(HealthStatus.Error, oError.Message);
                oReport.Findings.Add(oInvalid);
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
            const int AccountDisabledFlag = 0x2;
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
                        if (oEntry.Properties["userAccountControl"].Value is int nFlags &&
                            (nFlags & AccountDisabledFlag) != 0)
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
            const int ExpiryWarningDays = 30;
            HealthCheckFinding oResult = Finding("Certificate", "Certificate #" + oUser.UserId,
                "Certificate #" + oUser.UserId, oItems);
            try
            {
                if (oUser.Certificate == null || oUser.Certificate.Length == 0 ||
                    X509Certificate2.GetCertContentType(oUser.Certificate) != X509ContentType.Cert)
                    throw new CryptographicException("Stored data is not a public X.509 certificate.");
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oUser.Certificate))
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
                    else if (oCert.NotAfter.ToUniversalTime() <= oNow.AddDays(ExpiryWarningDays))
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
                        const int ChainRetrievalTimeoutSeconds = 10;
                        oChain.ChainPolicy.RevocationMode = bCheckRevocation
                            ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
                        oChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                        oChain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(ChainRetrievalTimeoutSeconds);
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
