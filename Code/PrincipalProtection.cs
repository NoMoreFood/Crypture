using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Crypture
{
    public sealed class ProtectionPrincipal
    {
        public string Sid { get; }
        public string Name { get; }

        internal ProtectionPrincipal(string sSid, string sName = null)
        {
            SecurityIdentifier oSid = new SecurityIdentifier(sSid);
            Sid = oSid.Value;
            Name = sName;
            if (!String.IsNullOrWhiteSpace(Name)) return;
            try
            {
                Name = oSid.Translate(typeof(NTAccount)).Value;
            }
            catch (SystemException)
            {
                Name = Sid;
            }
        }

        internal static ProtectionPrincipal Resolve(string sAccount)
        {
            sAccount = sAccount?.Trim();
            if (String.IsNullOrEmpty(sAccount))
                throw new InvalidOperationException("Enter a Windows account, group, or SID.");
            if (sAccount.StartsWith("S-", StringComparison.OrdinalIgnoreCase))
                return new ProtectionPrincipal(sAccount);
            try
            {
                SecurityIdentifier oSid = (SecurityIdentifier)new NTAccount(sAccount)
                    .Translate(typeof(SecurityIdentifier));
                return new ProtectionPrincipal(oSid.Value, sAccount);
            }
            catch (IdentityNotMappedException) when (PrincipalProtection.IsDomainJoined)
            {
                return ForestDirectory.ResolvePrincipal(sAccount);
            }
        }
    }

    internal static class PrincipalProtection
    {
        // Windows protection descriptor syntax.
        private const string SidPrefix = "SID=";
        internal const string LocalUserDescriptor = "LOCAL=user";
        internal const string LocalMachineDescriptor = "LOCAL=machine";

        // Limits for principal lists, descriptors, and protected key blobs.
        internal const int MaxPrincipals = 100;
        internal const int MaxDescriptorLength = 16000;
        internal const int MaxProtectedKeyLength = 1024 * 1024;

        // NCrypt suppresses provider UI during protect and unprotect operations.
        private const int SilentOperationFlag = 0x40;

        internal static bool IsDomainJoined
        {
            get
            {
                int nStatus = NetGetJoinInformation(null, out NetApiBuffer oBuffer, out JoinStatus nJoinStatus);
                using (oBuffer) return nStatus == 0 && nJoinStatus == JoinStatus.Domain;
            }
        }

        internal static string CreateDescriptor(IEnumerable<ProtectionPrincipal> oPrincipals, bool bRequireAll)
        {
            string[] oSids = oPrincipals.Select(p => new SecurityIdentifier(p.Sid).Value)
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.Ordinal).ToArray();
            if (oSids.Length == 0 || oSids.Length > MaxPrincipals)
                throw new InvalidOperationException("Select between 1 and 100 Windows users or security groups.");
            return String.Join(bRequireAll ? " AND " : " OR ", oSids.Select(s => SidPrefix + s));
        }

        internal static List<ProtectionPrincipal> ParseDescriptor(string sDescriptor, out bool bRequireAll,
            bool bResolveNames = true)
        {
            bRequireAll = false;
            if (String.IsNullOrEmpty(sDescriptor) || sDescriptor.Length > MaxDescriptorLength)
                throw new CryptographicException("The Windows protection policy is missing or invalid.");
            if (sDescriptor == LocalUserDescriptor || sDescriptor == LocalMachineDescriptor)
                return new List<ProtectionPrincipal>();
            bRequireAll = sDescriptor.Contains(" AND ");
            string[] oParts = sDescriptor.Split(new[] { bRequireAll ? " AND " : " OR " },
                StringSplitOptions.None);
            if (oParts.Length > MaxPrincipals ||
                oParts.Any(p => !p.StartsWith(SidPrefix, StringComparison.Ordinal)))
                throw new CryptographicException("The Windows protection policy is not supported.");
            try
            {
                return oParts.Select(p => new ProtectionPrincipal(p.Substring(SidPrefix.Length),
                    bResolveNames ? null : p.Substring(SidPrefix.Length))).ToList();
            }
            catch (ArgumentException)
            {
                throw new CryptographicException("The Windows protection policy contains an invalid SID.");
            }
        }

        internal static void ValidateCustomDescriptor(string sDescriptor)
        {
            if (String.IsNullOrWhiteSpace(sDescriptor) || sDescriptor.Length > MaxDescriptorLength ||
                sDescriptor.Contains("\0"))
                throw new CryptographicException("The recovery protection descriptor is missing or invalid.");
            int nStatus = NCryptCreateProtectionDescriptor(sDescriptor, 0, out DescriptorHandle oDescriptor);
            using (oDescriptor) ThrowIfFailed(nStatus, "create the emergency recovery policy");
        }

        internal static void ValidateRecoveryDescriptor(string sDescriptor) =>
            ResolveRecoveryDescriptor(sDescriptor, false);

        internal static string ResolveRecoveryDescriptor(string sDescriptor, bool bResolveNames = true)
        {
            if (String.IsNullOrWhiteSpace(sDescriptor) || sDescriptor.Length > MaxDescriptorLength ||
                sDescriptor.Contains("\0"))
                throw new CryptographicException("The recovery protection descriptor is missing or invalid.");
            try
            {
                // Resolve each principal independently without changing native providers or boolean precedence.
                string[] oParts = Regex.Split(sDescriptor, @"(\s+(?:AND|OR)\s+)");
                bool bPrincipalsOnly = true;
                int nPrincipals = 0;
                for (int nIndex = 0; nIndex < oParts.Length; nIndex += 2)
                {
                    string sPart = oParts[nIndex].Trim();
                    bool bSid = sPart.StartsWith(SidPrefix, StringComparison.OrdinalIgnoreCase);
                    if (!bSid && sPart.Contains('='))
                    {
                        bPrincipalsOnly = false;
                        continue;
                    }
                    string sName = (bSid ? sPart.Substring(SidPrefix.Length) : sPart).Trim();
                    if (String.IsNullOrEmpty(sName))
                        throw new CryptographicException("The recovery protection descriptor is missing or invalid.");
                    if (++nPrincipals > MaxPrincipals)
                        throw new CryptographicException("The recovery protection descriptor has too many principals.");

                    // Decode native SID escapes while retaining Windows account spelling for name lookups.
                    string sSidName = bSid ? Regex.Replace(sName, @"\\([0-9a-fA-F]{2})",
                        m => ((char)Convert.ToInt32(m.Groups[1].Value, 16)).ToString()) : sName;

                    // A placeholder validates the expression without looking up configured names before encryption.
                    string sSid = !bResolveNames ? "S-1-1-0" :
                        sSidName.StartsWith("S-", StringComparison.OrdinalIgnoreCase)
                            ? new SecurityIdentifier(sSidName).Value : ProtectionPrincipal.Resolve(sName).Sid;
                    oParts[nIndex] = SidPrefix + sSid;
                }

                // Simple principal lists share the canonical ordering used by the item editor.
                bool bAnd = oParts.Any(s => s.Trim() == "AND"), bOr = oParts.Any(s => s.Trim() == "OR");
                string sResolved = bPrincipalsOnly && !(bAnd && bOr)
                    ? String.Join(bAnd ? " AND " : " OR ", oParts.Where((s, i) => i % 2 == 0)
                        .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.Ordinal))
                    : String.Concat(oParts);
                ValidateCustomDescriptor(sResolved);
                return sResolved;
            }
            catch (Exception oError) when (oError is ArgumentException || oError is IdentityNotMappedException ||
                oError is InvalidOperationException)
            {
                throw new CryptographicException("The emergency recovery Windows principal could not be resolved.",
                    oError);
            }
        }

        internal static byte[] Protect(byte[] oKeys, string sDescriptor, bool bCustomDescriptor = false)
        {
            if (bCustomDescriptor) ValidateCustomDescriptor(sDescriptor);
            else ParseDescriptor(sDescriptor, out _, false);
            if (oKeys == null || oKeys.Length != ItemCryptography.ContentKeyBytes)
                throw new CryptographicException("The item encryption keys are invalid.");
            if (!bCustomDescriptor && sDescriptor != LocalUserDescriptor &&
                sDescriptor != LocalMachineDescriptor && !IsDomainJoined)
                throw new CryptographicException("Domain Users and Groups requires Active Directory. " +
                    "On a standalone computer, choose Saving Account's Local Windows Profile for your own account, " +
                    "or All Users on This Computer for everyone on this computer. " +
                    "Use certificates to share with selected users.");
            int nStatus = NCryptCreateProtectionDescriptor(sDescriptor, 0, out DescriptorHandle oDescriptor);
            using (oDescriptor)
            {
                ThrowIfFailed(nStatus, "create the Windows protection policy");
                nStatus = NCryptProtectSecret(oDescriptor, SilentOperationFlag, oKeys, oKeys.Length, IntPtr.Zero,
                    IntPtr.Zero, out LocalBuffer oBuffer, out int nLength);
                using (oBuffer)
                {
                    ThrowIfFailed(nStatus, "encrypt this item with the selected Windows scope");
                    if (nLength < 1 || nLength > MaxProtectedKeyLength || oBuffer.IsInvalid)
                        throw new CryptographicException("Windows returned an invalid protected key.");
                    byte[] oProtected = new byte[nLength];
                    Marshal.Copy(oBuffer.DangerousGetHandle(), oProtected, 0, nLength);
                    return oProtected;
                }
            }
        }

        internal static byte[] Unprotect(byte[] oProtected)
        {
            if (oProtected == null || oProtected.Length == 0 || oProtected.Length > MaxProtectedKeyLength)
                throw new CryptographicException("The protected item key is missing or damaged.");
            int nStatus = NCryptUnprotectSecret(IntPtr.Zero, SilentOperationFlag, oProtected, oProtected.Length,
                IntPtr.Zero, IntPtr.Zero, out LocalBuffer oBuffer, out int nLength);
            using (oBuffer)
            {
                oBuffer.ClearLength = nLength;
                ThrowIfFailed(nStatus, "decrypt this item with your Windows account");
                if (nLength != ItemCryptography.ContentKeyBytes || oBuffer.IsInvalid)
                    throw new CryptographicException("The protected item key is damaged.");
                byte[] oKeys = new byte[nLength];
                Marshal.Copy(oBuffer.DangerousGetHandle(), oKeys, 0, nLength);
                return oKeys;
            }
        }

        private static void ThrowIfFailed(int nStatus, string sAction)
        {
            if (nStatus == 0) return;
            throw new CryptographicException("Windows could not " + sAction + ". " +
                new Win32Exception(nStatus).Message +
                " (0x" + nStatus.ToString("X8", CultureInfo.InvariantCulture) + "). " +
                "For domain principals, check domain connectivity, key distribution services, " +
                "and account permissions. Local protection requires the original Windows profile or computer.");
        }

        private enum JoinStatus
        {
            Unknown,
            Unjoined,
            Workgroup,
            Domain
        }

        private sealed class NetApiBuffer : SafeHandleZeroOrMinusOneIsInvalid
        {
            public NetApiBuffer() : base(true)
            {
            }
            protected override bool ReleaseHandle() => NetApiBufferFree(handle) == 0;
        }

        private sealed class DescriptorHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public DescriptorHandle() : base(true)
            {
            }
            protected override bool ReleaseHandle() => NCryptCloseProtectionDescriptor(handle) == 0;
        }

        private sealed class LocalBuffer : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal int ClearLength { get; set; }
            public LocalBuffer() : base(true)
            {
            }
            protected override bool ReleaseHandle()
            {
                for (int nIndex = 0; nIndex < ClearLength; nIndex++) Marshal.WriteByte(handle, nIndex, 0);
                return LocalFree(handle) == IntPtr.Zero;
            }
        }

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int NCryptCreateProtectionDescriptor(string pwszDescriptorString,
            int dwFlags, out DescriptorHandle phDescriptor);

        [DllImport("ncrypt.dll", ExactSpelling = true)]
        private static extern int NCryptCloseProtectionDescriptor(IntPtr hDescriptor);

        [DllImport("ncrypt.dll", ExactSpelling = true)]
        private static extern int NCryptProtectSecret(DescriptorHandle hDescriptor, int dwFlags,
            byte[] pbData, int cbData, IntPtr pMemPara, IntPtr hWnd, out LocalBuffer ppbProtectedBlob,
            out int pcbProtectedBlob);

        [DllImport("ncrypt.dll", ExactSpelling = true)]
        private static extern int NCryptUnprotectSecret(IntPtr phDescriptor, int dwFlags,
            byte[] pbProtectedBlob, int cbProtectedBlob, IntPtr pMemPara, IntPtr hWnd,
            out LocalBuffer ppbData, out int pcbData);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int NetGetJoinInformation(string lpServer, out NetApiBuffer lpNameBuffer,
            out JoinStatus BufferType);

        [DllImport("netapi32.dll", ExactSpelling = true)]
        private static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);
    }
}
