using System;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Crypture
{
    internal static class NativeMethods
    {
#pragma warning disable 0649

        internal struct CRYPT_OID_INFO
        {
            internal uint cbSize;

            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszOID;

            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszName;

            internal uint dwGroupId;
            internal uint Algid;
        }

        internal delegate bool CryptEnumCallback(IntPtr pInfo, IntPtr pvParam);

        [DllImport("crypt32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptEnumOIDInfo(OidGroup oGroupId,
            UInt32 dwFlags, IntPtr pvParam, CryptEnumCallback oFunc);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptVerifyCertificateSignatureEx(IntPtr hProvider, uint nEncoding,
            uint nSubjectType, IntPtr pSubject, uint nIssuerType, IntPtr pIssuer, uint nFlags, IntPtr pExtra);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptAcquireCertificatePrivateKey(IntPtr pCertificate, uint nFlags,
            IntPtr pParameters, out SafeNCryptKeyHandle pKey, out uint nKeySpec,
            [MarshalAs(UnmanagedType.Bool)] out bool bCallerFrees);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CertGetCertificateContextProperty(IntPtr pCertificate, uint nProperty,
            IntPtr pData, ref uint nSize);

        internal static OidCollection GetExtendedKeyUsages()
        {
            OidCollection oUsages = new OidCollection();
            CryptEnumOIDInfo(OidGroup.EnhancedKeyUsage, 0, IntPtr.Zero, (pInfo, pvParam) =>
            {
                CRYPT_OID_INFO oInfo = Marshal.PtrToStructure<CRYPT_OID_INFO>(pInfo);
                oUsages.Add(new Oid(oInfo.pszOID, oInfo.pwszName));
                return true;
            });
            return oUsages;
        }
    }
}
