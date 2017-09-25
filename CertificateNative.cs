using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Crypture
{
    public static class NativeMethods
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

        internal delegate bool CryptEnumCallback(IntPtr pInfo, ref OidCollection pvParam);

        [DllImport("crypt32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptEnumOIDInfo(OidGroup oGroupId, UInt32 dwFlags, ref OidCollection pvParam, CryptEnumCallback oFunc);

        internal static bool GetExtendedKeyUsagesCallback(IntPtr pInfo, ref OidCollection pvParam)
        {
            CRYPT_OID_INFO oInfo = (CRYPT_OID_INFO) Marshal.PtrToStructure(pInfo, typeof(CRYPT_OID_INFO));
            OidCollection ExtendedKeyUsages = (OidCollection)pvParam;
            ExtendedKeyUsages.Add(new Oid(oInfo.pszOID, oInfo.pwszName));
            return true;
        }

        public static OidCollection GetExtendedKeyUsages()
        {
            OidCollection ExtendedKeyUsages = new OidCollection();
            CryptEnumOIDInfo(OidGroup.EnhancedKeyUsage, 0, ref ExtendedKeyUsages, GetExtendedKeyUsagesCallback);
            return ExtendedKeyUsages;
        }
    }
}