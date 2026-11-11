using System;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

    internal static class CertificateSilentAccess
    {
        private const int SilentFlag = 0x40;

        internal static byte[] DecryptRsa(X509Certificate2 oCertificate, byte[] oEncrypted)
        {
            // CAPI contexts suppress UI at acquisition; CNG also requires silent flags on private operations.
            const uint CachedCngKey = 0x00040001;
            const uint CngKeySpec = 0xFFFFFFFF;
            const int OaepPaddingFlag = 4;
            if (!CryptAcquireCertificatePrivateKey(oCertificate.Handle, CachedCngKey | SilentFlag,
                IntPtr.Zero, out IntPtr hProvider, out uint nKeySpec, out bool bCallerFrees) &&
                !CryptAcquireCertificatePrivateKey(oCertificate.Handle, SilentFlag,
                    IntPtr.Zero, out hProvider, out nKeySpec, out bCallerFrees))
                throw new CryptographicException(Marshal.GetLastWin32Error());
            byte[] oBuffer = (byte[])oEncrypted.Clone();
            try
            {
                int nLength = oBuffer.Length;
                if (nKeySpec == CngKeySpec)
                {
                    OaepPaddingInfo oPadding = new OaepPaddingInfo { Algorithm = "SHA1" };
                    int nStatus = NCryptDecrypt(hProvider, oEncrypted, oEncrypted.Length, ref oPadding,
                        oBuffer, oBuffer.Length, out nLength, OaepPaddingFlag | SilentFlag);
                    if (nStatus != 0) throw new CryptographicException(nStatus);
                }
                else
                {
                    if (!CryptGetUserKey(hProvider, nKeySpec, out IntPtr hKey))
                        throw new CryptographicException(Marshal.GetLastWin32Error());
                    try
                    {
                        // CryptoAPI consumes RSA ciphertext in little-endian order.
                        Array.Reverse(oBuffer);
                        if (!CryptDecrypt(hKey, IntPtr.Zero, true, OaepPaddingFlag, oBuffer, ref nLength))
                            throw new CryptographicException(Marshal.GetLastWin32Error());
                    }
                    finally { CryptDestroyKey(hKey); }
                }
                if (nLength != ItemCryptography.ContentKeyBytes)
                    throw new CryptographicException("The decrypted content key has an invalid length.");
                return oBuffer.AsSpan(0, nLength).ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oBuffer);
                if (bCallerFrees)
                {
                    if (nKeySpec == CngKeySpec) NCryptFreeObject(hProvider);
                    else CryptReleaseContext(hProvider, 0);
                }
                GC.KeepAlive(oCertificate);
            }
        }

        internal static byte[] DeriveSecret(CngKey oPrivate, byte[] oEncapsulation)
        {
            byte[] oSecret = new byte[32];
            bool bSuccess = false;
            try
            {
                int nStatus, nLength;
                if (oPrivate.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
                    throw new CryptographicException("The certificate needs an ECDH private key.");

                // Derive the same SHA-256 secret as ECDiffieHellmanCng, with UI suppressed throughout.
                using CngKey oPublic = CngKey.Import(oEncapsulation, CngKeyBlobFormat.EccPublicBlob,
                    oPrivate.Provider);
                nStatus = NCryptSecretAgreement(oPrivate.Handle, oPublic.Handle,
                    out SafeNCryptSecretHandle oAgreement, SilentFlag);
                using (oAgreement)
                {
                    if (nStatus != 0) throw new CryptographicException(nStatus);
                    IntPtr pAlgorithm = IntPtr.Zero, pBuffer = IntPtr.Zero;
                    try
                    {
                        pAlgorithm = Marshal.StringToHGlobalUni("SHA256");
                        KeyDerivationBuffer oBuffer = new KeyDerivationBuffer
                        {
                            Length = ("SHA256".Length + 1) * sizeof(char), Type = 0, Data = pAlgorithm
                        };
                        pBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<KeyDerivationBuffer>());
                        Marshal.StructureToPtr(oBuffer, pBuffer, false);
                        KeyDerivationParameters oParameters = new KeyDerivationParameters
                        {
                            Count = 1, Buffers = pBuffer
                        };

                        // Hash the established secret; this operation accepts no silent flag or private key.
                        nStatus = NCryptDeriveKey(oAgreement, "HASH", ref oParameters,
                            oSecret, oSecret.Length, out nLength, 0);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pBuffer);
                        Marshal.FreeHGlobal(pAlgorithm);
                    }
                }
                if (nStatus != 0) throw new CryptographicException(nStatus);
                if (nLength != oSecret.Length)
                    throw new CryptographicException("The derived secret has an invalid length.");
                bSuccess = true;
                return oSecret;
            }
            finally
            {
                if (!bSuccess) CryptographicOperations.ZeroMemory(oSecret);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct OaepPaddingInfo
        {
            [MarshalAs(UnmanagedType.LPWStr)] internal string Algorithm;
            internal IntPtr Label;
            internal int LabelLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KeyDerivationBuffer
        {
            internal int Length;
            internal int Type;
            internal IntPtr Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KeyDerivationParameters
        {
            internal int Version;
            internal int Count;
            internal IntPtr Buffers;
        }

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptAcquireCertificatePrivateKey(IntPtr pCertificate, uint nFlags,
            IntPtr pParameters, out IntPtr hProvider, out uint nKeySpec,
            [MarshalAs(UnmanagedType.Bool)] out bool bCallerFrees);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptGetUserKey(IntPtr hProvider, uint nKeySpec, out IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, [MarshalAs(UnmanagedType.Bool)] bool bFinal,
            int nFlags, [In, Out] byte[] oData, ref int nLength);

        [DllImport("advapi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptDestroyKey(IntPtr hKey);

        [DllImport("advapi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptReleaseContext(IntPtr hProvider, int nFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptFreeObject(IntPtr hObject);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptDecrypt(IntPtr hKey, byte[] oInput, int nInputLength,
            ref OaepPaddingInfo oPadding, [Out] byte[] oOutput, int nOutputLength, out int nWritten, int nFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSecretAgreement(SafeNCryptKeyHandle oPrivate, SafeNCryptKeyHandle oPublic,
            out SafeNCryptSecretHandle oSecret, int nFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptDeriveKey(SafeNCryptSecretHandle oSecret, string sKdf,
            ref KeyDerivationParameters oParameters, [Out] byte[] oOutput, int nOutputLength,
            out int nWritten, int nFlags);
    }
}
