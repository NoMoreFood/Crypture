using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Crypture
{
    internal static class FidoNative
    {
        // Use a stable relying party across computers and require verification on the external key.
        private const string RelyingPartyId = "crypture.local";
        private const int MinimumApiVersion = 4;
        private const int CrossPlatformAttachment = 2;
        private const int RequiredVerification = 1;
        private const int NoAttestation = 1;
        private const int RawHmacSecretFlag = 0x00100000;
        private const int TimeoutMilliseconds = 120000;
        private const int AuthenticatorFlagsOffset = 32;
        private const int AuthenticatorDataMinimumBytes = 37;
        private const byte PresenceAndVerificationFlags = 0x05;

        internal static Func<int> ReadApiVersion { get; set; } = WebAuthNGetApiVersionNumber;

        internal static bool IsAvailable
        {
            get
            {
                try { return ReadApiVersion() >= MinimumApiVersion && AesGcm.IsSupported; }
                catch (Exception oError) when (oError is DllNotFoundException || oError is EntryPointNotFoundException)
                {
                    return false;
                }
            }
        }

        internal static byte[] CreateCredential(IntPtr hOwner)
        {
            if (!IsAvailable)
                throw new PlatformNotSupportedException(
                    "FIDO2 encryption requires Windows WebAuthn hmac-secret support.");

            // Create a nonresident credential without consuming a discoverable-credential slot.
            using NativeBuffer oUserId = new NativeBuffer(RandomNumberGenerator.GetBytes(32));
            using NativeBuffer oCredentialType = new NativeBuffer(Encoding.Unicode.GetBytes("public-key\0"));
            using NativeBuffer oParameters = NativeBuffer.From(new CredentialParameter
            {
                Version = 1, Type = oCredentialType.DangerousGetHandle(), Algorithm = -7
            });
            using NativeBuffer oEnabled = NativeBuffer.From(1);
            using NativeBuffer oExtensionName = new NativeBuffer(Encoding.Unicode.GetBytes("hmac-secret\0"));
            using NativeBuffer oExtension = NativeBuffer.From(new Extension
            {
                Identifier = oExtensionName.DangerousGetHandle(), Length = sizeof(int),
                Value = oEnabled.DangerousGetHandle()
            });
            using NativeBuffer oJson = new NativeBuffer(ClientDataJson("webauthn.create"));
            RelyingParty oRp = new RelyingParty { Version = 1, Id = RelyingPartyId, Name = "Crypture" };
            UserEntity oUser = new UserEntity
            {
                Version = 1, IdLength = 32, Id = oUserId.DangerousGetHandle(),
                Name = "Crypture", DisplayName = "Crypture"
            };
            CredentialParameters oCredentialParameters = new CredentialParameters
            {
                Count = 1, Parameters = oParameters.DangerousGetHandle()
            };
            ClientData oClient = new ClientData
            {
                Version = 1, Length = oJson.Length, Json = oJson.DangerousGetHandle(), HashAlgorithm = "SHA-256"
            };
            MakeCredentialOptions oOptions = new MakeCredentialOptions
            {
                Version = 1, Timeout = TimeoutMilliseconds,
                Extensions = new Extensions { Count = 1, Values = oExtension.DangerousGetHandle() },
                Attachment = CrossPlatformAttachment, Verification = RequiredVerification, Attestation = NoAttestation
            };
            int nStatus = WebAuthNAuthenticatorMakeCredential(hOwner, ref oRp, ref oUser,
                ref oCredentialParameters, ref oClient, ref oOptions, out AttestationHandle oResult);
            using (oResult)
            {
                ThrowIfFailed(nStatus);
                if (oResult.IsInvalid || Marshal.ReadInt32(oResult.DangerousGetHandle()) < 2)
                    throw new CryptographicException("The security key did not return a FIDO2 credential.");
                CredentialAttestation oAttestation = Marshal.PtrToStructure<CredentialAttestation>(
                    oResult.DangerousGetHandle());
                bool bHmacSecret = false;
                for (int nIndex = 0; nIndex < oAttestation.Extensions.Count; nIndex++)
                {
                    Extension oValue = Marshal.PtrToStructure<Extension>(IntPtr.Add(
                        oAttestation.Extensions.Values, nIndex * Marshal.SizeOf<Extension>()));
                    if (Marshal.PtrToStringUni(oValue.Identifier) == "hmac-secret" &&
                        oValue.Length == sizeof(int) && oValue.Value != IntPtr.Zero)
                        bHmacSecret = Marshal.ReadInt32(oValue.Value) != 0;
                }
                if (!bHmacSecret)
                    throw new CryptographicException(
                        "This security key does not support FIDO2 hmac-secret encryption.");
                ValidateAuthenticatorData(oAttestation.AuthenticatorData, oAttestation.AuthenticatorDataLength);
                return CopyCredential(oAttestation.CredentialId, oAttestation.CredentialIdLength);
            }
        }

        internal static FidoKeyAccess Open(IntPtr hOwner, byte[] oCredentialId, byte[] oSalt)
        {
            if (!IsAvailable)
                throw new PlatformNotSupportedException(
                    "FIDO2 encryption requires Windows WebAuthn hmac-secret support.");
            if (oCredentialId == null || oCredentialId.Length is < 1 or > FidoKeyProtection.MaxCredentialIdBytes ||
                oSalt?.Length != FidoKeyProtection.SaltBytes)
                throw new CryptographicException("The saved FIDO2 credential is invalid.");

            // Ask Windows for the credential's verified hmac-secret output for this item's random salt.
            using NativeBuffer oId = new NativeBuffer(oCredentialId);
            using NativeBuffer oCredentialType = new NativeBuffer(Encoding.Unicode.GetBytes("public-key\0"));
            using NativeBuffer oCredential = NativeBuffer.From(new Credential
            {
                Version = 1, IdLength = oId.Length, Id = oId.DangerousGetHandle(),
                Type = oCredentialType.DangerousGetHandle()
            });
            using NativeBuffer oSaltData = new NativeBuffer(oSalt);
            using NativeBuffer oHmacSalt = NativeBuffer.From(new HmacSecret
            {
                FirstLength = oSaltData.Length, First = oSaltData.DangerousGetHandle()
            });
            using NativeBuffer oHmacValues = NativeBuffer.From(new HmacSaltValues
            {
                GlobalSalt = oHmacSalt.DangerousGetHandle()
            });
            using NativeBuffer oJson = new NativeBuffer(ClientDataJson("webauthn.get"));
            ClientData oClient = new ClientData
            {
                Version = 1, Length = oJson.Length, Json = oJson.DangerousGetHandle(), HashAlgorithm = "SHA-256"
            };
            GetAssertionOptions oOptions = new GetAssertionOptions
            {
                Version = 6, Timeout = TimeoutMilliseconds,
                Credentials = new Credentials { Count = 1, Values = oCredential.DangerousGetHandle() },
                Attachment = CrossPlatformAttachment, Verification = RequiredVerification,
                Flags = RawHmacSecretFlag, HmacSaltValues = oHmacValues.DangerousGetHandle()
            };
            int nStatus = WebAuthNAuthenticatorGetAssertion(hOwner, RelyingPartyId, ref oClient,
                ref oOptions, out AssertionHandle oResult);
            using (oResult)
            {
                ThrowIfFailed(nStatus);
                if (oResult.IsInvalid || Marshal.ReadInt32(oResult.DangerousGetHandle()) < 3)
                    throw new CryptographicException("The security key did not return an encryption secret.");
                Assertion oAssertion = Marshal.PtrToStructure<Assertion>(oResult.DangerousGetHandle());
                if (oAssertion.HmacSecret == IntPtr.Zero)
                    throw new CryptographicException(
                        "This security key does not support FIDO2 hmac-secret encryption.");
                HmacSecret oSecret = Marshal.PtrToStructure<HmacSecret>(oAssertion.HmacSecret);
                if (oSecret.FirstLength == FidoKeyProtection.SecretBytes && oSecret.First != IntPtr.Zero)
                    oResult.Secret = oSecret.First;
                if (oSecret.FirstLength != FidoKeyProtection.SecretBytes || oSecret.First == IntPtr.Zero ||
                    oSecret.SecondLength != 0)
                    throw new CryptographicException("The security key returned an invalid encryption secret.");
                ValidateAuthenticatorData(oAssertion.AuthenticatorData, oAssertion.AuthenticatorDataLength);
                if (!oCredentialId.AsSpan().SequenceEqual(CopyCredential(
                    oAssertion.Credential.Id, oAssertion.Credential.IdLength)))
                    throw new CryptographicException("The security key returned a different credential.");
                byte[] oOutput = new byte[FidoKeyProtection.SecretBytes];
                Marshal.Copy(oSecret.First, oOutput, 0, oOutput.Length);
                return new FidoKeyAccess(oCredentialId, oSalt, oOutput);
            }
        }

        private static byte[] ClientDataJson(string sType) => JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = sType,
            challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            origin = "https://" + RelyingPartyId,
            crossOrigin = false
        });

        private static byte[] CopyCredential(IntPtr pId, int nLength)
        {
            if (pId == IntPtr.Zero || nLength is < 1 or > FidoKeyProtection.MaxCredentialIdBytes)
                throw new CryptographicException("The security key returned an invalid credential identifier.");
            byte[] oId = new byte[nLength];
            Marshal.Copy(pId, oId, 0, nLength);
            return oId;
        }

        private static void ValidateAuthenticatorData(IntPtr pData, int nLength)
        {
            if (pData == IntPtr.Zero || nLength < AuthenticatorDataMinimumBytes ||
                (Marshal.ReadByte(pData, AuthenticatorFlagsOffset) & PresenceAndVerificationFlags) !=
                    PresenceAndVerificationFlags)
                throw new CryptographicException("The security key did not verify its user.");
            byte[] oRpHash = new byte[32];
            Marshal.Copy(pData, oRpHash, 0, oRpHash.Length);
            if (!CryptographicOperations.FixedTimeEquals(oRpHash,
                SHA256.HashData(Encoding.UTF8.GetBytes(RelyingPartyId))))
                throw new CryptographicException("The security key returned an invalid relying party.");
        }

        private static void ThrowIfFailed(int nStatus)
        {
            if (nStatus == 0) return;
            if ((uint)nStatus is 0x800704C7 or 0x80090036 ||
                Marshal.PtrToStringUni(WebAuthNGetErrorName(nStatus)) == "NotAllowedError")
                throw new OperationCanceledException("The security key operation was cancelled or timed out.");
            throw new CryptographicException("Windows could not use the FIDO2 security key. " +
                new Win32Exception(nStatus).Message + " (0x" + nStatus.ToString("X8") + "). " +
                "Connect a FIDO2 key supporting hmac-secret and complete its PIN and touch prompts.");
        }

        // Own native inputs and results for the entire blocking WebAuthn call.
        private sealed class NativeBuffer : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal int Length { get; }
            internal NativeBuffer(byte[] oData) : base(true)
            {
                Length = oData.Length;
                SetHandle(Marshal.AllocHGlobal(Length));
                Marshal.Copy(oData, 0, handle, Length);
            }

            internal static NativeBuffer From<T>(T oValue) where T : unmanaged
            {
                NativeBuffer oBuffer = new NativeBuffer(new byte[Marshal.SizeOf<T>()]);
                Marshal.StructureToPtr(oValue, oBuffer.handle, false);
                return oBuffer;
            }

            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(handle);
                return true;
            }
        }

        private sealed class AttestationHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public AttestationHandle() : base(true) { }
            protected override bool ReleaseHandle()
            {
                WebAuthNFreeCredentialAttestation(handle);
                return true;
            }
        }

        private sealed class AssertionHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal IntPtr Secret { get; set; }
            public AssertionHandle() : base(true) { }
            protected override bool ReleaseHandle()
            {
                if (Secret != IntPtr.Zero)
                    Marshal.Copy(new byte[FidoKeyProtection.SecretBytes], 0, Secret, FidoKeyProtection.SecretBytes);
                WebAuthNFreeAssertion(handle);
                return true;
            }
        }

        // Structure prefixes match the native API versions used for credential creation and hmac-secret assertions.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RelyingParty
        {
            internal int Version;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Id;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Name;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Icon;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct UserEntity
        {
            internal int Version, IdLength;
            internal IntPtr Id;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Name;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Icon;
            [MarshalAs(UnmanagedType.LPWStr)] internal string DisplayName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ClientData
        {
            internal int Version, Length;
            internal IntPtr Json;
            [MarshalAs(UnmanagedType.LPWStr)] internal string HashAlgorithm;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CredentialParameter
        {
            internal int Version;
            internal IntPtr Type;
            internal int Algorithm;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CredentialParameters
        {
            internal int Count;
            internal IntPtr Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Credential
        {
            internal int Version, IdLength;
            internal IntPtr Id, Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Credentials
        {
            internal int Count;
            internal IntPtr Values;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Extension
        {
            internal IntPtr Identifier;
            internal int Length;
            internal IntPtr Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Extensions
        {
            internal int Count;
            internal IntPtr Values;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MakeCredentialOptions
        {
            internal int Version, Timeout;
            internal Credentials Credentials;
            internal Extensions Extensions;
            internal int Attachment, RequireResidentKey, Verification, Attestation, Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GetAssertionOptions
        {
            internal int Version, Timeout;
            internal Credentials Credentials;
            internal Extensions Extensions;
            internal int Attachment, Verification, Flags;
            internal IntPtr U2fAppId, U2fAppIdUsed, CancellationId, AllowCredentials;
            internal int LargeBlobOperation, LargeBlobLength;
            internal IntPtr LargeBlob, HmacSaltValues;
            internal int PrivateMode;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct HmacSecret
        {
            internal int FirstLength;
            internal IntPtr First;
            internal int SecondLength;
            internal IntPtr Second;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct HmacSaltValues
        {
            internal IntPtr GlobalSalt;
            internal int CredentialCount;
            internal IntPtr CredentialSalts;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CredentialAttestation
        {
            internal int Version;
            internal IntPtr Format;
            internal int AuthenticatorDataLength;
            internal IntPtr AuthenticatorData;
            internal int AttestationLength;
            internal IntPtr Attestation;
            internal int DecodeType;
            internal IntPtr DecodedAttestation;
            internal int AttestationObjectLength;
            internal IntPtr AttestationObject;
            internal int CredentialIdLength;
            internal IntPtr CredentialId;
            internal Extensions Extensions;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Assertion
        {
            internal int Version, AuthenticatorDataLength;
            internal IntPtr AuthenticatorData;
            internal int SignatureLength;
            internal IntPtr Signature;
            internal Credential Credential;
            internal int UserIdLength;
            internal IntPtr UserId;
            internal Extensions Extensions;
            internal int LargeBlobLength;
            internal IntPtr LargeBlob;
            internal int LargeBlobStatus;
            internal IntPtr HmacSecret;
        }

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", ExactSpelling = true)]
        private static extern int WebAuthNGetApiVersionNumber();

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", ExactSpelling = true)]
        private static extern int WebAuthNAuthenticatorMakeCredential(IntPtr hWnd,
            ref RelyingParty pRpInformation, ref UserEntity pUserInformation,
            ref CredentialParameters pPubKeyCredParams, ref ClientData pWebAuthNClientData,
            ref MakeCredentialOptions pWebAuthNMakeCredentialOptions,
            out AttestationHandle ppWebAuthNCredentialAttestation);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int WebAuthNAuthenticatorGetAssertion(IntPtr hWnd, string pwszRpId,
            ref ClientData pWebAuthNClientData, ref GetAssertionOptions pWebAuthNGetAssertionOptions,
            out AssertionHandle ppWebAuthNAssertion);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", ExactSpelling = true)]
        private static extern void WebAuthNFreeCredentialAttestation(IntPtr pWebAuthNCredentialAttestation);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", ExactSpelling = true)]
        private static extern void WebAuthNFreeAssertion(IntPtr pWebAuthNAssertion);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", ExactSpelling = true)]
        private static extern IntPtr WebAuthNGetErrorName(int hr);
    }
}
