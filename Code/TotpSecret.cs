using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;

namespace Crypture
{
    internal sealed class TotpSecret : IDisposable
    {
        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private byte[] oKey;
        internal string Issuer { get; }
        internal string Account { get; }
        internal string Algorithm { get; }
        internal int Digits { get; }
        internal int Period { get; }

        internal TotpSecret(string sSecret, string sIssuer = "", string sAccount = "", string sAlgorithm = "SHA1",
            int nDigits = 6, int nPeriod = 30)
        {
            Issuer = (sIssuer ?? "").Trim();
            Account = (sAccount ?? "").Trim();
            Algorithm = (sAlgorithm ?? "").ToUpperInvariant();
            Digits = nDigits;
            Period = nPeriod;
            if (Algorithm is not ("SHA1" or "SHA256" or "SHA512") || Digits is not (6 or 8) ||
                Period < 1 || Period > 3600)
                throw new InvalidOperationException("Choose SHA-1, SHA-256, or SHA-512, 6 or 8 digits, " +
                    "and a rotation period between 1 and 3600 seconds.");
            if (Issuer.Length > 256 || Account.Length > 256 || Issuer.Contains(':') || Account.Contains(':') ||
                Issuer.Any(Char.IsControl) || Account.Any(Char.IsControl))
                throw new InvalidOperationException("Issuer and account names must be at most 256 characters " +
                    "and cannot contain colons or control characters.");
            oKey = DecodeBase32(sSecret);
        }

        internal static TotpSecret Parse(string sInput)
        {
            if (String.IsNullOrWhiteSpace(sInput) || sInput.Length > 4096)
                throw new InvalidOperationException("Enter a Base32 secret or a TOTP setup link.");
            sInput = sInput.Trim();
            if (!sInput.StartsWith("otpauth:", StringComparison.OrdinalIgnoreCase)) return new TotpSecret(sInput);
            if (!Uri.TryCreate(sInput, UriKind.Absolute, out Uri oUri) || oUri.Scheme != "otpauth" ||
                oUri.Host != "totp" || oUri.UserInfo.Length != 0 || oUri.Port != -1 || oUri.Fragment.Length != 0)
                throw new InvalidOperationException("Use an otpauth://totp/ setup link. " +
                    "Counter-based HOTP is not supported.");

            // Decode label and query values independently so encoded separators remain part of each value.
            Dictionary<string, string> oParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string sPart in oUri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                string[] oPair = sPart.Split('=', 2);
                string sName = Uri.UnescapeDataString(oPair[0].Replace('+', ' '));
                string sValue = oPair.Length == 2 ? Uri.UnescapeDataString(oPair[1].Replace('+', ' ')) : "";
                if (!oParameters.TryAdd(sName, sValue))
                    throw new InvalidOperationException("The TOTP setup link contains duplicate parameters.");
            }
            string sLabel = Uri.UnescapeDataString(oUri.AbsolutePath.TrimStart('/')).Trim();
            string[] oLabel = sLabel.Split(':', 2);
            string sLabelIssuer = oLabel.Length == 2 ? oLabel[0].Trim() : "";
            string sAccount = oLabel[^1].Trim();
            string sIssuer = oParameters.GetValueOrDefault("issuer", sLabelIssuer).Trim();
            if (sAccount.Length == 0 || oParameters.ContainsKey("counter") ||
                sLabelIssuer.Length != 0 && sLabelIssuer != sIssuer)
                throw new InvalidOperationException(
                    "The TOTP setup link has an invalid account or conflicting issuer.");
            if (!Int32.TryParse(oParameters.GetValueOrDefault("digits", "6"), NumberStyles.None,
                CultureInfo.InvariantCulture, out int nDigits) ||
                !Int32.TryParse(oParameters.GetValueOrDefault("period", "30"), NumberStyles.None,
                    CultureInfo.InvariantCulture, out int nPeriod))
                throw new InvalidOperationException("The TOTP digit count and rotation period must be whole numbers.");
            return new TotpSecret(oParameters.GetValueOrDefault("secret", ""), sIssuer, sAccount,
                oParameters.GetValueOrDefault("algorithm", "SHA1"), nDigits, nPeriod);
        }

        internal string GetBase32()
        {
            ObjectDisposedException.ThrowIf(oKey == null, this);
            return EncodeBase32(oKey);
        }

        internal string ToUri()
        {
            string sLabel = Uri.EscapeDataString(Account.Length == 0 ? "Crypture" : Account);
            if (Issuer.Length != 0) sLabel = Uri.EscapeDataString(Issuer) + ":" + sLabel;
            return "otpauth://totp/" + sLabel + "?secret=" + GetBase32() +
                (Issuer.Length == 0 ? "" : "&issuer=" + Uri.EscapeDataString(Issuer)) +
                "&algorithm=" + Algorithm + "&digits=" + Digits.ToString(CultureInfo.InvariantCulture) +
                "&period=" + Period.ToString(CultureInfo.InvariantCulture);
        }

        internal string GetCode(DateTimeOffset oTime)
        {
            ObjectDisposedException.ThrowIf(oKey == null, this);
            long nSeconds = oTime.ToUnixTimeSeconds();
            if (nSeconds < 0) throw new InvalidOperationException("TOTP requires a date after the Unix epoch.");

            // RFC 6238 uses the current Unix time step as the big-endian HOTP counter.
            Span<byte> oCounter = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(oCounter, (ulong)(nSeconds / Period));
            byte[] oHash = Algorithm switch
            {
                "SHA256" => HMACSHA256.HashData(oKey, oCounter),
                "SHA512" => HMACSHA512.HashData(oKey, oCounter),
                _ => HMACSHA1.HashData(oKey, oCounter)
            };
            try
            {
                int nOffset = oHash[^1] & 15;
                uint nValue = BinaryPrimitives.ReadUInt32BigEndian(oHash.AsSpan(nOffset, 4)) & 0x7FFFFFFF;
                return (nValue % (Digits == 6 ? 1000000u : 100000000u))
                    .ToString(Digits == 6 ? "D6" : "D8", CultureInfo.InvariantCulture);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oHash);
            }
        }

        internal double SecondsRemaining(DateTimeOffset oTime)
        {
            long nMilliseconds = oTime.ToUnixTimeMilliseconds();
            if (nMilliseconds < 0) throw new InvalidOperationException("TOTP requires a date after the Unix epoch.");
            return (Period * 1000 - nMilliseconds % (Period * 1000)) / 1000.0;
        }

        internal static string Generate(string sAlgorithm)
        {
            byte[] oBytes = RandomNumberGenerator.GetBytes(sAlgorithm switch
            {
                "SHA256" => 32,
                "SHA512" => 64,
                _ => 20
            });
            try
            {
                return EncodeBase32(oBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oBytes);
            }
        }

        private static byte[] DecodeBase32(string sInput)
        {
            if (String.IsNullOrWhiteSpace(sInput) || sInput.Length > 512)
                throw new InvalidOperationException("Enter a Base32 secret containing 10 to 128 bytes.");
            string sValue = new string(sInput.Where(c => !Char.IsWhiteSpace(c) && c != '-')
                .Select(Char.ToUpperInvariant).ToArray());
            int nPadding = sValue.IndexOf('=');
            int nLength = nPadding < 0 ? sValue.Length : nPadding;
            int nBytes = nLength * 5 / 8;
            if (nBytes < 10 || nBytes > 128 || nLength % 8 is 1 or 3 or 6 ||
                nPadding >= 0 && (sValue.Length % 8 != 0 || sValue.Length - nLength != (8 - nLength % 8) % 8 ||
                    sValue.AsSpan(nLength).ContainsAnyExcept('=')))
                throw new InvalidOperationException("The Base32 secret has an invalid length or padding.");
            byte[] oBytes = new byte[nBytes];
            uint nBuffer = 0;
            int nBits = 0;
            int nIndex = 0;
            try
            {
                for (int nCharacter = 0; nCharacter < nLength; nCharacter++)
                {
                    int nDigit = Alphabet.IndexOf(sValue[nCharacter]);
                    if (nDigit < 0) throw new InvalidOperationException("Base32 secrets use only A-Z and 2-7.");
                    nBuffer = (nBuffer << 5) | (uint)nDigit;
                    nBits += 5;
                    if (nBits < 8) continue;
                    nBits -= 8;
                    oBytes[nIndex++] = (byte)(nBuffer >> nBits);
                }
                if ((nBuffer & ((1u << nBits) - 1)) != 0)
                    throw new InvalidOperationException("The Base32 secret has invalid trailing bits.");
                return oBytes;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(oBytes);
                throw;
            }
        }

        private static string EncodeBase32(ReadOnlySpan<byte> oBytes)
        {
            char[] oCharacters = new char[(oBytes.Length * 8 + 4) / 5];
            uint nBuffer = 0;
            int nBits = 0;
            int nIndex = 0;
            foreach (byte nByte in oBytes)
            {
                nBuffer = (nBuffer << 8) | nByte;
                nBits += 8;
                while (nBits >= 5)
                {
                    nBits -= 5;
                    oCharacters[nIndex++] = Alphabet[(int)(nBuffer >> nBits) & 31];
                }
            }
            if (nBits != 0) oCharacters[nIndex] = Alphabet[(int)(nBuffer << (5 - nBits)) & 31];
            return new string(oCharacters);
        }

        public void Dispose()
        {
            if (oKey == null) return;
            CryptographicOperations.ZeroMemory(oKey);
            oKey = null;
        }
    }
}
