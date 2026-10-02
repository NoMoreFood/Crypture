using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Crypture
{
    public sealed class PasswordOptions
    {
        public int MinimumLength { get; set; } = 20;
        public int MaximumLength { get; set; } = 24;
        public bool IncludeUppercase { get; set; } = true;
        public bool IncludeLowercase { get; set; } = true;
        public bool IncludeDigits { get; set; } = true;
        public bool IncludeSymbols { get; set; } = true;
        public string SymbolCharacters { get; set; } = "!@#$%^&*()-_=+[]{}:,.?";
        public string ExcludedCharacters { get; set; } = "";
        public bool ExcludeSimilar { get; set; } = true;
        public bool RequireEachType { get; set; } = true;

        internal static PasswordOptions ReadDefaults()
        {
            // Read the adjacent configuration when opening a generator without saved Vault preferences.
            string sPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
            try
            {
                Configuration oConfig = ConfigurationManager.OpenMappedExeConfiguration(
                    new ExeConfigurationFileMap { ExeConfigFilename = sPath }, ConfigurationUserLevel.None);
                string Read(string sName, string sDefault) =>
                    oConfig.AppSettings.Settings["PasswordGenerator" + sName]?.Value ?? sDefault;

                int ReadNumber(string sName, int nDefault)
                {
                    if (Int32.TryParse(Read(sName, nDefault.ToString(CultureInfo.InvariantCulture)).Trim(),
                        NumberStyles.None, CultureInfo.InvariantCulture, out int nValue)) return nValue;
                    throw new InvalidOperationException("PasswordGenerator" + sName + " must be a whole number.");
                }

                bool ReadFlag(string sName, bool bDefault)
                {
                    if (Boolean.TryParse(Read(sName, bDefault.ToString()), out bool bValue)) return bValue;
                    throw new InvalidOperationException("PasswordGenerator" + sName + " must be True or False.");
                }

                // Preserve built-in defaults for omitted keys and validate the complete character policy.
                PasswordOptions oOptions = new PasswordOptions();
                oOptions.MinimumLength = ReadNumber(nameof(MinimumLength), oOptions.MinimumLength);
                oOptions.MaximumLength = ReadNumber(nameof(MaximumLength), oOptions.MaximumLength);
                oOptions.IncludeUppercase = ReadFlag(nameof(IncludeUppercase), oOptions.IncludeUppercase);
                oOptions.IncludeLowercase = ReadFlag(nameof(IncludeLowercase), oOptions.IncludeLowercase);
                oOptions.IncludeDigits = ReadFlag(nameof(IncludeDigits), oOptions.IncludeDigits);
                oOptions.IncludeSymbols = ReadFlag(nameof(IncludeSymbols), oOptions.IncludeSymbols);
                oOptions.SymbolCharacters = Read(nameof(SymbolCharacters), oOptions.SymbolCharacters);
                oOptions.ExcludedCharacters = Read(nameof(ExcludedCharacters), oOptions.ExcludedCharacters);
                oOptions.ExcludeSimilar = ReadFlag(nameof(ExcludeSimilar), oOptions.ExcludeSimilar);
                oOptions.RequireEachType = ReadFlag(nameof(RequireEachType), oOptions.RequireEachType);
                oOptions.GetCharacterGroups();
                return oOptions;
            }
            catch (Exception oError) when (oError is ConfigurationErrorsException or InvalidOperationException)
            {
                throw new InvalidOperationException("Invalid password generator defaults in " + sPath + ": " +
                    oError.Message);
            }
        }

        internal List<string> GetCharacterGroups()
        {
            if (MinimumLength < 1 || MaximumLength > 1024 || MinimumLength > MaximumLength)
                throw new InvalidOperationException(
                    "Lengths must be between 1 and 1024, with minimum at most maximum.");
            if (SymbolCharacters == null || ExcludedCharacters == null ||
                SymbolCharacters.Length > 94 || ExcludedCharacters.Length > 256)
                throw new InvalidOperationException("The symbol or exclusion list is missing or too long.");
            if (IncludeSymbols && SymbolCharacters.Any(c => c < '!' || c > '~' || Char.IsLetterOrDigit(c)))
                throw new InvalidOperationException(
                    "Allowed symbols must be ASCII punctuation, without letters, digits, or spaces.");

            List<string> oGroups = new List<string>();
            if (IncludeUppercase) oGroups.Add("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            if (IncludeLowercase) oGroups.Add("abcdefghijklmnopqrstuvwxyz");
            if (IncludeDigits) oGroups.Add("0123456789");
            if (IncludeSymbols) oGroups.Add(SymbolCharacters);
            if (oGroups.Count == 0) throw new InvalidOperationException("Select at least one character type.");
            string sExcluded = ExcludedCharacters + (ExcludeSimilar ? "Il1O0o|" : "");
            oGroups = oGroups.Select(g => new string(g.Where(c => sExcluded.IndexOf(c) < 0).Distinct().ToArray()))
                .ToList();
            if (oGroups.Any(g => g.Length == 0))
                throw new InvalidOperationException(
                    "Each selected character type must have at least one allowed character.");
            if (RequireEachType && MinimumLength < oGroups.Count)
                throw new InvalidOperationException(
                    "Increase the minimum length to fit every selected character type.");
            return oGroups;
        }
    }

    internal static class PasswordGeneration
    {
        internal static string Generate(PasswordOptions oOptions)
        {
            List<string> oGroups = oOptions.GetCharacterGroups();
            string sAlphabet = String.Concat(oGroups);
            using (RandomNumberGenerator oRandom = RandomNumberGenerator.Create())
            {
                int nLength = oOptions.MinimumLength + NextInt(oRandom,
                    oOptions.MaximumLength - oOptions.MinimumLength + 1);
                char[] oPassword = new char[nLength];
                try
                {
                    // Reject whole candidates to keep valid passwords uniform at the chosen length.
                    do
                    {
                        for (int nIndex = 0; nIndex < oPassword.Length; nIndex++)
                            oPassword[nIndex] = sAlphabet[NextInt(oRandom, sAlphabet.Length)];
                    }
                    while (oOptions.RequireEachType && oGroups.Any(g => !oPassword.Any(c => g.IndexOf(c) >= 0)));
                    return new string(oPassword);
                }
                finally
                {
                    Array.Clear(oPassword, 0, oPassword.Length);
                }
            }
        }

        internal static int NextInt(RandomNumberGenerator oRandom, int nExclusiveMaximum)
        {
            if (nExclusiveMaximum < 1) throw new ArgumentOutOfRangeException(nameof(nExclusiveMaximum));
            byte[] oBytes = new byte[4];
            try
            {
                ulong nRange = 1UL << 32;
                ulong nLimit = nRange - nRange % (uint)nExclusiveMaximum;
                uint nValue;
                // Discard the incomplete interval so remainder arithmetic does not favor any choice.
                do
                {
                    oRandom.GetBytes(oBytes);
                    nValue = BitConverter.ToUInt32(oBytes, 0);
                }
                while (nValue >= nLimit);
                return (int)(nValue % (uint)nExclusiveMaximum);
            }
            finally
            {
                Array.Clear(oBytes, 0, oBytes.Length);
            }
        }
    }
}
