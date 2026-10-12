using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Crypture
{
    public sealed class PasswordOptions
    {
        private const int LengthLimit = 1024;
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

        internal static PasswordOptions LoadPreferences()
        {
            // Read a fresh user snapshot when opening the generator.
            Properties.Settings oSettings = new Properties.Settings();
            PasswordOptions oOptions = oSettings.PasswordGeneratorOptions ?? ReadDefaults();
            oOptions.GetCharacterGroups();
            return oOptions;
        }

        internal static void SavePreferences(PasswordOptions oOptions)
        {
            oOptions.GetCharacterGroups();

            // Save the complete selection without overwriting unrelated preferences cached by the main window.
            Properties.Settings oSettings = new Properties.Settings();
            oSettings.PasswordGeneratorOptions = oOptions;
            oSettings.Save();
        }

        internal static PasswordOptions ReadDefaults()
        {
            // Read the adjacent configuration when the user has no saved generator preferences.
            ConfigurationDefaults oDefaults = new ConfigurationDefaults("PasswordGenerator");

            // Preserve built-in defaults for omitted keys and validate the complete character policy.
            PasswordOptions oOptions = new PasswordOptions();
            oOptions.MinimumLength = oDefaults.Number(nameof(MinimumLength), oOptions.MinimumLength, 1, LengthLimit);
            oOptions.MaximumLength = oDefaults.Number(nameof(MaximumLength), oOptions.MaximumLength, 1, LengthLimit);
            oOptions.IncludeUppercase = oDefaults.Flag(nameof(IncludeUppercase), oOptions.IncludeUppercase);
            oOptions.IncludeLowercase = oDefaults.Flag(nameof(IncludeLowercase), oOptions.IncludeLowercase);
            oOptions.IncludeDigits = oDefaults.Flag(nameof(IncludeDigits), oOptions.IncludeDigits);
            oOptions.IncludeSymbols = oDefaults.Flag(nameof(IncludeSymbols), oOptions.IncludeSymbols);
            oOptions.SymbolCharacters = oDefaults.Text(nameof(SymbolCharacters), oOptions.SymbolCharacters);
            oOptions.ExcludedCharacters = oDefaults.Text(nameof(ExcludedCharacters), oOptions.ExcludedCharacters);
            oOptions.ExcludeSimilar = oDefaults.Flag(nameof(ExcludeSimilar), oOptions.ExcludeSimilar);
            oOptions.RequireEachType = oDefaults.Flag(nameof(RequireEachType), oOptions.RequireEachType);
            try
            {
                oOptions.GetCharacterGroups();
            }
            catch (InvalidOperationException oError)
            {
                throw oDefaults.Error(oError.Message);
            }
            return oOptions;
        }

        internal List<string> GetCharacterGroups()
        {
            const int MaximumSymbolCharacters = 94;
            const int MaximumExcludedCharacters = 256;
            if (MinimumLength < 1 || MaximumLength > LengthLimit || MinimumLength > MaximumLength)
                throw new InvalidOperationException(
                    "Lengths must be between 1 and 1024, with minimum at most maximum.");
            if (SymbolCharacters == null || ExcludedCharacters == null ||
                SymbolCharacters.Length > MaximumSymbolCharacters ||
                ExcludedCharacters.Length > MaximumExcludedCharacters)
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
            char[] oPassword = new char[RandomNumberGenerator.GetInt32(
                oOptions.MinimumLength, oOptions.MaximumLength + 1)];
            try
            {
                // Reject whole candidates to keep valid passwords uniform at the chosen length.
                do
                {
                    for (int nIndex = 0; nIndex < oPassword.Length; nIndex++)
                        oPassword[nIndex] = sAlphabet[RandomNumberGenerator.GetInt32(sAlphabet.Length)];
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
}
