using System;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;

namespace Crypture
{
    internal sealed class ConfigurationDefaults
    {
        private static readonly string ConfigPath = Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config");
        private readonly KeyValueConfigurationCollection oSettings;
        private readonly string sPrefix;

        internal ConfigurationDefaults(string sPrefix = "")
        {
            this.sPrefix = sPrefix;

            // Read a fresh snapshot so newly opened tools see edits to the adjacent configuration.
            try
            {
                oSettings = ConfigurationManager.OpenMappedExeConfiguration(
                    new ExeConfigurationFileMap { ExeConfigFilename = ConfigPath }, ConfigurationUserLevel.None)
                    .AppSettings.Settings;
            }
            catch (ConfigurationErrorsException oError)
            {
                throw Error(oError.Message);
            }
        }

        internal string Text(string sName, string sDefault) => oSettings[sPrefix + sName]?.Value ?? sDefault;

        internal bool Flag(string sName, bool bDefault)
        {
            if (Boolean.TryParse(Text(sName, bDefault.ToString()), out bool bValue)) return bValue;
            throw Error(sPrefix + sName + " must be True or False.");
        }

        internal int Number(string sName, int nDefault, int nMinimum, int nMaximum)
        {
            if (Int32.TryParse(Text(sName, nDefault.ToString(CultureInfo.InvariantCulture)).Trim(),
                NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int nValue) &&
                nValue >= nMinimum && nValue <= nMaximum) return nValue;
            throw Error(sPrefix + sName + " must be a whole number between " + nMinimum + " and " + nMaximum + ".");
        }

        internal string Choice(string sName, string sDefault, params string[] oChoices)
        {
            string sValue = Text(sName, sDefault).Trim();
            return oChoices.FirstOrDefault(s => s.Equals(sValue, StringComparison.OrdinalIgnoreCase)) ??
                throw Error(sPrefix + sName + " must be one of: " + String.Join(", ", oChoices) + ".");
        }

        internal InvalidOperationException Error(string sMessage) =>
            new InvalidOperationException("Invalid defaults in " + ConfigPath + ": " + sMessage);
    }
}
