using System;
using System.Configuration;
using System.IO;
using System.Security.Principal;
using System.Threading;
using System.Xml;

namespace Crypture.Properties
{
    [SettingsManageability(SettingsManageability.Roaming)]
    [SettingsProvider(typeof(RoamingSettingsProvider))]
    internal sealed partial class Settings
    {
        [UserScopedSetting]
        [SettingsSerializeAs(SettingsSerializeAs.Xml)]
        public PasswordOptions PasswordGeneratorOptions
        {
            get => (PasswordOptions)this[nameof(PasswordGeneratorOptions)];
            set => this[nameof(PasswordGeneratorOptions)] = value;
        }
    }

    public sealed class RoamingSettingsProvider : LocalFileSettingsProvider
    {
        public override SettingsPropertyValueCollection GetPropertyValues(SettingsContext oContext,
            SettingsPropertyCollection oProperties)
        {
            return WithPreferenceLock(() =>
            {
                // Read user preferences from the roaming profile and inherit application defaults.
                string sSection = (string)oContext["GroupName"];
                if (oContext["SettingsKey"] is string sKey && sKey.Length > 0) sSection += "." + sKey;
                sSection = XmlConvert.EncodeLocalName(sSection);
                Configuration oConfig = ConfigurationManager.OpenExeConfiguration(
                    ConfigurationUserLevel.PerUserRoaming);
                ClientSettingsSection oUser = (ClientSettingsSection)oConfig.GetSection("userSettings/" + sSection);
                ClientSettingsSection oApp =
                    (ClientSettingsSection)oConfig.GetSection("applicationSettings/" + sSection);
                SettingsPropertyValueCollection oValues = new SettingsPropertyValueCollection();
                foreach (SettingsProperty oProperty in oProperties)
                {
                    bool bUser = oProperty.Attributes[typeof(UserScopedSettingAttribute)] is UserScopedSettingAttribute;
                    SettingElement oStored = (bUser ? oUser : oApp)?.Settings.Get(oProperty.Name);
                    SettingsPropertyValue oValue = new SettingsPropertyValue(oProperty);
                    if (oStored != null)
                        oValue.SerializedValue = oStored.SerializeAs == SettingsSerializeAs.String
                            ? oStored.Value.ValueXml.InnerText : oStored.Value.ValueXml.InnerXml;
                    else if (oProperty.DefaultValue != null) oValue.SerializedValue = oProperty.DefaultValue;
                    else oValue.PropertyValue = null;
                    oValue.IsDirty = false;
                    oValues.Add(oValue);
                }
                return oValues;
            });
        }

        public override void SetPropertyValues(SettingsContext oContext, SettingsPropertyValueCollection oValues)
        {
            WithPreferenceLock(() =>
            {
                base.SetPropertyValues(oContext, oValues);

                // Keep user.config readable when the optional adjacent configuration is absent.
                Configuration oConfig = ConfigurationManager.OpenExeConfiguration(
                    ConfigurationUserLevel.PerUserRoaming);
                ConfigurationSectionGroup oGroup = oConfig.GetSectionGroup("userSettings");
                if (oGroup != null)
                {
                    oGroup.ForceDeclaration();
                    foreach (ConfigurationSection oSection in oGroup.Sections)
                        oSection.SectionInformation.ForceDeclaration();
                    oConfig.Save();
                }
                return true;
            });
        }

        private static T WithPreferenceLock<T>(Func<T> oOperation)
        {
            // Coordinate access to user.config across Crypture instances in this Windows session.
            using WindowsIdentity oIdentity = WindowsIdentity.GetCurrent();
            using Mutex oMutex = new Mutex(false, "Local\\Crypture.UserPreferences." + oIdentity.User.Value);
            bool bAcquired;
            try { bAcquired = oMutex.WaitOne(TimeSpan.FromSeconds(10)); }
            catch (AbandonedMutexException) { bAcquired = true; }
            if (!bAcquired) throw new IOException("User preferences are busy. Try again.");
            try { return oOperation(); }
            finally { oMutex.ReleaseMutex(); }
        }
    }
}
