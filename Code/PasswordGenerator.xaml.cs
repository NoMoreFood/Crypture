using System;
using System.Globalization;
using System.Windows;
using System.Windows.Input;

namespace Crypture
{
    public partial class PasswordGenerator : ThemedWindow
    {
        public string SelectedPassword { get; private set; }
        private bool bLoading = true;

        public PasswordGenerator(bool bInsertIntoItem = false)
        {
            InitializeComponent();
            Utilities.EnableClipboardTimeout(oGeneratedPassword);
            PasswordOptions oOptions = PasswordOptions.LoadPreferences();
            oMinimumLength.Text = oOptions.MinimumLength.ToString(CultureInfo.InvariantCulture);
            oMaximumLength.Text = oOptions.MaximumLength.ToString(CultureInfo.InvariantCulture);
            oUppercase.IsChecked = oOptions.IncludeUppercase;
            oLowercase.IsChecked = oOptions.IncludeLowercase;
            oDigits.IsChecked = oOptions.IncludeDigits;
            oSymbols.IsChecked = oOptions.IncludeSymbols;
            oSymbolCharacters.Text = oOptions.SymbolCharacters;
            oExcludedCharacters.Text = oOptions.ExcludedCharacters;
            oExcludeSimilar.IsChecked = oOptions.ExcludeSimilar;
            oRequireEachType.IsChecked = oOptions.RequireEachType;
            oInsertButton.Visibility = bInsertIntoItem ? Visibility.Visible : Visibility.Collapsed;
            bLoading = false;
            oOptionsChanged(null, null);
        }

        private PasswordOptions ReadOptions()
        {
            if (!Int32.TryParse(oMinimumLength.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int nMin) ||
                !Int32.TryParse(oMaximumLength.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int nMax))
                throw new InvalidOperationException("Enter whole numbers for both lengths.");
            PasswordOptions oOptions = new PasswordOptions
            {
                MinimumLength = nMin, MaximumLength = nMax,
                IncludeUppercase = oUppercase.IsChecked == true, IncludeLowercase = oLowercase.IsChecked == true,
                IncludeDigits = oDigits.IsChecked == true, IncludeSymbols = oSymbols.IsChecked == true,
                SymbolCharacters = oSymbolCharacters.Text, ExcludedCharacters = oExcludedCharacters.Text,
                ExcludeSimilar = oExcludeSimilar.IsChecked == true, RequireEachType = oRequireEachType.IsChecked == true
            };
            oOptions.GetCharacterGroups();
            return oOptions;
        }

        private void oOptionsChanged(object sender, RoutedEventArgs e)
        {
            if (bLoading) return;
            oGeneratedPassword.Clear();
            oCopyButton.IsEnabled = false;
            oInsertButton.IsEnabled = false;
            oPasswordStatus.Text = "Uses Windows cryptographic randomness.";
            try
            {
                ReadOptions();
                oValidationMessage.Text = "";
                oGenerateButton.IsEnabled = true;
            }
            catch (InvalidOperationException oError)
            {
                oValidationMessage.Text = oError.Message;
                oGenerateButton.IsEnabled = false;
            }
        }

        private void oGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            oGeneratedPassword.Clear();
            oCopyButton.IsEnabled = false;
            oInsertButton.IsEnabled = false;
            Utilities.TryOperation(this, () =>
            {
                PasswordOptions oOptions = ReadOptions();
                string sPassword = PasswordGeneration.Generate(oOptions);
                PasswordOptions.SavePreferences(oOptions);
                oGeneratedPassword.Text = sPassword;
                oCopyButton.IsEnabled = true;
                oInsertButton.IsEnabled = true;
                oPasswordStatus.Text = sPassword.Length + " characters. " +
                    "Settings saved for your Windows user.";

                // Keep the generated password and copy action visible in small windows.
                oPasswordResult.UpdateLayout();
                oPasswordResult.BringIntoView();
            });
        }

        private void oCopyButton_Click(object sender, RoutedEventArgs e)
        {
            if (oGeneratedPassword.Text.Length == 0) return;
            Utilities.TryOperation(this, () =>
            {
                TimeSpan oTimeout = App.CopyProtectedText(oGeneratedPassword.Text);
                oPasswordStatus.Text = "Copied. Clipboard clears after " + oTimeout.TotalSeconds +
                    " seconds or when Crypture closes.";
            });
        }

        private void oInsertButton_Click(object sender, RoutedEventArgs e)
        {
            if (oGeneratedPassword.Text.Length == 0) return;
            SelectedPassword = oGeneratedPassword.Text;
            DialogResult = true;
        }

        internal void ConcealSecrets()
        {
            if (oGeneratedPassword.Text.Length == 0 || oPrivacyShield.Visibility == Visibility.Visible) return;

            // Keep a generated password available without leaving it visible after inactivity.
            oPrivacyShield.Visibility = Visibility.Visible;
            oGeneratorContent.IsEnabled = false;
            oGeneratorActions.IsEnabled = false;
            oGeneratorContent.Visibility = Visibility.Collapsed;
            oGeneratorActions.Visibility = Visibility.Collapsed;
            Keyboard.ClearFocus();
            oRevealButton.Focus();
        }

        private void oRevealButton_Click(object sender, RoutedEventArgs e)
        {
            oGeneratorContent.Visibility = Visibility.Visible;
            oGeneratorActions.Visibility = Visibility.Visible;
            oPrivacyShield.Visibility = Visibility.Collapsed;
            oGeneratorContent.IsEnabled = true;
            oGeneratorActions.IsEnabled = true;
            oGeneratedPassword.Focus();
        }

        private void oWindow_Closed(object sender, EventArgs e)
        {
            oGeneratedPassword.Clear();
        }
    }
}
