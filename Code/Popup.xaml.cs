using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;

namespace Crypture
{
    internal sealed partial class Popup : ThemedWindow
    {
        private readonly MessageBoxButton oButtonSet;
        private MessageBoxResult oResult;

        internal Popup(string sText, string sCaption, MessageBoxButton oButtonSet = MessageBoxButton.OK,
            MessageBoxImage oImage = MessageBoxImage.None, MessageBoxResult oDefault = MessageBoxResult.None)
        {
            this.oButtonSet = oButtonSet;
            InitializeComponent();
            Title = sCaption;
            oMessage.Text = sText;
            Width = Math.Min(Width, SystemParameters.WorkArea.Width * 0.9);
            MaxHeight = SystemParameters.WorkArea.Height * 0.8;

            // Keep standard message-box choices, default buttons, and access keys.
            MessageBoxResult[] oChoices = oButtonSet switch
            {
                MessageBoxButton.OK => [MessageBoxResult.OK],
                MessageBoxButton.OKCancel => [MessageBoxResult.OK, MessageBoxResult.Cancel],
                MessageBoxButton.YesNo => [MessageBoxResult.Yes, MessageBoxResult.No],
                MessageBoxButton.YesNoCancel => [MessageBoxResult.Yes, MessageBoxResult.No, MessageBoxResult.Cancel],
                _ => throw new ArgumentOutOfRangeException(nameof(oButtonSet))
            };
            if (!oChoices.Contains(oDefault)) oDefault = oChoices[0];
            foreach (MessageBoxResult oChoice in oChoices)
            {
                Button oButton = new Button
                {
                    Content = oChoice == MessageBoxResult.OK ? "_OK" : "_" + oChoice,
                    Tag = oChoice, IsDefault = oChoice == oDefault,
                    MinWidth = 84, Padding = new Thickness(16, 6, 16, 6),
                    Margin = new Thickness(8, 4, 0, 4)
                };
                oButton.Click += (s, e) =>
                {
                    oResult = oChoice;
                    Close();
                };
                oButtons.Children.Add(oButton);
                if (oButton.IsDefault) Loaded += (s, e) => oButton.Focus();
            }

            // Use the application's scalable glyphs and theme colors for message severity.
            oIcon.Text = oImage switch
            {
                MessageBoxImage.Error => "\uEA39",
                MessageBoxImage.Question => "\uE897",
                MessageBoxImage.Warning => "\uE7BA",
                MessageBoxImage.Information => "\uE946",
                _ => ""
            };
            oIcon.Visibility = oIcon.Text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
            if (oImage is MessageBoxImage.Error or MessageBoxImage.Warning)
                oIcon.SetResourceReference(ForegroundProperty, "Crypture.WarningBrush");
        }

        internal static MessageBoxResult Show(string sText, string sCaption,
            MessageBoxButton oButtons = MessageBoxButton.OK, MessageBoxImage oImage = MessageBoxImage.None,
            MessageBoxResult oDefault = MessageBoxResult.None) => Show(null, sText, sCaption, oButtons, oImage, oDefault);

        internal static MessageBoxResult Show(Window oOwner, string sText, string sCaption,
            MessageBoxButton oButtons = MessageBoxButton.OK, MessageBoxImage oImage = MessageBoxImage.None,
            MessageBoxResult oDefault = MessageBoxResult.None)
        {
            Popup oPopup = new Popup(sText, sCaption, oButtons, oImage, oDefault);
            oOwner = oOwner?.IsVisible == true ? oOwner : Application.Current.Windows.Cast<Window>()
                .FirstOrDefault(oWindow => oWindow.IsActive);
            if (oOwner != null) oPopup.Owner = oOwner;
            else oPopup.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            oPopup.ShowDialog();
            return oPopup.oResult;
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            // Yes/No prompts require an explicit choice, matching the native message box.
            const uint CloseCommand = 0xF060;
            const uint MenuGrayed = 1;
            if (oButtonSet == MessageBoxButton.YesNo)
                EnableMenuItem(GetSystemMenu(new WindowInteropHelper(this).Handle, false), CloseCommand, MenuGrayed);
            base.OnSourceInitialized(e);
        }

        protected override void OnPreviewKeyDown(KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                e.Handled = true;
                if (oButtonSet != MessageBoxButton.YesNo) Close();
            }
            base.OnPreviewKeyDown(e);
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            if (oResult == MessageBoxResult.None)
            {
                if (oButtonSet == MessageBoxButton.YesNo) e.Cancel = true;
                else oResult = oButtonSet == MessageBoxButton.OK ? MessageBoxResult.OK : MessageBoxResult.Cancel;
            }
            base.OnClosing(e);
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetSystemMenu(IntPtr hWindow, [MarshalAs(UnmanagedType.Bool)] bool bRevert);

        [DllImport("user32.dll")]
        private static extern uint EnableMenuItem(IntPtr hMenu, uint nItem, uint nFlags);
    }
}
