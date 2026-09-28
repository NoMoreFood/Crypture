using Microsoft.Win32;
using System;
using System.Collections;
using System.IO;
using System.Security;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;

namespace Crypture
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        internal static bool IsDarkMode { get; private set; }
        private static bool bThemeApplied;
        private static readonly ClipboardExpiration oClipboardExpiration = new ClipboardExpiration();

        static App()
        {
            EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent,
                new RoutedEventHandler((s, e) => ApplyTitleBarTheme((Window)s)));
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            ApplyThemePreference();
            base.OnStartup(e);
        }

        internal static void CopyProtectedText(string sText)
        {
            Clipboard.SetText(sText);
            oClipboardExpiration.TrackCopy();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            oClipboardExpiration.Dispose();
            base.OnExit(e);
        }

        private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            Application oApplication = Current;
            if (oApplication == null || oApplication.Dispatcher.HasShutdownStarted) return;
            oApplication.Dispatcher.BeginInvoke(new Action(() =>
            {
                if (!oApplication.Dispatcher.HasShutdownStarted) ApplyThemePreference();
            }), DispatcherPriority.Background);
        }

        internal static void ApplyThemePreference()
        {
            string sMode = Crypture.Properties.Settings.Default.ThemeMode;
            bool bDark = sMode == "Dark";
            if (sMode != "Dark" && sMode != "Light")
            {
                try
                {
                    object oValue = Registry.GetValue(
                        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                        "AppsUseLightTheme", 1);
                    bDark = oValue is int nLight && nLight == 0;
                }
                catch (Exception oError) when (oError is IOException || oError is UnauthorizedAccessException ||
                    oError is SecurityException)
                {
                    bDark = false;
                }
            }
            if (!bThemeApplied || bDark != IsDarkMode) ApplyTheme(bDark);
        }

        internal static void ApplyTheme(bool bDark)
        {
            bThemeApplied = true;
            IsDarkMode = bDark;
            string sTheme = bDark ? "BaseDark" : "BaseLight";
            Fluent.ThemeManager.ChangeAppTheme(Current, sTheme);
            // Fluent 6.1 does not refresh existing controls when it adds a merged theme dictionary.
            foreach (DictionaryEntry oResource in Fluent.ThemeManager.GetAppTheme(sTheme).Resources)
                Current.Resources[oResource.Key] = oResource.Value;
            SetThemeBrush("Window", bDark ? "#1E1E1E" : "#FFFFFF");
            SetThemeBrush("Panel", bDark ? "#252526" : "#F6F8FB");
            SetThemeBrush("Control", bDark ? "#2D2D30" : "#FFFFFF");
            SetThemeBrush("Text", bDark ? "#F1F1F1" : "#17212F");
            SetThemeBrush("Muted", bDark ? "#B7BFCC" : "#475569");
            SetThemeBrush("Border", bDark ? "#50545D" : "#D6DEE8");
            SetThemeBrush("Hover", bDark ? "#353D47" : "#E8F2FE");
            SetThemeBrush("Selection", bDark ? "#264F78" : "#D7EAFE");
            SetThemeBrush("Accent", bDark ? "#76B9ED" : "#0F6CBD");
            SetThemeBrush("Disabled", bDark ? "#8993A2" : "#687582");
            SetThemeBrush("Warning", bDark ? "#FDBA74" : "#9A3412");
            foreach (Window oWindow in Current.Windows) ApplyTitleBarTheme(oWindow);
        }

        private static void SetThemeBrush(string sName, string sColor)
        {
            SolidColorBrush oBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(sColor));
            oBrush.Freeze();
            Current.Resources["Crypture." + sName + "Brush"] = oBrush;
        }

        private static void ApplyTitleBarTheme(Window oWindow)
        {
            IntPtr hWindow = new WindowInteropHelper(oWindow).Handle;
            if (hWindow == IntPtr.Zero) return;
            int nDark = IsDarkMode ? 1 : 0;
            int nCaption = IsDarkMode ? 0x001E1E1E : -1;
            int nText = IsDarkMode ? 0x00F1F1F1 : -1;
            DwmSetWindowAttribute(hWindow, 20, ref nDark, sizeof(int));
            DwmSetWindowAttribute(hWindow, 35, ref nCaption, sizeof(int));
            DwmSetWindowAttribute(hWindow, 36, ref nText, sizeof(int));
        }

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hWindow, int nAttribute, ref int nValue, int nSize);
    }
}
