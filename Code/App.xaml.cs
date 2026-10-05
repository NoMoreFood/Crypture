using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Input;
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
        private DispatcherTimer oPrivacyTimer;
        private DateTime oLastActivityUtc;
        internal const string ClipboardExclusionFormat = "ExcludeClipboardContentFromMonitorProcessing";
        internal static TimeSpan PrivacyIdleTimeout => TimeSpan.FromMinutes(
            new ConfigurationDefaults().Number("AutoConcealIdleMinutes", 10, 0, 1440));

        static App()
        {
            CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.GetCultureInfo("en-US");
            AppContext.SetData("APP_CONFIG_FILE", Path.Combine(AppContext.BaseDirectory, "Crypture.exe.config"));
            EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent,
                new RoutedEventHandler((s, e) => ApplyTitleBarTheme((Window)s)));
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            base.OnStartup(e);

            // Surface invalid startup defaults before opening the main window.
            try
            {
                TimeSpan oIdleTimeout = PrivacyIdleTimeout;
                ApplyThemePreference();
                MainWindow = new ItemBrowser();
                MainWindow.Show();

                // Conceal secrets after Crypture inactivity or a Windows session disconnect.
                SystemEvents.SessionSwitch += OnSessionSwitch;
                if (oIdleTimeout > TimeSpan.Zero)
                {
                    TimeSpan oPrivacyCheckInterval = TimeSpan.FromSeconds(15);
                    oLastActivityUtc = DateTime.UtcNow;
                    InputManager.Current.PreProcessInput += OnInput;
                    oPrivacyTimer = new DispatcherTimer(oPrivacyCheckInterval, DispatcherPriority.Background,
                        (s, args) =>
                        {
                            if (DateTime.UtcNow - oLastActivityUtc >= oIdleTimeout) ConcealOpenSecrets();
                        }, Dispatcher);
                    oPrivacyTimer.Start();
                }
            }
            catch (Exception oError)
            {
                MessageBox.Show("Crypture could not start.\n\n" + oError.GetBaseException().Message,
                    "Crypture", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
            }
        }

        private void oImage_Loaded(object sender, RoutedEventArgs e)
        {
            // Ribbon templates force nearest-neighbor scaling; override it after the image loads.
            RenderOptions.SetBitmapScalingMode((Image)sender, BitmapScalingMode.HighQuality);
        }

        internal static TimeSpan CopyProtectedText(string sText)
        {
            // Validate the timeout before placing any secret on the clipboard.
            TimeSpan oTimeout = ClipboardExpiration.Timeout;
            Clipboard.SetDataObject(CreateProtectedClipboardData(sText), true);
            oClipboardExpiration.TrackCopy(oTimeout);
            return oTimeout;
        }

        internal static DataObject CreateProtectedClipboardData(string sText)
        {
            DataObject oData = new DataObject();
            oData.SetText(sText);
            oData.SetData(DataFormats.GetDataFormat(ClipboardExclusionFormat).Name, new byte[] { 0 }, false);
            return oData;
        }

        protected override void OnExit(ExitEventArgs e)
        {
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            SystemEvents.SessionSwitch -= OnSessionSwitch;
            if (oPrivacyTimer != null)
            {
                oPrivacyTimer.Stop();
                InputManager.Current.PreProcessInput -= OnInput;
            }
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

        private void OnInput(object sender, PreProcessInputEventArgs e)
        {
            if (e.StagingItem.Input is KeyEventArgs or MouseEventArgs or TouchEventArgs)
                oLastActivityUtc = DateTime.UtcNow;
        }

        private static void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
        {
            if (e.Reason is not (SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or
                SessionSwitchReason.RemoteDisconnect)) return;
            Application oApplication = Current;
            if (oApplication == null || oApplication.Dispatcher.HasShutdownStarted) return;
            oApplication.Dispatcher.BeginInvoke(new Action(ConcealOpenSecrets), DispatcherPriority.Send);
        }

        internal static void ConcealOpenSecrets()
        {
            foreach (Window oWindow in Current.Windows)
            {
                if (oWindow is ItemEditor oEditor) oEditor.ConcealSecrets();
                else if (oWindow is PasswordGenerator oGenerator) oGenerator.ConcealSecrets();
            }
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
            // DWM title-bar attribute identifiers.
            const int ImmersiveDarkModeAttribute = 20;
            const int CaptionColorAttribute = 35;
            const int CaptionTextColorAttribute = 36;
            IntPtr hWindow = new WindowInteropHelper(oWindow).Handle;
            if (hWindow == IntPtr.Zero) return;
            int nDark = IsDarkMode ? 1 : 0;
            int nCaption = IsDarkMode ? 0x001E1E1E : -1;
            int nText = IsDarkMode ? 0x00F1F1F1 : -1;
            DwmSetWindowAttribute(hWindow, ImmersiveDarkModeAttribute, ref nDark, sizeof(int));
            DwmSetWindowAttribute(hWindow, CaptionColorAttribute, ref nCaption, sizeof(int));
            DwmSetWindowAttribute(hWindow, CaptionTextColorAttribute, ref nText, sizeof(int));
        }

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hWindow, int nAttribute, ref int nValue, int nSize);
    }

    internal static class PortableStartup
    {
        [STAThread]
        private static void Main()
        {
            // Show native startup feedback before library probing or Application initialization.
            SplashScreen oScreen = new SplashScreen(typeof(PortableStartup).Assembly, "Images/Save.png");
            oScreen.Show(true);
            try
            {
                if (TryRestartWithLocalExtraction()) return;
                RunApplication();
            }
            finally
            {
                oScreen.Close(TimeSpan.Zero);
            }
        }

        // Defer Application loading and JIT compilation until the splash is visible and probing completes.
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void RunApplication() => App.Main();

        internal static bool TryRestartWithLocalExtraction()
        {
            try
            {
                // Retry once using a cache beside the portable executable.
                const string sVariable = "DOTNET_BUNDLE_EXTRACT_BASE_DIR";
                string sLocalCache = Path.Combine(AppContext.BaseDirectory, ".net");
                string sCurrentCache = Environment.GetEnvironmentVariable(sVariable);
                if (!string.IsNullOrEmpty(sCurrentCache) &&
                    Path.TrimEndingDirectorySeparator(Path.GetFullPath(sCurrentCache)).Equals(sLocalCache,
                        StringComparison.OrdinalIgnoreCase)) return false;

                // Probe extracted native libraries before WPF or SQLite initializes.
                string sSearchPaths = AppContext.GetData("NATIVE_DLL_SEARCH_DIRECTORIES") as string ?? "";
                foreach (string sDirectory in sSearchPaths.Split(Path.PathSeparator,
                    StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!Directory.Exists(sDirectory) || Path.TrimEndingDirectorySeparator(sDirectory).Equals(
                        Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                            StringComparison.OrdinalIgnoreCase)) continue;
                    foreach (string sLibrary in Directory.EnumerateFiles(sDirectory, "*.dll"))
                    {
                        if (NativeLibrary.TryLoad(sLibrary, out IntPtr hLibrary))
                        {
                            NativeLibrary.Free(hLibrary);
                            continue;
                        }

                        // Preserve arguments and change extraction only for the restarted process.
                        Directory.CreateDirectory(sLocalCache);
                        ProcessStartInfo oStart = new ProcessStartInfo(Environment.ProcessPath)
                        {
                            UseShellExecute = false, CreateNoWindow = true
                        };
                        foreach (string sArgument in Environment.GetCommandLineArgs().AsSpan(1))
                            oStart.ArgumentList.Add(sArgument);
                        oStart.Environment[sVariable] = sLocalCache;
                        using Process oProcess = Process.Start(oStart);
                        return oProcess != null;
                    }
                }
            }
            catch (Exception oError) when (oError is IOException || oError is UnauthorizedAccessException ||
                oError is SecurityException || oError is Win32Exception)
            {
                // Keep the original startup path if the local cache or restart is unavailable.
            }
            return false;
        }
    }
}
