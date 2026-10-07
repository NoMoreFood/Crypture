using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestPopups()
    {
        bool bPreviousDark = App.IsDarkMode;
        ThemedWindow oOwner = new ThemedWindow
        {
            Width = 300, Height = 200, Left = -20000, Top = -20000,
            WindowStartupLocation = WindowStartupLocation.Manual, ShowInTaskbar = false, ShowActivated = false
        };
        Popup oPreview = null;
        SqlServerBackupDialog oBackup = null;
        try
        {
            // Check native colors at handle creation, before Loaded or the first visible frame.
            App.ApplyTheme(true);
            oPreview = new Popup("The operation could not be completed.\n\nThe selected Vault is unavailable.",
                "Crypture", MessageBoxButton.OK, MessageBoxImage.Error)
            {
                Left = -20000, Top = -20000, WindowStartupLocation = WindowStartupLocation.Manual,
                ShowActivated = false
            };
            bool bSourceChecked = false;
            oPreview.SourceInitialized += (s, e) =>
            {
                Check(!oPreview.IsLoaded && !oPreview.IsVisible && PopupSurfaceMatchesTheme(oPreview),
                    "Popup native surface is dark before loading and display");
                int nDark;
                IntPtr hWindow = new WindowInteropHelper(oPreview).Handle;
                if (DwmGetWindowAttribute(hWindow, 20, out nDark, sizeof(int)) == 0)
                    Check(nDark == 1, "Popup title bar is dark at native window creation");
                bSourceChecked = true;
            };
            new WindowInteropHelper(oPreview).EnsureHandle();
            Check(bSourceChecked, "Popup applies its theme during SourceInitialized");
            ((Window)oPreview).Show();
            PumpUntil(() => oPreview.IsLoaded);
            oPreview.UpdateLayout();
            SavePopupImage(oPreview, "popup-dark");

            // Theme changes also update open windows and their native backing surfaces.
            App.ApplyTheme(false);
            oPreview.UpdateLayout();
            Check(PopupSurfaceMatchesTheme(oPreview) && ((SolidColorBrush)oPreview.Background).Color == Colors.White &&
                ((TextBox)oPreview.FindName("oMessage")).Foreground == oPreview.Foreground,
                "An open popup follows a switch to light mode without stale text or native colors");
            SavePopupImage(oPreview, "popup-light");
            App.ApplyTheme(true);
            oPreview.UpdateLayout();
            Check(PopupSurfaceMatchesTheme(oPreview) && ((SolidColorBrush)oPreview.Background).Color.R == 30,
                "An open popup follows a switch back to dark mode");
            oPreview.Close();
            oPreview = null;

            oBackup = new SqlServerBackupDialog("PopupTests");
            new WindowInteropHelper(oBackup).EnsureHandle();
            Check(!oBackup.IsLoaded && PopupSurfaceMatchesTheme(oBackup),
                "Existing application dialogs receive the dark native surface before loading");
            oBackup.Close();
            oBackup = null;

            // Exercise modal result handling through the shared API and real WPF button/default-key routing.
            oOwner.Show();
            PumpUntil(() => oOwner.IsLoaded);
            foreach (var oCase in new[]
            {
                (MessageBoxButton.OK, MessageBoxResult.None, MessageBoxResult.OK),
                (MessageBoxButton.OKCancel, MessageBoxResult.Cancel, MessageBoxResult.Cancel),
                (MessageBoxButton.YesNo, MessageBoxResult.No, MessageBoxResult.No),
                (MessageBoxButton.YesNoCancel, MessageBoxResult.Cancel, MessageBoxResult.Cancel)
            })
            {
                MessageBoxResult oActual = ExercisePopup(oOwner, oCase.Item1, oCase.Item2, oPopup =>
                {
                    Button oDefault = PopupButtons(oPopup).Single(oButton => oButton.IsDefault);
                    Check(oPopup.Owner == oOwner && !IsWindowEnabled(new WindowInteropHelper(oOwner).Handle) &&
                        (MessageBoxResult)oDefault.Tag == oCase.Item3 && oDefault.IsKeyboardFocused,
                        "Modal ownership and default focus are preserved for " + oCase.Item1);
                    AccessKeyManager.ProcessKey(oPopup, "\r", false);
                });
                Check(oActual == oCase.Item3 && IsWindowEnabled(new WindowInteropHelper(oOwner).Handle),
                    "Enter returns the default choice and restores the owner for " + oCase.Item1);
            }
            foreach (MessageBoxButton oButtons in new[] { MessageBoxButton.OK, MessageBoxButton.OKCancel,
                MessageBoxButton.YesNoCancel })
            {
                MessageBoxResult oExpected = oButtons == MessageBoxButton.OK ?
                    MessageBoxResult.OK : MessageBoxResult.Cancel;
                Check(ExercisePopup(oOwner, oButtons, MessageBoxResult.None, oPopup =>
                {
                    oPopup.RaiseEvent(new KeyEventArgs(Keyboard.PrimaryDevice, PresentationSource.FromVisual(oPopup),
                        Environment.TickCount, Key.Escape) { RoutedEvent = Keyboard.PreviewKeyDownEvent });
                }) == oExpected, "Escape safely dismisses " + oButtons);
                Check(ExercisePopup(oOwner, oButtons, MessageBoxResult.None, oPopup => oPopup.Close()) == oExpected,
                    "Title-bar close safely dismisses " + oButtons);
            }
            Check(ExercisePopup(oOwner, MessageBoxButton.YesNo, MessageBoxResult.No, oPopup =>
            {
                oPopup.Close();
                Check(oPopup.IsVisible, "Yes/No prompts remain open without an explicit choice");
                PopupButtons(oPopup).Single(oButton => (MessageBoxResult)oButton.Tag == MessageBoxResult.Yes)
                    .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }) == MessageBoxResult.Yes, "Clicking Yes returns an affirmative result");
            Check(ExercisePopup(null, MessageBoxButton.OK, MessageBoxResult.None, oPopup => oPopup.Close()) ==
                MessageBoxResult.OK, "Startup popups can be displayed without an owner");

            // Long messages must scroll while all choices remain visible with enlarged text and a narrow window.
            oPreview = new Popup(String.Join("\n\n", Enumerable.Repeat(
                "The operation could not be completed. Check the selected Vault and try again.", 20)),
                "Crypture", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel)
            {
                FontSize = 21, Width = 300, MaxHeight = 320, Left = -20000, Top = -20000,
                WindowStartupLocation = WindowStartupLocation.Manual, ShowActivated = false
            };
            ((Window)oPreview).Show();
            PumpUntil(() => oPreview.IsLoaded);
            oPreview.UpdateLayout();
            Check(((ScrollViewer)oPreview.FindName("oMessageScroll")).ScrollableHeight > 0 &&
                PopupButtons(oPreview).All(oButton =>
                {
                    Rect oBounds = oButton.TransformToAncestor(oPreview).TransformBounds(new Rect(oButton.RenderSize));
                    return oBounds.Left >= 0 && oBounds.Right <= oPreview.RenderSize.Width + 1 &&
                        oBounds.Top >= 0 && oBounds.Bottom <= oPreview.RenderSize.Height + 1;
                }), "Long popup text scrolls without clipping choices at enlarged text size");
            SavePopupImage(oPreview, "popup-enlarged");
        }
        finally
        {
            if (oPreview != null)
                PopupButtons(oPreview).Last().RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            oBackup?.Close();
            oOwner.Close();
            App.ApplyTheme(bPreviousDark);
        }
    }

    private static Button[] PopupButtons(Popup oPopup) =>
        ((WrapPanel)oPopup.FindName("oButtons")).Children.Cast<Button>().ToArray();

    private static bool PopupSurfaceMatchesTheme(Window oWindow) =>
        HwndSource.FromHwnd(new WindowInteropHelper(oWindow).Handle).CompositionTarget.BackgroundColor ==
            ((SolidColorBrush)oWindow.Background).Color;

    private static MessageBoxResult ExercisePopup(Window oOwner, MessageBoxButton oButtons,
        MessageBoxResult oDefault, Action<Popup> oExercise)
    {
        Exception oFailure = null;
        Application.Current.Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() =>
        {
            Popup oPopup = Application.Current.Windows.OfType<Popup>().Single();
            try { oExercise(oPopup); }
            catch (Exception oError) { oFailure = oError; }
            finally
            {
                if (oPopup.IsVisible)
                    PopupButtons(oPopup).Last().RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
        }));
        MessageBoxResult oResult = Popup.Show(oOwner, "Confirm this operation?", "Crypture", oButtons,
            MessageBoxImage.Question, oDefault);
        if (oFailure != null) throw oFailure;
        return oResult;
    }

    private static void SavePopupImage(Popup oPopup, string sName)
    {
        string sDirectory = Environment.GetEnvironmentVariable("CRYPTURE_TEST_POPUP_IMAGES");
        if (sDirectory == null) return;
        Directory.CreateDirectory(sDirectory);
        FrameworkElement oContent = (FrameworkElement)oPopup.Content;
        RenderTargetBitmap oBitmap = new RenderTargetBitmap((int)Math.Ceiling(oContent.ActualWidth),
            (int)Math.Ceiling(oContent.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        DrawingVisual oVisual = new DrawingVisual();
        using (DrawingContext oDrawing = oVisual.RenderOpen())
        {
            Rect oBounds = new Rect(oContent.RenderSize);
            oDrawing.DrawRectangle(oPopup.Background, null, oBounds);
            oDrawing.DrawRectangle(new VisualBrush(oContent), null, oBounds);
        }
        oBitmap.Render(oVisual);
        PngBitmapEncoder oEncoder = new PngBitmapEncoder();
        oEncoder.Frames.Add(BitmapFrame.Create(oBitmap));
        using FileStream oFile = File.Create(Path.Combine(sDirectory, sName + ".png"));
        oEncoder.Save(oFile);
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmGetWindowAttribute(IntPtr hWindow, int nAttribute, out int nValue, int nSize);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowEnabled(IntPtr hWindow);
}
