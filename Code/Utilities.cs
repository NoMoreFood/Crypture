using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Collections;
using System.Windows;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using System.Windows.Media;
using System.Runtime.InteropServices;

namespace Crypture
{
    internal class Utilities
    {
        internal const int MaxItemSize = 64 * 1024 * 1024;

        // Reserve bounded space for gzip headers and incompressible blocks.
        internal const int MaxCompressedItemSize = MaxItemSize + 1024 * 1024;

        internal static void EnableClipboardTimeout(TextBox oTextBox, Func<string, bool> oCopy = null)
        {
            oCopy = oCopy ?? (s => TryOperation(Window.GetWindow(oTextBox), () => App.CopyProtectedText(s)));
            ExecutedRoutedEventHandler oExecuted = (s, e) =>
            {
                e.Handled = true;
                bool bCut = e.Command == ApplicationCommands.Cut;

                // Copy icons use the whole field; keyboard Copy and Cut keep their selection behavior.
                bool bAll = !bCut && Equals(e.Parameter, "All");
                string sText = bAll ? oTextBox.Text : oTextBox.SelectedText;
                if (!oTextBox.IsEnabled || sText.Length == 0 || (bCut && oTextBox.IsReadOnly)) return;
                if (oCopy(sText) && bCut) oTextBox.SelectedText = "";
            };
            CanExecuteRoutedEventHandler oCanExecute = (s, e) =>
            {
                bool bCut = e.Command == ApplicationCommands.Cut;
                bool bAll = !bCut && Equals(e.Parameter, "All");
                e.CanExecute = oTextBox.IsEnabled && (bAll ? oTextBox.Text.Length > 0 :
                    oTextBox.SelectionLength > 0) && (!bCut || !oTextBox.IsReadOnly);
                e.Handled = true;
            };
            oTextBox.CommandBindings.Add(new CommandBinding(ApplicationCommands.Copy, oExecuted, oCanExecute));
            oTextBox.CommandBindings.Add(new CommandBinding(ApplicationCommands.Cut, oExecuted, oCanExecute));
            oTextBox.TextChanged += (s, e) => CommandManager.InvalidateRequerySuggested();
            oTextBox.IsEnabledChanged += (s, e) => CommandManager.InvalidateRequerySuggested();
        }

        internal static bool TryOperation(Window oOwner, Action oAction)
        {
            try
            {
                oAction();
                return true;
            }
            catch (Exception oError)
            {
                MessageBox.Show(oOwner, "The operation could not be completed." + Environment.NewLine +
                    Environment.NewLine + oError.GetBaseException().Message, "Crypture",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        internal static async Task<bool> TryOperationAsync(Window oOwner, Func<Task> oAction)
        {
            try
            {
                await oAction();
                return true;
            }
            catch (Exception oError)
            {
                MessageBox.Show(oOwner, "The operation could not be completed." + Environment.NewLine +
                    Environment.NewLine + oError.GetBaseException().Message, "Crypture",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        internal static byte[] ReadFile(string sPath)
        {
            using (FileStream oFile = File.OpenRead(sPath))
            {
                if (oFile.Length > MaxItemSize) throw new InvalidDataException("Files must be no larger than 64 MB.");
                using (BinaryReader oReader = new BinaryReader(oFile)) return oReader.ReadBytes((int)oFile.Length);
            }
        }

        internal static byte[] Compress(byte[] oInputArray)
        {
            if (oInputArray.Length > MaxItemSize) throw new InvalidDataException("Files must be no larger than 64 MB.");
            using (MemoryStream oOutputStream = new MemoryStream())
            {
                using (GZipStream oZipStream = new GZipStream(oOutputStream, CompressionMode.Compress))
                using (MemoryStream oInputStream = new MemoryStream(oInputArray))
                    oInputStream.CopyTo(oZipStream);
                return oOutputStream.ToArray();
            }
        }

        internal static byte[] Decompress(byte[] oInputArray)
        {
            using (MemoryStream oInputStream = new MemoryStream(oInputArray))
            using (GZipStream oZipStream = new GZipStream(oInputStream, CompressionMode.Decompress))
            using (MemoryStream oOutputSream = new MemoryStream())
            {
                byte[] oBuffer = new byte[81920];
                try
                {
                    int nRead;
                    while ((nRead = oZipStream.Read(oBuffer, 0, oBuffer.Length)) != 0)
                    {
                        if (oOutputSream.Length + nRead > MaxItemSize)
                            throw new InvalidDataException("The expanded file exceeds the 64 MB limit.");
                        oOutputSream.Write(oBuffer, 0, nRead);
                    }
                }
                finally
                {
                    Array.Clear(oBuffer, 0, oBuffer.Length);
                }
                return oOutputSream.ToArray();
            }
        }
    }

    internal sealed class ClipboardExpiration : IDisposable
    {
        internal static readonly TimeSpan Timeout = TimeSpan.FromMinutes(5);
        private readonly DispatcherTimer oTimer;
        private readonly Func<uint> oCaptureSequence;
        private readonly Func<uint, bool> oClearIfUnchanged;
        private readonly Func<DateTime> oUtcNow;
        private uint nSequence;
        private DateTime oDeadline;

        internal ClipboardExpiration(Func<uint> oCaptureSequence = null,
            Func<uint, bool> oClearIfUnchanged = null, Func<DateTime> oUtcNow = null)
        {
            this.oCaptureSequence = oCaptureSequence ?? CaptureOwnedSequence;
            this.oClearIfUnchanged = oClearIfUnchanged ?? ClearIfUnchanged;
            this.oUtcNow = oUtcNow ?? (() => DateTime.UtcNow);
            oTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(1) };
            oTimer.Tick += (s, e) => ClearExpired();
        }

        internal void TrackCopy()
        {
            uint nCopied = oCaptureSequence();
            if (nCopied == 0) return;
            nSequence = nCopied;
            oDeadline = oUtcNow() + Timeout;
            oTimer.Start();
        }

        internal void ClearExpired()
        {
            if (nSequence == 0 || oUtcNow() < oDeadline || !oClearIfUnchanged(nSequence)) return;
            nSequence = 0;
            oTimer.Stop();
        }

        public void Dispose()
        {
            oTimer.Stop();
            if (nSequence != 0) oClearIfUnchanged(nSequence);
            nSequence = 0;
        }

        private static uint CaptureOwnedSequence()
        {
            uint nCopied = GetClipboardSequenceNumber();
            GetWindowThreadProcessId(GetClipboardOwner(), out uint nOwner);
            return nOwner == GetCurrentProcessId() ? nCopied : 0;
        }

        private static bool ClearIfUnchanged(uint nCopied)
        {
            if (!OpenClipboard(IntPtr.Zero)) return false;
            try
            {
                // Check and clear under the same clipboard lock so a newer copy cannot be erased.
                return GetClipboardSequenceNumber() != nCopied || EmptyClipboard();
            }
            finally
            {
                CloseClipboard();
            }
        }

        [DllImport("user32.dll")]
        private static extern uint GetClipboardSequenceNumber();
        [DllImport("user32.dll")]
        private static extern IntPtr GetClipboardOwner();
        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWindow, out uint nProcessId);
        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenClipboard(IntPtr hWindow);
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EmptyClipboard();
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseClipboard();
    }

    public sealed class SecretFontConverter : IValueConverter
    {
        internal static readonly FontFamily[] FontFamilies =
            Fonts.SystemFontFamilies.OrderBy(f => f.Source, StringComparer.OrdinalIgnoreCase).ToArray();

        internal static FontFamily ResolveFont(string sName)
        {
            // Only use installed fonts; missing preferences fall back to Consolas.
            return FontFamilies.FirstOrDefault(f => String.Equals(f.Source, sName, StringComparison.OrdinalIgnoreCase)) ??
                FontFamilies.FirstOrDefault(f => f.Source == "Consolas") ?? new FontFamily("Consolas");
        }

        public object Convert(object value, Type targetType, object parameter,
            System.Globalization.CultureInfo culture)
        {
            return ResolveFont(value as string);
        }

        public object ConvertBack(object value, Type targetType, object parameter,
            System.Globalization.CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }

    public sealed class SecretFontSelector : ComboBox
    {
        public SecretFontSelector()
        {
            ItemsSource = SecretFontConverter.FontFamilies;
            DisplayMemberPath = "Source";
            SetBinding(SelectedItemProperty, new Binding(nameof(Properties.Settings.SecretFontFamily))
            {
                Source = Properties.Settings.Default, Mode = BindingMode.OneWay, Converter = new SecretFontConverter()
            });
        }

        protected override void OnSelectionChanged(SelectionChangedEventArgs e)
        {
            base.OnSelectionChanged(e);
            if (!IsLoaded || SelectedItem is not FontFamily oFont ||
                oFont.Equals(SecretFontConverter.ResolveFont(Properties.Settings.Default.SecretFontFamily))) return;

            // Update every open secret field before saving the appearance preference.
            Properties.Settings.Default.SecretFontFamily = oFont.Source;
            Utilities.TryOperation(Window.GetWindow(this), () => Properties.Settings.Default.Save());
        }
    }

    public class CheckIfItemIsSelectedConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return values.Length == 2 && values[0] is IList oList && oList.Contains(values[1]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            return null;
        }
    }

    public class CheckIfDateIsNotSetConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return value is DateTime oDate && oDate != DateTime.MinValue ? value : "- Not Yet Set -";
        }

        public object ConvertBack(object value, Type targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            return null;
        }
    }
}