using System;
using System.IO;
using System.Buffers;
using System.IO.Compression;
using System.Linq;
using System.Collections;
using System.Windows;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Threading;
using System.Windows.Media;
using System.Runtime.InteropServices;

namespace Crypture
{
    internal static class Utilities
    {
        internal const int MaxItemSize = 64 * 1024 * 1024;

        // Reserve bounded space for gzip headers and incompressible blocks.
        internal const int MaxCompressedItemSize = MaxItemSize + 1024 * 1024;

        internal static void EnableClipboardTimeout(TextBox oTextBox, Func<string, bool> oCopy = null) =>
            EnableClipboardTimeout(oTextBox, oCopy, bAll => bAll ? oTextBox.Text : oTextBox.SelectedText,
                bAll => bAll ? oTextBox.Text.Length > 0 : oTextBox.SelectionLength > 0,
                () => oTextBox.SelectedText = "");

        internal static string GetRichText(RichTextBox oTextBox)
        {
            string sText = new TextRange(oTextBox.Document.ContentStart, oTextBox.Document.ContentEnd).Text;
            return sText.EndsWith("\r\n", StringComparison.Ordinal) ? sText[..^2] : sText;
        }

        internal static void NormalizeRichTextAppearance(RichTextBox oTextBox)
        {
            // RTF stores inherited colors and fonts; let the app theme and secret-font setting supply those values.
            FlowDocument oDocument = oTextBox.Document;
            oDocument.ClearValue(TextElement.ForegroundProperty);
            oDocument.ClearValue(TextElement.BackgroundProperty);
            oDocument.ClearValue(TextElement.FontFamilyProperty);
            oDocument.ClearValue(TextElement.FontSizeProperty);
            for (TextPointer oPosition = oDocument.ContentStart;
                oPosition != null && oPosition.CompareTo(oDocument.ContentEnd) < 0;
                oPosition = oPosition.GetNextContextPosition(LogicalDirection.Forward))
            {
                if (oPosition.GetPointerContext(LogicalDirection.Forward) != TextPointerContext.ElementStart ||
                    oPosition.GetAdjacentElement(LogicalDirection.Forward) is not TextElement oElement) continue;
                oElement.ClearValue(TextElement.ForegroundProperty);
                oElement.ClearValue(TextElement.BackgroundProperty);
                oElement.ClearValue(TextElement.FontFamilyProperty);
                oElement.ClearValue(TextElement.FontSizeProperty);
            }
        }

        internal static void EnableClipboardTimeout(RichTextBox oTextBox, Func<string, bool> oCopy = null)
        {
            // Rich editing must use the same protected plain-text clipboard path as ordinary secrets.
            EnableClipboardTimeout(oTextBox, oCopy, bAll => bAll ? GetRichText(oTextBox) : oTextBox.Selection.Text,
                bAll => bAll ? oTextBox.Document.ContentStart.GetInsertionPosition(LogicalDirection.Forward).CompareTo(
                    oTextBox.Document.ContentEnd.GetInsertionPosition(LogicalDirection.Backward)) != 0 :
                    !oTextBox.Selection.IsEmpty,
                () => oTextBox.Selection.Text = "");

            // Paste text only, keeping embedded files and external rich content out of encrypted notes.
            DataObject.AddPastingHandler(oTextBox, (s, e) =>
            {
                if (e.SourceDataObject.GetDataPresent(DataFormats.UnicodeText))
                    e.FormatToApply = DataFormats.UnicodeText;
                else if (e.SourceDataObject.GetDataPresent(DataFormats.Text))
                    e.FormatToApply = DataFormats.Text;
                else e.CancelCommand();
            });
        }

        private static void EnableClipboardTimeout(TextBoxBase oTextBox, Func<string, bool> oCopy,
            Func<bool, string> oReadText, Func<bool, bool> oHasText, Action oClearSelection)
        {
            oCopy = oCopy ?? (s => TryOperation(Window.GetWindow(oTextBox), () => App.CopyProtectedText(s)));

            // Copy icons use the whole field; keyboard Copy and Cut keep their selection behavior.
            bool CanRun(ICommand oCommand, object oParameter, out bool bCut, out bool bAll)
            {
                bCut = oCommand == ApplicationCommands.Cut;
                bAll = !bCut && Equals(oParameter, "All");
                return oTextBox.IsEnabled && (!bCut || !oTextBox.IsReadOnly) && oHasText(bAll);
            }
            ExecutedRoutedEventHandler oExecuted = (s, e) =>
            {
                e.Handled = true;
                if (!CanRun(e.Command, e.Parameter, out bool bCut, out bool bAll)) return;
                string sText = oReadText(bAll);
                if (sText.Length != 0 && oCopy(sText) && bCut) oClearSelection();
            };
            CanExecuteRoutedEventHandler oCanExecute = (s, e) =>
            {
                e.CanExecute = CanRun(e.Command, e.Parameter, out _, out _);
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
                ShowError(oOwner, oError);
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
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (Exception oError)
            {
                ShowError(oOwner, oError);
                return false;
            }
        }

        private static void ShowError(Window oOwner, Exception oError) => Popup.Show(oOwner,
            "The operation could not be completed." + Environment.NewLine + Environment.NewLine +
            oError.GetBaseException().Message, "Crypture", MessageBoxButton.OK, MessageBoxImage.Error);

        internal static byte[] CompressFile(string sPath)
        {
            using (FileStream oFile = File.OpenRead(sPath))
                return Compress(oFile);
        }

        internal static byte[] Compress(byte[] oInputArray)
        {
            using (MemoryStream oInputStream = new MemoryStream(oInputArray)) return Compress(oInputStream);
        }

        private static byte[] Compress(Stream oInputStream)
        {
            const string SizeError = "Files must be no larger than 64 MB.";
            if (oInputStream.Length > MaxItemSize) throw new InvalidDataException(SizeError);
            using (MemoryStream oOutputStream = new MemoryStream())
            {
                using (GZipStream oZipStream = new GZipStream(oOutputStream, CompressionMode.Compress))
                    CopyFileContent(oInputStream, oZipStream, SizeError);
                return oOutputStream.ToArray();
            }
        }

        internal static byte[] Decompress(byte[] oInputArray)
        {
            using (MemoryStream oOutputStream = new MemoryStream())
            {
                Decompress(oInputArray, oOutputStream);
                return oOutputStream.ToArray();
            }
        }

        internal static void DecompressToFile(byte[] oInputArray, string sDestination)
        {
            // Publish only a complete, size-checked file and preserve an existing destination's permissions.
            string sPath = Path.GetFullPath(sDestination);
            string sTemporary = Path.Combine(Path.GetDirectoryName(sPath), ".crypture-" + Guid.NewGuid() + ".tmp");
            try
            {
                using (FileStream oFile = new FileStream(sTemporary,
                    FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    Decompress(oInputArray, oFile);
                if (File.Exists(sPath)) File.Replace(sTemporary, sPath, null);
                else File.Move(sTemporary, sPath);
            }
            finally
            {
                File.Delete(sTemporary);
            }
        }

        private static void Decompress(byte[] oInputArray, Stream oOutputStream)
        {
            using (MemoryStream oInputStream = new MemoryStream(oInputArray))
            using (GZipStream oZipStream = new GZipStream(oInputStream, CompressionMode.Decompress))
                CopyFileContent(oZipStream, oOutputStream, "The expanded file exceeds the 64 MB limit.");
        }

        private static void CopyFileContent(Stream oInputStream, Stream oOutputStream, string sSizeError)
        {
            // Bound expanded content while keeping plaintext transfer buffers short-lived.
            byte[] oBuffer = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                int nTotal = 0;
                int nRead;
                while ((nRead = oInputStream.Read(oBuffer, 0, oBuffer.Length)) != 0)
                {
                    nTotal += nRead;
                    if (nTotal > MaxItemSize) throw new InvalidDataException(sSizeError);
                    oOutputStream.Write(oBuffer, 0, nRead);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(oBuffer, true);
            }
        }
    }

    internal sealed class ClipboardExpiration : IDisposable
    {
        internal static TimeSpan Timeout => TimeSpan.FromSeconds(
            new ConfigurationDefaults().Number("ClipboardTimeoutSeconds", 300, 1, 86400));
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

        internal void TrackCopy(TimeSpan? oTimeout = null)
        {
            TimeSpan oDuration = oTimeout ?? Timeout;
            uint nCopied = oCaptureSequence();
            if (nCopied == 0) return;
            nSequence = nCopied;
            oDeadline = oUtcNow() + oDuration;
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
            return FontFamilies.FirstOrDefault(f => String.Equals(f.Source,
                sName, StringComparison.OrdinalIgnoreCase)) ??
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
        public object Convert(object[] values, Type targetType,
            object parameter, System.Globalization.CultureInfo culture)
        {
            return values.Length >= 2 && values[0] is IList oList && oList.Contains(values[1]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes,
            object parameter, System.Globalization.CultureInfo culture)
        {
            return null;
        }
    }

    public class CheckIfDateIsNotSetConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            // Display UTC values in local time and leave unspecified timestamps as recorded.
            if (value is not DateTime oDate || oDate == DateTime.MinValue) return "- Not Yet Set -";
            return oDate.Kind == DateTimeKind.Utc ? oDate.ToLocalTime() : oDate;
        }

        public object ConvertBack(object value, Type targetTypes,
            object parameter, System.Globalization.CultureInfo culture)
        {
            return null;
        }
    }
}
