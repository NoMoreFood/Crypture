using System;
using System.IO;
using System.IO.Compression;
using System.Windows.Data;

namespace Crypture
{
    internal class Utilities
    {
        internal static byte[] Compress(byte[] oInputArray)
        {
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
                oZipStream.CopyTo(oOutputSream);
                return oOutputSream.ToArray();
            }
        }
    }

    public class CheckIfItemIsSelectedConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            //ObservableCollection<object> oList = (ObservableCollection<object>)values[0];
            //  return oList.Contains(values[1]);
            return ((dynamic)values[0]).Contains((dynamic)values[1]);
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
            return ((DateTime)value == DateTime.MinValue) ? "- Not Yet Set -" : value;
        }

        public object ConvertBack(object value, Type targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            return null;
        }
    }
}