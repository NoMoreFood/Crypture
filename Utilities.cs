using System.IO;
using System.IO.Compression;

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
}