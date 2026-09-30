using System.IO;
using System.Reflection;
using System.Windows;

namespace Crypture
{
    public partial class AboutBox : Window
    {
        public AboutBox()
        {
            InitializeComponent();
            foreach (string sName in new[] { "Crypture.RuntimeNotices", "Crypture.RuntimeThirdPartyNotices" })
            {
                using (Stream oStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(sName))
                {
                    if (oStream == null) continue;
                    using (StreamReader oReader = new StreamReader(oStream))
                        oRuntimeNotices.AppendText(oReader.ReadToEnd() + "\r\n");
                }
            }
        }
    }
}