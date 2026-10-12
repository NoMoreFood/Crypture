using System.IO;
using System.Reflection;

namespace Crypture
{
    public partial class AboutBox : ThemedWindow
    {
        public AboutBox()
        {
            InitializeComponent();
            oVersion.Text = "Version " + Assembly.GetExecutingAssembly().GetName().Version.ToString(3);
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