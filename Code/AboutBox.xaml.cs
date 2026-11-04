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
            foreach (var (sName, oTextBox) in new[]
            {
                ("Crypture.License", oLicense), ("Crypture.RuntimeNotices", oRuntimeNotices),
                ("Crypture.RuntimeThirdPartyNotices", oRuntimeNotices)
            })
            {
                using (Stream oStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(sName))
                {
                    if (oStream == null) continue;
                    using (StreamReader oReader = new StreamReader(oStream))
                        oTextBox.AppendText(oReader.ReadToEnd() + "\r\n");
                }
            }
        }
    }
}