using System;
using System.Windows;

namespace Crypture
{
    public class ThemedWindow : Window
    {
        public ThemedWindow()
        {
            SetResourceReference(BackgroundProperty, "Crypture.WindowBrush");
            SetResourceReference(ForegroundProperty, "Crypture.TextBrush");
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            // Color the native surface and title bar before the window becomes visible.
            App.ApplyWindowTheme(this);
            base.OnSourceInitialized(e);
        }
    }
}
