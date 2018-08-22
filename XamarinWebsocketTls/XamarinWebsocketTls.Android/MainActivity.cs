using System;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using Android.App;
using Android.Content.PM;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Android.OS;
using Java.Security;
using Javax.Net.Ssl;
using Xamarin.Forms;
using X509Certificate = Java.Security.Cert.X509Certificate;

namespace XamarinWebsocketTls.Droid
{
    [Activity(Label = "XamarinWebsocketTls", Icon = "@mipmap/icon", Theme = "@style/MainTheme", MainLauncher = true, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation)]
    public class MainActivity : global::Xamarin.Forms.Platform.Android.FormsAppCompatActivity
    {
        protected override void OnCreate(Bundle savedInstanceState)
        {
            DependencyService.Register<IWebsocketDemo, WebSocketDemo>();

            TabLayoutResource = Resource.Layout.Tabbar;
            ToolbarResource = Resource.Layout.Toolbar;

            base.OnCreate(savedInstanceState);
            global::Xamarin.Forms.Forms.Init(this, savedInstanceState);
            LoadApplication(new App());
        }
    }
}