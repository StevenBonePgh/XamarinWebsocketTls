using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Xamarin.Forms;

namespace XamarinWebsocketTls
{
    public sealed class MainPageViewModel : INotifyPropertyChanged, IDisposable
    {
        private readonly IWebsocketDemo _websocket;

        public MainPageViewModel()
        {
            _websocket          = DependencyService.Get<IWebsocketDemo>();
            _websocket.HostName = "yourhost";

            _websocket.AddCertToStore              = true;
            _websocket.UseServerValidationCallback = true;
            _websocket.UseTls                      = false;

            _websocket.PropertyChanged += delegate (object sender, PropertyChangedEventArgs args)
            {
                OnPropertyChanged(args.PropertyName);
            };
        }

        public void Connect()
        {
            _websocket.Connect();
        }

        public bool IsConnected => _websocket.IsConnected;

        public bool UseTls
        {
            get => _websocket.UseTls;
            set => _websocket.UseTls = value;
        }

        public bool AddCertToStore
        {
            get => _websocket.AddCertToStore;
            set => _websocket.AddCertToStore = value;
        }

        public string HostName
        {
            get => _websocket.HostName;
            set => _websocket.HostName = value;
        }

        public bool UseServerValidationCallback
        {
            get => _websocket.UseServerValidationCallback;
            set => _websocket.UseServerValidationCallback = value;
        }

        public string Messages => _websocket.Messages;

        public string CurrentMessage { get; set; } = string.Empty;

        public Command ConnectCommand => new Command(() => _websocket.Connect());

        public Command ClearCommand => new Command(() => _websocket.ClearMessages());

        public Command SendMessageCommand => new Command(() => SendMessage(CurrentMessage));

        public void SendMessage(string message)
        {
            if (!string.IsNullOrWhiteSpace(message))
                _websocket.SendMessage(message);
        }
        
        public event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <inheritdoc />
        public void Dispose()
        {
            (_websocket as IDisposable)?.Dispose();
        }
    }
}