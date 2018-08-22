using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Environment = System.Environment;

namespace XamarinWebsocketTls.Droid
{
    public sealed class WebSocketDemo : IWebsocketDemo, IDisposable
    {
        private ClientWebSocket _webSocket;
        private bool _isConnected;
        private bool _useTls;
        private bool _addCertToStore;
        private bool _useServerValidationCallback;
        private string _hostName = "yourservername";
        private readonly X509Certificate2 _caCert;

        public WebSocketDemo()
        {
            using (var memoryStream = new MemoryStream())
            {
                Android.App.Application.Context.Resources.OpenRawResource(Resource.Raw.sample_ca).CopyTo(memoryStream);
                var bytes = memoryStream.ToArray();
                _caCert = new X509Certificate2(bytes);
            }

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, errors) =>
            {
                //NOTE: This is never called in Xamarin.Android.
                AddMessage("ServerCertificateValidationCallback called.");

                if (errors == SslPolicyErrors.None)
                {
                    if (certificate.Issuer == _caCert.Issuer)
                        AddMessage("cert was already deemed valid!");
                    return true;
                }

                if (UseServerValidationCallback)
                {
                    //BUGBUG: Obviously there should be a much more extensive check here.
                    if (certificate.Issuer == _caCert.Issuer)
                    {
                        AddMessage("ServerCertificateValidationCallback - matched our caCert.");
                        return true;
                    }
                }

                return false;
            };
        }

        /// <inheritdoc />
        public void Connect()
        {
            _webSocket?.Dispose();
            IsConnected = false;

            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            var certs = store.Certificates.Find(X509FindType.FindByThumbprint, _caCert.Thumbprint, false);
            if (certs.Count == 0 && AddCertToStore)
                store.Add(_caCert);
            else if (certs.Count > 0 && !AddCertToStore)
                store.Remove(certs[0]);
            store.Close();

            var uriPrefix = UseTls ? "wss:" : "ws:";
            try
            {
                _webSocket = new ClientWebSocket();

                //NOTE: It would not be expected for this to work, but I may as well show it
                //      as to avoid getting comments like 'did you try...'  This approach should
                //      be the only required change to connect to a fully self-signed certificate, however.
                //_webSocket.Options.ClientCertificates.Add(_caCert);

                _webSocket.ConnectAsync(new Uri($"{uriPrefix}//{HostName}:8181"), CancellationToken.None).Wait();
            }
            catch (Exception e)
            {
                AddMessage(e);
                return;
            }

            Task.Run(ReceiveTask).ContinueWith((t) =>
                        {
                            if (t.IsFaulted)
                                AddMessage(t.Exception);
                        });
        }

        private async Task ReceiveTask()
        {
            var buffer = new ArraySegment<byte>(new Byte[8192]);
            while (true)
            {
                WebSocketReceiveResult rcvResult = await _webSocket.ReceiveAsync(buffer, CancellationToken.None).ConfigureAwait(false);
                byte[]                 msgBytes  = buffer.Skip(buffer.Offset).Take(rcvResult.Count).ToArray();
                string                 rcvMsg    = Encoding.UTF8.GetString(msgBytes);
                AddMessage(Encoding.UTF8.GetString(msgBytes));
            }
            return;
        }

        /// <inheritdoc />
        public void SendMessage(string message)
        {
            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
            {
                AddMessage("Not Connected.");
                return;
            }
            var bytes = new ArraySegment<byte>(Encoding.UTF8.GetBytes(message));
            try
            {
                _webSocket.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None).Wait();
            }
            catch (Exception e)
            {
                AddMessage(e.Message);
            }
        }

        /// <inheritdoc />
        public bool IsConnected
        {
            get => _isConnected;
            private set
            {
                var old = _isConnected;
                _isConnected = value;
                if (old != value)
                    OnPropertyChanged();
            } 
        }

        /// <inheritdoc />
        public bool UseTls
        {
            get => _useTls;
            set
            {
                var old = _useTls;
                _useTls = value;
                if (old != value)
                    OnPropertyChanged();
            }
        }

        /// <inheritdoc />
        public bool AddCertToStore
        {
            get => _addCertToStore;
            set
            {
                var old = _addCertToStore;
                _addCertToStore = value;
                if (old != value)
                    OnPropertyChanged();
            }
        }

        /// <inheritdoc />
        public bool UseServerValidationCallback
        {
            get => _useServerValidationCallback;
            set
            {
                var old = _useServerValidationCallback;
                _useServerValidationCallback = value;
                if (old != value)
                    OnPropertyChanged();
            }
        }

        /// <inheritdoc />
        public string HostName
        {
            get => _hostName;
            set
            {
                var old = _hostName;
                _hostName = value;
                if (old != value)
                    OnPropertyChanged();
            }
        }

        /// <inheritdoc />
        public string Messages { get; private set; } = string.Empty;

        /// <inheritdoc />
        public event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private void AddMessage(Exception e)
        {
            var aggEx = e as AggregateException;
            if (aggEx != null)
                e = aggEx.Flatten();

            var sb = new StringBuilder(e.Message);
            sb.AppendLine();
            Exception ex = e;
            while ((ex = ex.InnerException) != null)
                sb.AppendLine(ex.Message);
            AddMessage(sb.ToString());
        }

        private void AddMessage(string message)
        {
            Messages = string.Concat(message, Environment.NewLine, Messages);
            OnPropertyChanged(nameof(Messages));
        }

        /// <inheritdoc />
        public void ClearMessages()
        {
            Messages = string.Empty;
            OnPropertyChanged(nameof(Messages));
        }

        /// <inheritdoc />
        public void Dispose()
        {
            _webSocket?.Dispose();
        }
    }
}