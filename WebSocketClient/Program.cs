using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WebSocketClient
{
    class Program
    {
        static void Main(string[] args)
        {
            bool useTls = true;
            bool addCaCertToStore = true;
            bool useServerCertificateValidationCallback = true;

            Task.Run(() => Connect(useTls, addCaCertToStore, useServerCertificateValidationCallback)).Wait();
        }

        static async Task Connect(bool useTls, bool addCaCertToStore, bool useServerCertificateValidationCallback)
        {
            await Console.Out.WriteLineAsync("Press Enter to connect to Websocket server.").ConfigureAwait(false);
            Console.ReadLine();

            try
            {
                var caCert = new X509Certificate2("sample_ca.cer");
                X509Store store  = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, caCert.Thumbprint, false);
                if (certs.Count == 0 && addCaCertToStore)
                    store.Add(caCert);
                else if (certs.Count > 0 && !addCaCertToStore)
                    store.Remove(caCert);
                store.Close();

                var webSocket = new ClientWebSocket();
                //NOTE: It would not be expected for this to work, but I may as well show it
                //      as to avoid getting comments like 'did you try...'  This approach should
                //      work for a self-signed certificate, however.
                //webSocket.Options.ClientCertificates.Add(caCert); //add the CA cert.
                // For giggles, add the cert issued by caCert.  Again, this should not work as it is issued
                // by an untrusted CA.
                //webSocket.Options.ClientCertificates.Add(new X509Certificate2(@"..\..\..\FleckServer\bin\debug\sample_cert.cer"));
                var uriPrefix = "ws:";
                if (useTls)
                {
                    uriPrefix = "wss:";
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                }

                if(useServerCertificateValidationCallback)
                {
                    ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, errors) =>
                    {
                        if (errors == SslPolicyErrors.None)
                            return true;

                        //BUGBUG: Obviously there should be a much more extensive check here.
                        if (certificate.Issuer == caCert.Issuer)
                            return true;

                        return false;
                    };
                }

                await webSocket.ConnectAsync(new Uri($"{uriPrefix}//localhost:8181"), CancellationToken.None).ConfigureAwait(false);

                Task.Run(() => Receive(webSocket));

                await Console.Out.WriteLineAsync("Type line to send to websocket, Enter key sends it. 'exit' to exit.").ConfigureAwait(false);
                string input = Console.ReadLine();
                while (input != "exit")
                {
                    var bytes = new ArraySegment<byte>(Encoding.UTF8.GetBytes(input));
                    await webSocket.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None).ConfigureAwait(false);
                    input = Console.ReadLine();
                }
                await Console.Out.WriteLineAsync("Goodbye.").ConfigureAwait(false);
            }
            catch (Exception e)
            {
                await Console.Out.WriteLineAsync(e.ToString()).ConfigureAwait(false);
            }
        }

        private static void Receive(WebSocket websocket)
        {
            ArraySegment<Byte> buffer = new ArraySegment<byte>(new Byte[8192]);

            WebSocketReceiveResult result = null;

            using (var ms = new MemoryStream())
            {
                do
                {
                    result = websocket.ReceiveAsync(buffer, CancellationToken.None).Result;
                    ms.Write(buffer.Array, buffer.Offset, result.Count);
                }
                while (!result.EndOfMessage);

                ms.Seek(0, SeekOrigin.Begin);

                if (result.MessageType == WebSocketMessageType.Text)
                {
                    using (var reader = new StreamReader(ms, Encoding.UTF8))
                    {
                        Console.Out.WriteLine(reader.ReadToEnd());
                    }
                }
            }

            Receive(websocket);
        }
    }
}
