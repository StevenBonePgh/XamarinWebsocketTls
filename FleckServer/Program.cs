using Fleck;
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Authentication;

namespace FleckServer
{
    class Program
    {
        static void Main(string[] args)
        {
            var useTls = true;

            List<IWebSocketConnection> sockets = new List<IWebSocketConnection>();
            var commonName = "Sample Cert";
            var password = "password";

            //Issue certificate from the CA and write the cert files to disk.
            var cert = CertUtilities.IssueCert("sample_ca.pfx", password, commonName, out var keyPair);
            var fileName = commonName.ToLower().Replace(" ", "_");
            CertUtilities.WritePfxCertificate(cert, fileName + ".pfx", password);
            CertUtilities.WritePublicCertificate(cert, fileName + ".cer");
            CertUtilities.WritePemCertificate(cert, fileName + ".public.pem");
            CertUtilities.WritePemPrivateKey(keyPair, fileName + ".private.pem");

            var uriPrefix = useTls ? "wss:" : "ws:";
            WebSocketServer server  = new WebSocketServer($"{uriPrefix}//0.0.0.0:8181");
            if(useTls)
            {
                server.Certificate         = cert;
                server.EnabledSslProtocols = SslProtocols.Tls12;
            }
            server.RestartAfterListenError = true;
            server.Start(socket =>
            {
                socket.OnOpen = () =>
                {
                    Console.WriteLine("Connection open.");
                    sockets.Add(socket);
                };
                socket.OnClose = () =>
                {
                    Console.WriteLine("Connection closed.");
                    sockets.Remove(socket);
                };
                socket.OnMessage = message =>
                {
                    Console.WriteLine("Client Says: " + message);
                    sockets.ToList().ForEach(s => s.Send(" client says: " + message));
                };
            });

            string input = Console.ReadLine();
            while (input != "exit")
            {
                sockets.ToList().ForEach(s => s.Send(input));
                input = Console.ReadLine();
            }
        }


    }
}
