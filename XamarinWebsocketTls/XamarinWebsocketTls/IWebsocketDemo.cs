using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks;

namespace XamarinWebsocketTls
{
    public interface IWebsocketDemo : INotifyPropertyChanged
    {
        void Connect();

        bool IsConnected { get; }

        bool UseTls { get; set; }

        bool AddCertToStore { get; set; }

        string HostName { get; set; }

        bool UseServerValidationCallback { get; set; }

        string Messages { get; }

        void SendMessage(string message);

        void ClearMessages();
    }
}
