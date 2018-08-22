# XamarinWebsocketTls
Demonstrate TLS 1.2 issue with custom Certification Authority Certificates in Xamarin Android.

This is the sample code for [Stack Overflow Question Xamarin Android: Native TLS, ClientWebSocket, with Custom Certificate Authority Certificate Validation Fails](https://stackoverflow.com/questions/51967177/xamarin-android-native-tls-clientwebsocket-with-custom-certificate-authority)

Included is a sample_ca Certification Authority in all common formats. The code in the FleckServer project will use this CA to generate a client certificate with Subject Alternative Names (SAN) that are bound to your IP addresses and hostname, then host a Fleck WebSocket server using this client certificate under TLS 1.2.

You can make the Android application connect under TLS 1.2 if you install the sample_ca.cer to the android device via Settings->Security->Install from SD Card.  This, however, is undesired for multiple reasons.  Ultimately, an app specific means of connecting to a websocket with a custom CA is desired.  
