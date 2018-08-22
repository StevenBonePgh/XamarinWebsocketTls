using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace FleckServer
{
    public static class CertUtilities
    {
        public static void WritePfxCertificate(X509Certificate2 certificate, string outputPfxFileName, string password)
        {
            // This password is the one attached to the PFX file. Use 'null' for no password.
            var bytes = certificate.Export(X509ContentType.Pfx, password);
            File.WriteAllBytes(outputPfxFileName, bytes);
        }

        public static void WritePublicCertificate(X509Certificate2 certificate, string outputCerFileName)
        {
            var bytes = certificate.Export(X509ContentType.Cert, null as string);
            File.WriteAllBytes(outputCerFileName, bytes);
        }

        public static void WritePemCertificate(X509Certificate2 certificate, string outputPemFileName)
        {
            var bcCert = DotNetUtilities.FromX509Certificate(certificate);

            Stream fs = null;
            try
            {
                fs = new FileStream(outputPemFileName, FileMode.Create);
                using (TextWriter w = new StreamWriter(fs))
                {
                    fs = null;//prevent double release CA2202
                    var pw = new PemWriter(w);
                    pw.WriteObject(bcCert);
                }
            }
            finally
            {
                if (fs != null)
                    fs.Dispose();
            }
        }

        public static void WritePemPrivateKey(AsymmetricCipherKeyPair certificateSubjectKeyPair, string outputPemFileName)
        {
            Stream fs = null;
            try
            {
                // ReSharper disable ExceptionNotDocumented
                fs = new FileStream(outputPemFileName, FileMode.Create);
                // ReSharper restore ExceptionNotDocumented
                using (TextWriter w = new StreamWriter(fs))
                {
                    fs = null;//prevent double release CA2202
                    var pw = new PemWriter(w);
                    pw.WriteObject(certificateSubjectKeyPair.Private);
                }
            }
            finally
            {
                if (fs != null)
                    fs.Dispose();
            }
        }

        public static X509Certificate2 IssueCert(string pathToPfxFile, string password, string commonName, out AsymmetricCipherKeyPair certificateSubjectKeyPair)
        {
            var issuerCertificate = new X509Certificate2(pathToPfxFile, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            if (!issuerCertificate.HasPrivateKey)
                throw new InvalidOperationException("The authority's .pfx file does not have a private key.");

            var keyUsages = KeyUsage.DataEncipherment | KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature;
            var extendedKeyUsages = new List<KeyPurposeID>(new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth });

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            certificateSubjectKeyPair = GenerateRsaKeyPair(random, 2048);
            var subjectSerialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            var subjectDn = $"C=US,ST=NY,L=New York,STREET=123 Main St,E=certs@sample.com,O=Sample Certs,OU=MegaCorp,CN={commonName}";
            var bcIssuerCertificate = DotNetUtilities.FromX509Certificate(issuerCertificate);
            var issuerDn = bcIssuerCertificate.SubjectDN.ToString();
            var issuerKeyPair = DotNetUtilities.GetKeyPair(issuerCertificate.PrivateKey);
            var signatureAlgorithmName = bcIssuerCertificate.SigAlgOid;

            var certificate = GenerateCertificate(random, subjectDn, certificateSubjectKeyPair, subjectSerialNumber,
                                                  GetAllSan(), issuerDn, issuerKeyPair, keyUsages, extendedKeyUsages, 30, signatureAlgorithmName);

            var convertedCertificate = ConvertCertificate(certificate, certificateSubjectKeyPair, random);
            convertedCertificate.FriendlyName = commonName;
            return convertedCertificate;
        }

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(SecureRandom random, int strength)
        {
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            return subjectKeyPair;
        }

        private static X509Certificate2 ConvertCertificate(Org.BouncyCastle.X509.X509Certificate certificate, AsymmetricCipherKeyPair subjectKeyPair, SecureRandom random)
        {
            // Now to convert the Bouncy Castle certificate to a .NET certificate. Basically, we create a PKCS12 store (a .PFX file) in memory, 
            // and add the public and private key to that.
            var store = new Pkcs12Store();

            // What Bouncy Castle calls "alias" is the same as what Windows terms the "friendly name".
            string friendlyName = certificate.SubjectDN.ToString();

            // Add the certificate.
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);

            // Add the private key.
            var keyEntry = new AsymmetricKeyEntry(subjectKeyPair.Private);
            store.SetKeyEntry(friendlyName, keyEntry, new[] { certificateEntry });

            // Convert it to an X509Certificate2 object by saving/loading it from a MemoryStream.
            // It needs a password. Since we'll remove this when the certificate is loaded as a X509Certificate2, 
            // it doesn't particularly matter what we use.
            var stream = new MemoryStream();
            var passwordString = "temp";
            var passwordChars = passwordString.ToCharArray();
            store.Save(stream, passwordChars, random);

            var convertedCertificate = new X509Certificate2(stream.ToArray(), passwordString, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
            return convertedCertificate;
        }

        private static List<string> GetAllSan()
        {
            var requiredSubjectAlternativeNamesDict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            requiredSubjectAlternativeNamesDict[Environment.MachineName] = null;
            requiredSubjectAlternativeNamesDict["localhost"] = null;
            requiredSubjectAlternativeNamesDict["127.0.0.1"] = null;
            foreach (IPAddress localIp in Dns.GetHostAddresses(Dns.GetHostName()))
            {
                if (!(localIp.IsIPv6LinkLocal || localIp.IsIPv6Multicast || localIp.IsIPv6SiteLocal || localIp.IsIPv6Teredo) &&
                    localIp.AddressFamily == AddressFamily.InterNetwork)
                {
                    var localIpString = localIp.ToString();
                    requiredSubjectAlternativeNamesDict[localIpString] = null;
                }
            }
            return new List<string>(requiredSubjectAlternativeNamesDict.Keys);
        }

        private static Org.BouncyCastle.X509.X509Certificate GenerateCertificate(SecureRandom random, string subjectDN, AsymmetricCipherKeyPair subjectKeyPair,
                                                            BigInteger subjectSerialNumber, IEnumerable<string> subjectAlternativeNames,
                                                            string issuerDN, AsymmetricCipherKeyPair issuerKeyPair, int keyUsages,
                                                            List<KeyPurposeID> extendedKeyUsages, int yearsValid, string signatureAlgorithmName)
        {
            var certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetSerialNumber(subjectSerialNumber);
            var signatureFactory = new Asn1SignatureFactory(signatureAlgorithmName, issuerKeyPair.Private, random);
            var issuerDN509 = new X509Name(issuerDN);
            certificateGenerator.SetIssuerDN(issuerDN509);

            var subjectDN509 = new X509Name(subjectDN);
            certificateGenerator.SetSubjectDN(subjectDN509);

            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(yearsValid);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);
            var subjectKeyIdentifierExtension = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifierExtension);

            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(false));

            // http://tools.ietf.org/html/rfc5280#section-4.2.1.3
            if (keyUsages > 0)
                certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(keyUsages));

            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(extendedKeyUsages.ToArray()));
            AddSubjectAlternativeNames(certificateGenerator, subjectAlternativeNames);

            var certificate = certificateGenerator.Generate(signatureFactory);
            return certificate;
        }

        private static void AddSubjectAlternativeNames(X509V3CertificateGenerator certificateGenerator, IEnumerable<string> subjectAlternativeNames)
        {
            if (subjectAlternativeNames == null)
                return;
            var list = new List<Asn1Encodable>();
            foreach (string name in subjectAlternativeNames)
            {
                if (string.IsNullOrEmpty(name))
                    continue;
                IPAddress addr;
                if (IPAddress.TryParse(name, out addr))
                {
                    list.Add(new GeneralName(GeneralName.IPAddress, name));
                    // This is a *sigh*... An IP address should be sufficient for a client to accept the certificate, but
                    // Microsoft clients (IE, .NET, etc.) don't validate the cert properly.  Chrome uses the IP properly.
                    // To work around this, we add the IP address as a DNS name also. 
                    list.Add(new GeneralName(GeneralName.DnsName, name));
                }
                else
                {
                    if (!name.Contains(" "))
                        list.Add(new GeneralName(GeneralName.DnsName, name));
                }
            }
            if (list.Count == 0)
                return;
            var subjectAlternativeNamesExtension = new DerSequence(list.ToArray());
            certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);
        }
    }
}
