using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.ConstrainedExecution;

namespace certreq
{
    public class Request
    {
        public string GenerateCSR()
        {
            string subjectName =
               "CN=www.companyName.com,O=Company Name,OU=Department,T=Area,ST=State,C=Country";

            RSACryptoServiceProvider cryptoServiceProvider =
               new RSACryptoServiceProvider(4096);

            string pk = cryptoServiceProvider.ExportRSAPrivateKeyPem();

            File.WriteAllText("c:\\ws\\key.pem", pk);

            CertificateRequest certificateRequest =
               new CertificateRequest(subjectName,
                  cryptoServiceProvider, HashAlgorithmName.SHA256,
                  RSASignaturePadding.Pkcs1);



            List<string> hosts = new List<string>();

            var sanBuilder = new SubjectAlternativeNameBuilder();
            hosts.ToList().ForEach(sanBuilder.AddDnsName);
            certificateRequest.CertificateExtensions.Add(sanBuilder.Build());

            

            return DERtoPEM(
                  certificateRequest.CreateSigningRequest(
                     X509SignatureGenerator.CreateForRSA(
                        cryptoServiceProvider,
            RSASignaturePadding.Pkcs1)));

            
        }

        public void generatePfx(string pk, X509Certificate2 signed)
        {
            RSACryptoServiceProvider cryptoServiceProvider =
               new RSACryptoServiceProvider(4096);
            cryptoServiceProvider.ImportFromPem(pk);


            var cert = RSACertificateExtensions.CopyWithPrivateKey(signed, cryptoServiceProvider);
             File.WriteAllBytes("c:\\exp.pfx", cert.Export(X509ContentType.Pfx, ""));
        }

        private string DERtoPEM(byte[] bytesDER)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");

            string base64 = Convert.ToBase64String(bytesDER);

            int offset = 0;
            const int LineLength = 64;
            while (offset  < base64.Length)
         {
                int lineEnd = Math.Min(offset + LineLength, base64.Length);
                builder.AppendLine(
                   base64.Substring(offset, lineEnd - offset));
                offset = lineEnd;
            }

            builder.AppendLine("-----END CERTIFICATE REQUEST-----");
            return builder.ToString();
        }
    }
}
