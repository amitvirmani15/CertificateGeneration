using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;


namespace CertificateGeneration
{
    public class CertificateRequestNet
    {
        public void GenerateHierrachyUsingNetClass()
        {
            using (RSA parent = RSA.Create(4096))
            using (RSA rsa = RSA.Create(2048))
            {

                System.Security.Cryptography.X509Certificates.CertificateRequest parentReq = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                    "CN=Experimental Issuing Authority",
                    parent,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                parentReq.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(true, false, 0, true));

                parentReq.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));
                //var csr = parentReq.CreateSigningRequest();

                using (X509Certificate2 parentCert = parentReq.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddDays(-45),
                    DateTimeOffset.UtcNow.AddDays(365)))
                {

                    CertificateRequest req = new CertificateRequest(
                        "CN=Valid-Looking Timestamp Authority",
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    req.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(true, false, 0, false));

                    req.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                            false));

                    //https://pkisolutions.com/object-identifiers-oid-in-pki/
                    //https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/supported-extensions
                    req.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new OidCollection
                            {
                                new Oid("1.3.6.1.5.5.7.3.8")
                            },
                            true));

                    req.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
                    req.CreateSigningRequest();
                    using (X509Certificate2 cert = req.Create(
                        parentCert,
                        DateTimeOffset.UtcNow.AddDays(-1),
                        DateTimeOffset.UtcNow.AddDays(90),
                        new byte[] { 1, 2, 3, 4 }))
                    {
                        // Do something with these certs, like export them to PFX,
                        // or add them to an X509Store, or whatever.
                    }

                    using (X509Certificate2 cert = req.Create(
                        parentCert,
                        DateTimeOffset.UtcNow.AddDays(-1),
                        DateTimeOffset.UtcNow.AddDays(90),
                        new byte[] { 1, 2, 3, 4 }))
                    {
                        // Do something with these certs, like export them to PFX,
                        // or add them to an X509Store, or whatever.
                    }
                }
            }
        }

        public void CertificateSigningRequest()
        {
            using (RSA parent = RSA.Create(4096))
            using (RSA rsa = RSA.Create(2048))
            {

                System.Security.Cryptography.X509Certificates.CertificateRequest parentReq = new CertificateRequest(
                    "CN=Experimental Issuing Authority",
                    parent,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                parentReq.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(true, false, 0, true));

                parentReq.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));
                //var csr = parentReq.CreateSigningRequest();

                using (X509Certificate2 parentCert = parentReq.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddDays(-45),
                    DateTimeOffset.UtcNow.AddDays(365)))
                {

                    CertificateRequest req = new CertificateRequest(
                        "CN=Valid-Looking Timestamp Authority",
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    req.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(true, false, 0, false));

                    req.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                            false));

                    //https://pkisolutions.com/object-identifiers-oid-in-pki/
                    //https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/supported-extensions
                    req.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new OidCollection
                            {
                                new Oid("1.3.6.1.5.5.7.3.8")
                            },
                            true));

                    req.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
                    req.CreateSigningRequest();
                    using (X509Certificate2 cert = req.Create(
                        parentCert,
                        DateTimeOffset.UtcNow.AddDays(-1),
                        DateTimeOffset.UtcNow.AddDays(90),
                        new byte[] { 1, 2, 3, 4 }))
                    {
                        // Do something with these certs, like export them to PFX,
                        // or add them to an X509Store, or whatever.
                    }

                    using (X509Certificate2 cert = req.Create(
                        parentCert,
                        DateTimeOffset.UtcNow.AddDays(-1),
                        DateTimeOffset.UtcNow.AddDays(90),
                        new byte[] { 1, 2, 3, 4 }))
                    {
                        // Do something with these certs, like export them to PFX,
                        // or add them to an X509Store, or whatever.
                    }
                }
            }
        }
    }
}
