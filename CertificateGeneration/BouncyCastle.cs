using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using crypto;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace CertificateGeneration
{
    public class BouncyCastle
    {
        public void GenerateNewCertUsingBouncyCastle()
        {
            X509KeyUsageExtension var = new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DecipherOnly | X509KeyUsageFlags.KeyCertSign, true);

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var cert = new X509V3CertificateGenerator();
            var serialNumber =
                BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            cert.SetSerialNumber(serialNumber);

            var subjectDN = new X509Name("CN=test");

            cert.SetIssuerDN(subjectDN);
            cert.SetSubjectDN(subjectDN);

            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(10);

            cert.SetNotBefore(notBefore);
            cert.SetNotAfter(notAfter);

            const int strength = 2048;
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            cert.SetPublicKey(subjectKeyPair.Public);
            cert.SetSignatureAlgorithm("SHA256withRSA");


            var certificate = cert.Generate(subjectKeyPair.Private, random);

            var certexp = new X509Certificate2(certificate.GetEncoded(), "1234");
            certexp.Extensions.Add(var);
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(certexp);
            File.WriteAllBytes(@"C:\cmstest\test.pfx", certexp
                .Export(X509ContentType.Pfx, "1234"));
        }

        public void GenerateUsingCsr()
        {

            var root = File.ReadAllBytes(@"root.pfx");
            X509KeyUsageExtension var = new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DecipherOnly | X509KeyUsageFlags.KeyCertSign, true);

            var x509RootCert = new X509Certificate2(root, "airwatch",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var cert = new X509V3CertificateGenerator();
            var csr = string.Empty;
            var textReader = new StringReader(csr);
            var reader = new Org.BouncyCastle.OpenSsl.PemReader(textReader);
            var csrRequestObject = reader.ReadObject() as Pkcs10CertificationRequest;
            if (csrRequestObject != null)
            {
                var csrInfo = csrRequestObject.GetCertificationRequestInfo();
                csrInfo.SubjectPublicKeyInfo.GetPublicKey();
                cert.SetPublicKey(PublicKeyFactory.CreateKey(csrInfo.SubjectPublicKeyInfo));
            }
            cert.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage((int) 0));
            var asn1EncodableVector = new Asn1EncodableVector
            {
                new DerObjectIdentifier("1.3.6.1.4.1.311.20.2.1")
            };
            var derSeq = new DerSequence(asn1EncodableVector);
            cert.AddExtension(X509Extensions.AuthorityInfoAccess, false, derSeq);
            cert.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(true));
            var privatekey = x509RootCert.PrivateKey as RSACryptoServiceProvider;
            var ss = privatekey.ExportParameters(true);
            IRsa rsa = new RsaCoreEngine();
            rsa.Init(true, new RsaKeyParameters(true, new BigInteger(1, ss.Modulus), new BigInteger(1, ss.Exponent)));
            //var signer = new RsaDigestSigner(rsa, new Sha512Digest(),
            //    new AlgorithmIdentifier(new DerObjectIdentifier("1.3.6.1.4.1.311.20.2.1")));

            //(signingKeyPair, properties.SignatureAlgorithm);
            X509Extension extension = new X509Extension(false, new DerOctetString(new AuthorityKeyIdentifierStructure(new X509Certificate(X509CertificateStructure.GetInstance(root)))));
            cert.AddExtension(X509Extensions.CertificateIssuer, true, new AuthorityKeyIdentifierStructure(new X509Certificate(X509CertificateStructure.GetInstance(root))));
            var serialNumber =
                BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            cert.SetSerialNumber(serialNumber);

            var subjectDN = new X509Name("CN=test");

            cert.SetIssuerDN(subjectDN);
            cert.SetSubjectDN(subjectDN);

            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(10);

            cert.SetNotBefore(notBefore);
            cert.SetNotAfter(notAfter);

            const int strength = 2048;
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            cert.SetPublicKey(subjectKeyPair.Public);
            cert.SetSignatureAlgorithm("SHA256withRSA");


            var certificate = cert.Generate(subjectKeyPair.Private, random);

            var certexp = new X509Certificate2(certificate.GetEncoded(), "1234");
            certexp.Extensions.Add(var);
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(certexp);
            File.WriteAllBytes(@"C:\cmstest\test.pfx", certexp
                .Export(X509ContentType.Pfx, "1234"));
        }

        public void GenerateCertUsingExistigCertificate()
        {

            var root = File.ReadAllBytes(@"root.pfx");
            var childRoot = File.ReadAllBytes(@"childroot.pfx");
            X509KeyUsageExtension var = new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DecipherOnly | X509KeyUsageFlags.KeyCertSign, true);
            var x509ChildCertificate = new X509Certificate2(childRoot, "airwatch",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
            var x509RootCert = new X509Certificate2(root, "airwatch",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var cert = new X509V3CertificateGenerator();
            var serialNumber =
                BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            cert.SetSerialNumber(serialNumber);
            var rootSubject = new X509Name(x509RootCert.SubjectName.Name);
            var subjectDN = new X509Name(x509ChildCertificate.SubjectName.Name);

            cert.SetIssuerDN(rootSubject);
            cert.SetSubjectDN(subjectDN);
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(10);

            cert.SetNotBefore(notBefore);
            cert.SetNotAfter(notAfter);
            //var x509Certificate = new X509Certificate(X509CertificateStructure.GetInstance(new DerTaggedObject(x509RootCert, new )))
            cert.SetSignatureAlgorithm("SHA256withRSA");
            cert.SetPublicKey(TransformRSAPublicKey(x509ChildCertificate.PublicKey.Key, false));
            cert.AddExtension(X509Extensions.AuthorityKeyIdentifier, true, new AuthorityKeyIdentifierStructure(new X509CertificateParser().ReadCertificate(x509RootCert.RawData)));
            //new X509CertificateParser().ReadCertificate(x509RootCert.RawData);
            //var factory = new Asn1SignatureFactory(SHA256.Create().ToString(), TransformRSAPrivateKey(x509RootCert.PrivateKey, true));
            var certificate = cert.Generate(TransformRSAPrivateKey(x509RootCert.PrivateKey, true), random);

            x509ChildCertificate.Extensions.Add(var);

            var certexp = new X509Certificate2(certificate.GetEncoded(), "1234");
            //var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            //store.Open(OpenFlags.ReadWrite);
            //store.Add(certexp);
            var chain = new X509Chain(true);
            chain.Build(certexp);
            File.WriteAllBytes(@"C:\cmstest\test.pfx", certexp
                .Export(X509ContentType.Pfx, "1234"));
        }

        public AsymmetricKeyParameter TransformRSAPrivateKey(AsymmetricAlgorithm privateKey, bool isPrivate)
        {
            RSACryptoServiceProvider prov = privateKey as RSACryptoServiceProvider;
            RSAParameters parameters = prov.ExportParameters(isPrivate);

            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, parameters.Modulus),
                new BigInteger(1, parameters.Exponent),
                new BigInteger(1, parameters.D),
                new BigInteger(1, parameters.P),
                new BigInteger(1, parameters.Q),
                new BigInteger(1, parameters.DP),
                new BigInteger(1, parameters.DQ),
                new BigInteger(1, parameters.InverseQ));
        }

        public AsymmetricKeyParameter TransformRSAPublicKey(AsymmetricAlgorithm privateKey, bool isPrivate)
        {
            RSACryptoServiceProvider prov = privateKey as RSACryptoServiceProvider;
            RSAParameters parameters = prov.ExportParameters(isPrivate);

            return new RsaKeyParameters(false, new BigInteger(1, parameters.Modulus),
                new BigInteger(1, parameters.Exponent));
        }
}
}
        
    
