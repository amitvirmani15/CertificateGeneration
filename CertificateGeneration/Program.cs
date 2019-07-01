
namespace CertificateGeneration
{
    class Program
    {
        static void Main(string[] args)
        {
            var bouncyCastle = new BouncyCastle();
            bouncyCastle.GenerateCertUsingExistigCertificate();

            //bouncyCastle.GenerateCertUsingExistigCertificate();

            var certRequestNet = new CertificateRequestNet();
            certRequestNet.GenerateHierrachyUsingNetClass();

        }

        
    }
}
