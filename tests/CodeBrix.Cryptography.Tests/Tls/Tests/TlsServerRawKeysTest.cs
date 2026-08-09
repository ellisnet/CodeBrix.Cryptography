using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using CodeBrix.Cryptography.Tls.Crypto.Impl.BC;
using CodeBrix.Cryptography.Utilities.IO;
using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests; //was previously: Org.BouncyCastle.Tls.Tests;

/// <summary>A simple test designed to conduct a TLS handshake with an external TLS client.</summary>
/// <remarks>
/// <code>
/// gnutls-cli --rawpkkeyfile ed25519.priv --rawpkfile ed25519.pub --priority NORMAL:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK --insecure --debug 10 --port 5556 localhost
/// </code>
/// </remarks>
public class TlsServerRawKeysTest
{
    [Fact(Skip = "Explicit test in the upstream NUnit suite; not run by default. Remove Skip to run it.")]
    public void TestConnection()
    {
        int port = 5556;
        ProtocolVersion[] tlsVersions = ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12);

        TcpListener ss = new TcpListener(IPAddress.Any, port);
        ss.Start();
        Stream stdout = Console.OpenStandardOutput();
        try
        {
            foreach (var tlsVersion in tlsVersions)
            {
                TcpClient s = ss.AcceptTcpClient();
                Console.WriteLine("--------------------------------------------------------------------------------");
                Console.WriteLine("Accepted " + s);
                ServerTask serverTask = new ServerTask(s, stdout, tlsVersion);
                Thread t = new Thread(serverTask.Run);
                t.Start();
            }
        }
        finally
        {
            ss.Stop();
        }
    }

    internal class ServerTask
    {
        private readonly TcpClient s;
        private readonly Stream stdout;
        private readonly ProtocolVersion tlsVersion;

        internal ServerTask(TcpClient s, Stream stdout, ProtocolVersion tlsVersion)
        {
            this.s = s;
            this.stdout = stdout;
            this.tlsVersion = tlsVersion;
        }

        public void Run()
        {
            try
            {
                MockRawKeysTlsServer server = new MockRawKeysTlsServer(new BcTlsCrypto(),
                    CertificateType.RawPublicKey, CertificateType.RawPublicKey,
                    new short[]{ CertificateType.RawPublicKey }, tlsVersion);
                TlsServerProtocol serverProtocol = new TlsServerProtocol(s.GetStream());
                serverProtocol.Accept(server);

                using (var stream = serverProtocol.Stream)
                {
                    // NB: We don't dispose this directly to avoid disposing stdout
                    Stream log = new TeeOutputStream(stream, stdout);

                    Streams.PipeAll(stream, log);
                }
            }
            finally
            {
                try
                {
                    s.Close();
                }
                catch (IOException)
                {
                }
            }
        }
    }
}
