using System;
using System.Threading;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Tls.Crypto;
using CodeBrix.Cryptography.Tls.Crypto.Impl.BC;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.IO;
using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests; //was previously: Org.BouncyCastle.Tls.Tests;

public class TlsRawKeysProtocolTest
{
    protected readonly SecureRandom Random = new SecureRandom();

    [Fact]
    public void TestClientSendsExtensionButServerDoesNotSupportIt()
    {
        TestClientSendsExtensionButServerDoesNotSupportItImpl(ProtocolVersion.TLSv12);
    }

    [Fact]
    public void TestClientSendsExtensionButServerDoesNotSupportIt_13()
    {
        TestClientSendsExtensionButServerDoesNotSupportItImpl(ProtocolVersion.TLSv13);
    }

    private void TestClientSendsExtensionButServerDoesNotSupportItImpl(ProtocolVersion tlsVersion)
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.X509, -1,
            new short[]{ CertificateType.RawPublicKey, CertificateType.X509 }, null, tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509, -1, null,
            tlsVersion);
        PumpData(client, server);
    }

    [Fact]
    public void TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509()
    {
        TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509Impl(ProtocolVersion.TLSv12);
    }

    [Fact]
    public void TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509_13()
    {
        TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509Impl(ProtocolVersion.TLSv13);
    }

    private void TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509Impl(ProtocolVersion tlsVersion)
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.X509,
            CertificateType.X509, new short[]{ CertificateType.X509 }, new short[]{ CertificateType.X509 },
            tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509,
            CertificateType.X509, new short[]{ CertificateType.X509 }, tlsVersion);
        PumpData(client, server);

        Assert.False(server.m_receivedClientExtensions.ContainsKey(ExtensionType.client_certificate_type), "client cert type extension should not be sent");
        Assert.False(server.m_receivedClientExtensions.ContainsKey(ExtensionType.server_certificate_type), "server cert type extension should not be sent");
    }

    [Fact]
    public void TestBothSidesUseRawKey()
    {
        TestBothSidesUseRawKeyImpl(ProtocolVersion.TLSv12);
    }

    [Fact]
    public void TestBothSidesUseRawKey_13()
    {
        TestBothSidesUseRawKeyImpl(ProtocolVersion.TLSv13);
    }

    private void TestBothSidesUseRawKeyImpl(ProtocolVersion tlsVersion)
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.RawPublicKey,
            CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey },
            new short[]{ CertificateType.RawPublicKey }, tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.RawPublicKey,
            CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, tlsVersion);
        PumpData(client, server);
    }

    [Fact]
    public void TestServerUsesRawKeyAndClientIsAnonymous()
    {
        TestServerUsesRawKeyAndClientIsAnonymousImpl(ProtocolVersion.TLSv12);
    }

    [Fact]
    public void TestServerUsesRawKeyAndClientIsAnonymous_13()
    {
        TestServerUsesRawKeyAndClientIsAnonymousImpl(ProtocolVersion.TLSv13);
    }

    private void TestServerUsesRawKeyAndClientIsAnonymousImpl(ProtocolVersion tlsVersion)
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.RawPublicKey, -1,
            new short[]{ CertificateType.RawPublicKey }, null, tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.RawPublicKey, -1,
            null, tlsVersion);
        PumpData(client, server);
    }

    [Fact]
    public void TestServerUsesRawKeyAndClientUsesX509()
    {
        TestServerUsesRawKeyAndClientUsesX509Impl(ProtocolVersion.TLSv12);
    }

    [Fact]
    public void TestServerUsesRawKeyAndClientUsesX509_13()
    {
        TestServerUsesRawKeyAndClientUsesX509Impl(ProtocolVersion.TLSv13);
    }

    private void TestServerUsesRawKeyAndClientUsesX509Impl(ProtocolVersion tlsVersion)
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.RawPublicKey,
            CertificateType.X509, new short[]{ CertificateType.RawPublicKey }, null, tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.RawPublicKey,
            CertificateType.X509, null, tlsVersion);
        PumpData(client, server);
    }

    [Fact]
    public void TestServerUsesX509AndClientUsesRawKey()
    {
        TestServerUsesX509AndClientUsesRawKeyImpl(ProtocolVersion.TLSv12);
    }

    [Fact]
    public void TestServerUsesX509AndClientUsesRawKey_13()
    {
        TestServerUsesX509AndClientUsesRawKeyImpl(ProtocolVersion.TLSv13);
    }

    private void TestServerUsesX509AndClientUsesRawKeyImpl(ProtocolVersion tlsVersion)
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.X509,
            CertificateType.RawPublicKey, null, new short[]{ CertificateType.RawPublicKey }, tlsVersion);
        MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509,
            CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, tlsVersion);
        PumpData(client, server);
    }

    [Fact]
    public void TestClientSendsClientCertExtensionButServerHasNoCommonTypes()
    {
        TestClientSendsClientCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion.TLSv12);
    }

    [Fact]
    public void TestClientSendsClientCertExtensionButServerHasNoCommonTypes_13()
    {
        TestClientSendsClientCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion.TLSv13);
    }

    private void TestClientSendsClientCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion tlsVersion)
    {
        try
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.X509,
                CertificateType.RawPublicKey, null, new short[]{ CertificateType.RawPublicKey }, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509,
                CertificateType.X509, new short[]{ CertificateType.X509 }, tlsVersion);
            PumpData(client, server);
            Assert.Fail("Should have caused unsupported_certificate alert");
        }
        catch (TlsFatalAlertReceived alert)
        {
            Assert.Equal(AlertDescription.unsupported_certificate, alert.AlertDescription);
        }
    }

    [Fact]
    public void TestClientSendsServerCertExtensionButServerHasNoCommonTypes()
    {
        TestClientSendsServerCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion.TLSv12);
    }

    [Fact]
    public void TestClientSendsServerCertExtensionButServerHasNoCommonTypes_13()
    {
        TestClientSendsServerCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion.TLSv13);
    }

    private void TestClientSendsServerCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion tlsVersion)
    {
        try
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.RawPublicKey,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, null, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, tlsVersion);
            PumpData(client, server);
            Assert.Fail("Should have caused unsupported_certificate alert");
        }
        catch (TlsFatalAlertReceived alert)
        {
            Assert.Equal(AlertDescription.unsupported_certificate, alert.AlertDescription);
        }
    }

    protected virtual TlsCrypto CreateCrypto() => new BcTlsCrypto(Random);

    private void PumpData(TlsClient client, TlsServer server)
    {
        PipedStream clientPipe = new PipedStream();
        PipedStream serverPipe = new PipedStream(clientPipe);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

        ServerTask serverTask = new ServerTask(serverProtocol, server);

        Thread serverThread = new Thread(serverTask.Run);
        serverThread.Start();

        clientProtocol.Connect(client);

        // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
        int length = 1000;

        byte[] data = new byte[length];
        Random.NextBytes(data);

        using (var stream = clientProtocol.Stream)
        {
            stream.Write(data, 0, data.Length);

            byte[] echo = new byte[data.Length];
            int count = Streams.ReadFully(stream, echo);

            Assert.Equal(count, data.Length);
            Assert.True(Arrays.AreEqual(data, echo));
        }

        serverThread.Join();
    }

    internal class ServerTask
    {
        private readonly TlsServerProtocol m_serverProtocol;
        private readonly TlsServer m_server;

        internal ServerTask(TlsServerProtocol serverProtocol, TlsServer server)
        {
            m_serverProtocol = serverProtocol;
            m_server = server;
        }

        public void Run()
        {
            try
            {
                m_serverProtocol.Accept(m_server);

                using (var stream = m_serverProtocol.Stream)
                {
                    Streams.PipeAll(stream, stream);
                }
            }
            catch (Exception)
            {
            }
        }
    }
}
