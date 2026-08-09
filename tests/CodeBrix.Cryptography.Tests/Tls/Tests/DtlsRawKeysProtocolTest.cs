using System;
using System.Threading;
using CodeBrix.Cryptography.Security;
using CodeBrix.Cryptography.Tls.Crypto;
using CodeBrix.Cryptography.Tls.Crypto.Impl.BC;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests; //was previously: Org.BouncyCastle.Tls.Tests;

public class DtlsRawKeysProtocolTest
{
    protected readonly SecureRandom Random = new SecureRandom();

    [Fact]
    public void TestClientSendsExtensionButServerDoesNotSupportIt()
    {
        TestClientSendsExtensionButServerDoesNotSupportItImpl(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
    //[Test]
    //public void TestClientSendsExtensionButServerDoesNotSupportIt_13()
    //{
    //    TestClientSendsExtensionButServerDoesNotSupportItImpl(ProtocolVersion.DTLSv13);
    //}

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
        TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509Impl(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
    //[Test]
    //public void TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509_13()
    //{
    //    TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509Impl(ProtocolVersion.DTLSv13);
    //}

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
        TestBothSidesUseRawKeyImpl(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
    //[Test]
    //public void TestBothSidesUseRawKey_13()
    //{
    //    TestBothSidesUseRawKeyImpl(ProtocolVersion.DTLSv13);
    //}

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
        TestServerUsesRawKeyAndClientIsAnonymousImpl(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
    //[Test]
    //public void TestServerUsesRawKeyAndClientIsAnonymous_13()
    //{
    //    TestServerUsesRawKeyAndClientIsAnonymousImpl(ProtocolVersion.DTLSv13);
    //}

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
        TestServerUsesRawKeyAndClientUsesX509Impl(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
    //[Test]
    //public void TestServerUsesRawKeyAndClientUsesX509_13()
    //{
    //    TestServerUsesRawKeyAndClientUsesX509Impl(ProtocolVersion.DTLSv13);
    //}

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
        TestServerUsesX509AndClientUsesRawKeyImpl(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
    //[Test]
    //public void TestServerUsesX509AndClientUsesRawKey_13()
    //{
    //    TestServerUsesX509AndClientUsesRawKeyImpl(ProtocolVersion.DTLSv13);
    //}

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
        TestClientSendsClientCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
    //[Test]
    //public void TestClientSendsClientCertExtensionButServerHasNoCommonTypes_13()
    //{
    //    TestClientSendsClientCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion.DTLSv13);
    //}

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
        TestClientSendsServerCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion.DTLSv12);
    }

    // TODO[dtls13]
    //[Test]
    //public void TestClientSendsServerCertExtensionButServerHasNoCommonTypes_13()
    //{
    //    TestClientSendsServerCertExtensionButServerHasNoCommonTypesImpl(ProtocolVersion.DTLSv13);
    //}

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
        DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
        DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerTask serverTask = new ServerTask(serverProtocol, server, network.Server);

        Thread serverThread = new Thread(serverTask.Run);
        serverThread.Start();

        DatagramTransport clientTransport = network.Client;

        clientTransport = new UnreliableDatagramTransport(clientTransport, Random, 0, 0);

        clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);

        DtlsTransport dtlsClient = clientProtocol.Connect(client, clientTransport);

        for (int i = 1; i <= 10; ++i)
        {
            byte[] data = new byte[i];
            Arrays.Fill(data, (byte)i);
            dtlsClient.Send(data, 0, data.Length);
        }

        byte[] buf = new byte[dtlsClient.GetReceiveLimit()];
        while (dtlsClient.Receive(buf, 0, buf.Length, 100) >= 0)
        {
        }

        dtlsClient.Close();

        serverTask.Shutdown(serverThread);
    }

    internal class ServerTask
    {
        private readonly DtlsServerProtocol m_serverProtocol;
        private readonly TlsServer m_server;
        private readonly DatagramTransport m_serverTransport;
        private volatile bool m_isShutdown = false;

        internal ServerTask(DtlsServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            m_serverProtocol = serverProtocol;
            m_server = server;
            m_serverTransport = serverTransport;
        }

        public void Run()
        {
            try
            {
                TlsCrypto serverCrypto = m_server.Crypto;

                DtlsRequest request = null;

                // Use DtlsVerifier to require a HelloVerifyRequest cookie exchange before accepting
                {
                    DtlsVerifier verifier = new DtlsVerifier(serverCrypto);

                    // NOTE: Test value only - would typically be the client IP address
                    byte[] clientID = Strings.ToUtf8ByteArray("MockRawKeysTlsClient");

                    int receiveLimit = m_serverTransport.GetReceiveLimit();
                    int dummyOffset = serverCrypto.SecureRandom.Next(16) + 1;
                    byte[] buf = new byte[dummyOffset + m_serverTransport.GetReceiveLimit()];

                    do
                    {
                        if (m_isShutdown)
                            return;

                        int length = m_serverTransport.Receive(buf, dummyOffset, receiveLimit, 100);
                        if (length > 0)
                        {
                            request = verifier.VerifyRequest(clientID, buf, dummyOffset, length, m_serverTransport);
                        }
                    }
                    while (request == null);
                }

                // NOTE: A real server would handle each DtlsRequest in a new task/thread and continue accepting
                {
                    DtlsTransport dtlsTransport = m_serverProtocol.Accept(m_server, m_serverTransport, request);
                    byte[] buf = new byte[dtlsTransport.GetReceiveLimit()];
                    while (!m_isShutdown)
                    {
                        int length = dtlsTransport.Receive(buf, 0, buf.Length, 100);
                        if (length >= 0)
                        {
                            dtlsTransport.Send(buf, 0, length);
                        }
                    }
                    dtlsTransport.Close();
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                Console.Error.Flush();
            }
        }

        internal void Shutdown(Thread serverThread)
        {
            if (!m_isShutdown)
            {
                m_isShutdown = true;
                serverThread.Join();
            }
        }
    }
}
