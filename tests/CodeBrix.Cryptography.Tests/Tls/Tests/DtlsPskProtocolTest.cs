using System;
using System.Threading;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests; //was previously: Org.BouncyCastle.Tls.Tests;

// BadClientKeyTimeout and BadServerKeyTimeout assert that a DTLS handshake fails by timing
// out, which is not reliable while the rest of the suite competes for CPU. See
// TimingSensitiveCollection.
[Collection(TimingSensitiveCollection.Name)]
public class DtlsPskProtocolTest
{
    [Fact]
    public void BadClientKeyTimeout()
    {
        MockPskDtlsClient client = new MockPskDtlsClient(null, badKey: true);
        MockPskDtlsServer server = new MockPskDtlsServer();

        ImplTestKeyMismatch(client, server);
    }

    [Fact]
    public void BadServerKeyTimeout()
    {
        MockPskDtlsClient client = new MockPskDtlsClient(null);
        MockPskDtlsServer server = new MockPskDtlsServer(badKey: true);

        ImplTestKeyMismatch(client, server);
    }

    [Fact]
    public void TestClientServer()
    {
        MockPskDtlsClient client = new MockPskDtlsClient(null);
        MockPskDtlsServer server = new MockPskDtlsServer();

        DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
        DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerTask serverTask = new ServerTask(serverProtocol, server, network.Server);

        Thread serverThread = new Thread(serverTask.Run);
        serverThread.Start();

        DatagramTransport clientTransport = network.Client;

        clientTransport = new UnreliableDatagramTransport(clientTransport, client.Crypto.SecureRandom, 0, 0);

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

    private void ImplTestKeyMismatch(MockPskDtlsClient client, MockPskDtlsServer server)
    {
        DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
        DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerTask serverTask = new ServerTask(serverProtocol, server, network.Server);

        Thread serverThread = new Thread(serverTask.Run);
        serverThread.Start();

        DatagramTransport clientTransport = network.Client;

        // Don't use unreliable transport because we are focused on timeout due to bad PSK
        //clientTransport = new UnreliableDatagramTransport(clientTransport, client.Crypto.SecureRandom, 0, 0);

        clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);

        bool correctException = false;

        try
        {
            DtlsTransport dtlsClient = clientProtocol.Connect(client, clientTransport);
            dtlsClient.Close();
        }
        catch (TlsTimeoutException)
        {
            correctException = true;
        }
        catch (Exception)
        {
        }
        finally
        {
            clientTransport.Close();
        }

        serverTask.Shutdown(serverThread);

        Assert.True(correctException);
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
                DtlsTransport dtlsServer = m_serverProtocol.Accept(m_server, m_serverTransport);
                byte[] buf = new byte[dtlsServer.GetReceiveLimit()];
                while (!m_isShutdown)
                {
                    int length = dtlsServer.Receive(buf, 0, buf.Length, 100);
                    if (length >= 0)
                    {
                        dtlsServer.Send(buf, 0, length);
                    }
                }
                dtlsServer.Close();
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
                this.m_isShutdown = true;
                serverThread.Join();
            }
        }
    }
}
