using System;
using System.Threading;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.IO;
using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests; //was previously: Org.BouncyCastle.Tls.Tests;

public class Tls13PskProtocolTest
{
    [Fact]
    public void BadClientKey()
    {
        MockPskTls13Client client = new MockPskTls13Client(badKey: true);
        MockPskTls13Server server = new MockPskTls13Server();

        ImplTestKeyMismatch(client, server);
    }

    [Fact]
    public void BadServerKey()
    {
        MockPskTls13Client client = new MockPskTls13Client();
        MockPskTls13Server server = new MockPskTls13Server(badKey: true);

        ImplTestKeyMismatch(client, server);
    }

    [Fact]
    public void TestClientServer()
    {
        MockPskTls13Client client = new MockPskTls13Client();
        MockPskTls13Server server = new MockPskTls13Server();

        PipedStream clientPipe = new PipedStream();
        PipedStream serverPipe = new PipedStream(clientPipe);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

        ServerTask serverTask = new ServerTask(serverProtocol, server);

        Thread serverThread = new Thread(serverTask.Run);
        serverThread.Start();

        clientProtocol.Connect(client);

        byte[] data = new byte[1000];
        client.Crypto.SecureRandom.NextBytes(data);

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

    private void ImplTestKeyMismatch(MockPskTls13Client client, MockPskTls13Server server)
    {
        PipedStream clientPipe = new PipedStream();
        PipedStream serverPipe = new PipedStream(clientPipe);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

        ServerTask serverTask = new ServerTask(serverProtocol, server);

        Thread serverThread = new Thread(serverTask.Run);
        serverThread.Start();

        bool correctException = false;
        short alertDescription = -1;

        try
        {
            clientProtocol.Connect(client);
        }
        catch (TlsFatalAlertReceived e)
        {
            correctException = true;
            alertDescription = e.AlertDescription;
        }
        catch (Exception)
        {
        }
        finally
        {
            clientProtocol.Close();
        }

        serverThread.Join();

        Assert.True(correctException);
        Assert.Equal(AlertDescription.decrypt_error, alertDescription);
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
