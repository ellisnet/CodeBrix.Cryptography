using System;
using System.Threading;
using CodeBrix.Cryptography.Utilities;
using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests; //was previously: Org.BouncyCastle.Tls.Tests;

public class DtlsTestCase
{
    private static void CheckDtlsVersions(ProtocolVersion[] versions)
    {
        if (versions != null)
        {
            for (int i = 0; i < versions.Length; ++i)
            {
                if (!versions[i].IsDtls)
                    throw new InvalidOperationException("Non-DTLS version");
            }
        }
    }

    [Theory]
    [MemberData(nameof(DtlsTestSuite.Suite), MemberType = typeof(DtlsTestSuite))]
    // `name` is the upstream NUnit test-case name; it is carried through as a
    // theory argument so the xUnit display name stays readable.
    public void RunTest(TlsTestConfig config, string name)
    {
        // Upstream set this as the NUnit test-case name; xUnit derives its display
        // name from the arguments, so surface it in the test output instead.
        TestContext.Current.TestOutputHelper?.WriteLine(name);

        CheckDtlsVersions(config.clientSupportedVersions);
        CheckDtlsVersions(config.serverSupportedVersions);

        DtlsTestClientProtocol clientProtocol = new DtlsTestClientProtocol(config);
        DtlsTestServerProtocol serverProtocol = new DtlsTestServerProtocol(config);

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
        TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

        ServerTask serverTask = new ServerTask(this, serverProtocol, network.Server, serverImpl);

        Thread serverThread = new Thread(serverTask.Run);
        serverThread.Start();

        Exception caught = null;
        try
        {
            DatagramTransport clientTransport = network.Client;

            if (TlsTestConfig.Debug)
            {
                clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);
            }

            DtlsTransport dtlsClient = clientProtocol.Connect(clientImpl, clientTransport);

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
        }
        catch (Exception e)
        {
            caught = e;
            LogException(caught);
        }

        serverTask.Shutdown(serverThread);

        // TODO Add checks that the various streams were closed

        Assert.Equal(config.expectFatalAlertConnectionEnd, clientImpl.FirstFatalAlertConnectionEnd);
        Assert.Equal(config.expectFatalAlertConnectionEnd, serverImpl.FirstFatalAlertConnectionEnd);

        Assert.Equal(config.expectFatalAlertDescription, clientImpl.FirstFatalAlertDescription);
        Assert.Equal(config.expectFatalAlertDescription, serverImpl.FirstFatalAlertDescription);

        if (config.expectFatalAlertConnectionEnd == -1)
        {
            Assert.Null(caught);
            Assert.Null(serverTask.Caught);
        }
    }

    protected void LogException(Exception e)
    {
        if (TlsTestConfig.Debug)
        {
            Console.Error.WriteLine(e);
            Console.Error.Flush();
        }
    }

    internal class ServerTask
    {
        private readonly DtlsTestCase m_outer;
        private readonly DtlsTestServerProtocol m_serverProtocol;
        private readonly DatagramTransport m_serverTransport;
        private readonly TlsTestServerImpl m_serverImpl;

        private volatile bool m_isShutdown = false;
        private Exception m_caught = null;

        internal ServerTask(DtlsTestCase outer, DtlsTestServerProtocol serverProtocol,
            DatagramTransport serverTransport, TlsTestServerImpl serverImpl)
        {
            m_outer = outer;
            m_serverProtocol = serverProtocol;
            m_serverTransport = serverTransport;
            m_serverImpl = serverImpl;
        }

        public void Run()
        {
            try
            {
                DtlsTransport dtlsServer = m_serverProtocol.Accept(m_serverImpl, m_serverTransport);
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
                m_caught = e;
                m_outer.LogException(m_caught);
            }
        }

        internal void Shutdown(Thread serverThread)
        {
            if (!m_isShutdown)
            {
                m_isShutdown = true;
                //serverThread.Interrupt();
                serverThread.Join();
            }
        }

        internal Exception Caught => m_caught;
    }
}
