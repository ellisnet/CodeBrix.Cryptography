using System;
using System.Threading;
using CodeBrix.Cryptography.Utilities;
using CodeBrix.Cryptography.Utilities.IO;
using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests; //was previously: Org.BouncyCastle.Tls.Tests;

public class TlsTestCase
{
    private static void CheckTlsVersions(ProtocolVersion[] versions)
    {
        if (versions != null)
        {
            for (int i = 0; i < versions.Length; ++i)
            {
                if (!versions[i].IsTls)
                    throw new InvalidOperationException("Non-TLS version");
            }
        }
    }

    [Theory]
    [MemberData(nameof(TlsTestSuite.Suite), MemberType = typeof(TlsTestSuite))]
    // `name` is the upstream NUnit test-case name; it is carried through as a
    // theory argument so the xUnit display name stays readable.
    public void RunTest(TlsTestConfig config, string name)
    {
        // Upstream set this as the NUnit test-case name; xUnit derives its display
        // name from the arguments, so surface it in the test output instead.
        TestContext.Current.TestOutputHelper?.WriteLine(name);

        // Disable the test if it is not being run via TlsTestSuite
        if (config == null)
            return;

        CheckTlsVersions(config.clientSupportedVersions);
        CheckTlsVersions(config.serverSupportedVersions);

        PipedStream clientPipe = new PipedStream();
        PipedStream serverPipe = new PipedStream(clientPipe);

        NetworkStream clientNet = new NetworkStream(clientPipe);
        NetworkStream serverNet = new NetworkStream(serverPipe);

        TlsTestClientProtocol clientProtocol = new TlsTestClientProtocol(clientNet, config);
        TlsTestServerProtocol serverProtocol = new TlsTestServerProtocol(serverNet, config);

        clientProtocol.IsResumableHandshake = true;
        serverProtocol.IsResumableHandshake = true;

        TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
        TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

        ServerTask serverTask = new ServerTask(this, serverProtocol, serverImpl);

        Thread serverThread = new Thread(serverTask.Run);
        serverThread.Start();

        Exception caught = null;
        try
        {
            clientProtocol.Connect(clientImpl);

            byte[] data = new byte[1000];
            clientImpl.Crypto.SecureRandom.NextBytes(data);

            using (var stream = clientProtocol.Stream)
            {
                stream.Write(data, 0, data.Length);

                byte[] echo = new byte[data.Length];
                int count = Streams.ReadFully(stream, echo, 0, echo.Length);

                Assert.Equal(count, data.Length);
                Assert.True(Arrays.AreEqual(data, echo));

                Assert.True(Arrays.AreEqual(clientImpl.m_tlsKeyingMaterial1, serverImpl.m_tlsKeyingMaterial1));
                Assert.True(Arrays.AreEqual(clientImpl.m_tlsKeyingMaterial2, serverImpl.m_tlsKeyingMaterial2));
                Assert.True(Arrays.AreEqual(clientImpl.m_tlsServerEndPoint, serverImpl.m_tlsServerEndPoint));

                if (!TlsUtilities.IsTlsV13(clientImpl.m_negotiatedVersion))
                {
                    Assert.NotNull(clientImpl.m_tlsUnique);
                    Assert.NotNull(serverImpl.m_tlsUnique);
                }
                Assert.True(Arrays.AreEqual(clientImpl.m_tlsUnique, serverImpl.m_tlsUnique));
            }
        }
        catch (Exception e)
        {
            caught = e;
            LogException(caught);
        }

        serverTask.AllowExit();
        serverThread.Join();

        Assert.True(clientNet.IsClosed, "Client Stream not closed");
        Assert.True(serverNet.IsClosed, "Server Stream not closed");

        Assert.Equal(config.expectFatalAlertConnectionEnd, clientImpl.FirstFatalAlertConnectionEnd);
        Assert.Equal(config.expectFatalAlertConnectionEnd, serverImpl.FirstFatalAlertConnectionEnd);

        Assert.Equal(config.expectFatalAlertDescription, clientImpl.FirstFatalAlertDescription);
        Assert.Equal(config.expectFatalAlertDescription, serverImpl.FirstFatalAlertDescription);

        if (config.expectFatalAlertConnectionEnd == -1)
        {
            Assert.Null(caught);
            Assert.Null(serverTask.m_caught);
        }
    }

    protected virtual void LogException(Exception e)
    {
        if (TlsTestConfig.Debug)
        {
            Console.Error.WriteLine(e);
            Console.Error.Flush();
        }
    }

    internal class ServerTask
    {
        protected readonly TlsTestCase m_outer;
        protected readonly TlsServerProtocol m_serverProtocol;
        protected readonly TlsServer m_server;

        internal bool m_canExit = false;
        internal Exception m_caught = null;

        internal ServerTask(TlsTestCase outer, TlsTestServerProtocol serverProtocol, TlsServer server)
        {
            m_outer = outer;
            m_serverProtocol = serverProtocol;
            m_server = server;
        }

        internal void AllowExit()
        {
            lock (this)
            {
                m_canExit = true;
                Monitor.PulseAll(this);
            }
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
            catch (Exception e)
            {
                m_caught = e;
                m_outer.LogException(m_caught);
            }

            WaitExit();
        }

        protected void WaitExit()
        {
            lock (this)
            {
                while (!m_canExit)
                {
                    try
                    {
                        Monitor.Wait(this);
                    }
                    catch (ThreadInterruptedException)
                    {
                    }
                }
            }
        }
    }
}
