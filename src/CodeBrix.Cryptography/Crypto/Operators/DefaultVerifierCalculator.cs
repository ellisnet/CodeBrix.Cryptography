using System;
using System.IO;
using CodeBrix.Cryptography.Crypto.IO;

namespace CodeBrix.Cryptography.Crypto.Operators; //was previously: Org.BouncyCastle.Crypto.Operators;

// TODO[api] sealed
public class DefaultVerifierCalculator
    : IStreamCalculator<IVerifier>
{
    private readonly SignerSink m_signerSink;

    public DefaultVerifierCalculator(ISigner signer)
    {
        m_signerSink = new SignerSink(signer);
    }

    public Stream Stream => m_signerSink;

    public IVerifier GetResult() => new DefaultVerifierResult(m_signerSink.Signer);
}
