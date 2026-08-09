using System.IO;
using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Crypto.IO;

namespace CodeBrix.Cryptography.Tls.Crypto.Impl.BC; //was previously: Org.BouncyCastle.Tls.Crypto.Impl.BC;

internal sealed class BcTlsStreamSigner
    : TlsStreamSigner
{
    private readonly SignerSink m_output;

    internal BcTlsStreamSigner(ISigner signer)
    {
        m_output = new SignerSink(signer);
    }

    public Stream Stream => m_output;

    public byte[] GetSignature()
    {
        try
        {
            return m_output.Signer.GenerateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
