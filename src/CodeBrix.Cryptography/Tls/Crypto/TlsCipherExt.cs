namespace CodeBrix.Cryptography.Tls.Crypto; //was previously: Org.BouncyCastle.Tls.Crypto;

// TODO[api] Merge into TlsCipher
public interface TlsCipherExt
{
    int GetPlaintextDecodeLimit(int ciphertextLimit);

    int GetPlaintextEncodeLimit(int ciphertextLimit);
}
