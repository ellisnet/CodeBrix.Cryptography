namespace CodeBrix.Cryptography.Tls.Crypto; //was previously: Org.BouncyCastle.Tls.Crypto;

public interface TlsKemDomain
{
    TlsAgreement CreateKem();
}
