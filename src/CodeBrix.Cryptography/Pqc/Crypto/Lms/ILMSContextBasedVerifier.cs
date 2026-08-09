namespace CodeBrix.Cryptography.Pqc.Crypto.Lms; //was previously: Org.BouncyCastle.Pqc.Crypto.Lms;

public interface ILmsContextBasedVerifier
{
    LmsContext GenerateLmsContext(byte[] signature);

    bool Verify(LmsContext context);
}
