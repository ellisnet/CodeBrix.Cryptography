namespace CodeBrix.Cryptography.Pqc.Crypto.Lms; //was previously: Org.BouncyCastle.Pqc.Crypto.Lms;

public interface ILmsContextBasedSigner
{
    LmsContext GenerateLmsContext();

    byte[] GenerateSignature(LmsContext context);

    long GetUsagesRemaining();
}
