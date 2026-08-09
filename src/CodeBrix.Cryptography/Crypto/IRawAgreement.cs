using System;

namespace CodeBrix.Cryptography.Crypto; //was previously: Org.BouncyCastle.Crypto;

public interface IRawAgreement
{
    void Init(ICipherParameters parameters);

    int AgreementSize { get; }

    void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off);

    void CalculateAgreement(ICipherParameters publicKey, Span<byte> output);
}
