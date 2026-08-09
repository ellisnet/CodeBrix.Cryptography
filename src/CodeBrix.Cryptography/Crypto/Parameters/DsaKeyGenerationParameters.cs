using System;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crypto.Parameters; //was previously: Org.BouncyCastle.Crypto.Parameters;

public class DsaKeyGenerationParameters
	: KeyGenerationParameters
{
    private readonly DsaParameters parameters;

    public DsaKeyGenerationParameters(
        SecureRandom	random,
        DsaParameters	parameters)
		: base(random, parameters.P.BitLength - 1)
    {
        this.parameters = parameters;
    }

	public DsaParameters Parameters
    {
        get { return parameters; }
    }
}
