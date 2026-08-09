using System;

namespace CodeBrix.Cryptography.OpenSsl; //was previously: Org.BouncyCastle.OpenSsl;

public interface IPasswordFinder
{
	char[] GetPassword();
}
