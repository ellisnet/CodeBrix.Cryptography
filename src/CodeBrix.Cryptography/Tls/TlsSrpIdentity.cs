using System;

namespace CodeBrix.Cryptography.Tls; //was previously: Org.BouncyCastle.Tls;

/// <summary>Processor interface for an SRP identity.</summary>
public interface TlsSrpIdentity
{
    byte[] GetSrpIdentity();

    byte[] GetSrpPassword();
}
