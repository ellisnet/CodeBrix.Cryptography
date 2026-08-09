using Xunit;

namespace CodeBrix.Cryptography.Tls.Tests;

/// <summary>
/// A test collection that xUnit runs on its own, never alongside another collection.
/// </summary>
/// <remarks>
/// <para>
/// It exists for tests whose assertion is about elapsed time rather than about a value.
/// <see cref="DtlsPskProtocolTest"/> is the case that prompted it: BadClientKeyTimeout and
/// BadServerKeyTimeout drive a DTLS handshake with a deliberately wrong PSK and require it
/// to fail by TIMING OUT. Under the CPU contention of a full parallel run the handshake can
/// instead fail some other way first, so the expected TlsTimeoutException never arrives and
/// the assertion fails. Both tests pass reliably in isolation.
/// </para>
/// <para>
/// DisableParallelization keeps this collection from running concurrently with any other,
/// which removes the contention rather than papering over it with a Skip. Add a class here
/// only when its outcome genuinely depends on timing; everything else should stay parallel.
/// </para>
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public class TimingSensitiveCollection
{
    public const string Name = "Timing-sensitive";
}
