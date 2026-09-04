================================================================================
MAINTAINER-README: CodeBrix.Cryptography
Notes for people and agents MAINTAINING this repository — not for package
consumers
================================================================================

If you are CONSUMING the NuGet package, read AGENT-README.txt instead. This file
covers building, testing, packaging and the conventions that apply to changes
made inside this repository.


PURPOSE AND SCOPE
=================

The repository produces exactly one NuGet package:

    Package id      CodeBrix.Cryptography.MitLicenseForever
    Project         src/CodeBrix.Cryptography/CodeBrix.Cryptography.csproj
    Assembly        CodeBrix.Cryptography
    Root namespace  CodeBrix.Cryptography
    Consumer docs   AGENT-README.txt (repository root)

There are no sibling packages and no companion projects. The one other project
in the solution is the test project.


REPOSITORY LAYOUT
=================

    AGENT-README.txt        Consumer documentation; packed into the nupkg.
    MAINTAINER-README.txt   This file. Not packed.
    EXTRAS-README.txt       Non-package content (test data). Not packed.
    README-INDEX.txt        Map of the README files. Not packed.
    README.md               Human-facing overview; packed into the nupkg and
                            shown on nuget.org.
    LICENSE                 MIT.
    THIRD-PARTY-NOTICES.txt Attribution for the ported upstream sources and the
                            components they incorporate; packed into the nupkg.
    icon-codebrix-128.png   Package icon; packed into the nupkg.
    global.json             Selects the Microsoft.Testing.Platform test runner.
                            Does NOT pin an SDK version. See TESTING below.
    CodeBrix.Cryptography.slnx
                            Solution: "Solution Items" folder (.gitignore,
                            AGENT-README.txt, EXTRAS-README.txt, global.json,
                            icon-codebrix-128.png, LICENSE,
                            MAINTAINER-README.txt, README-INDEX.txt, README.md,
                            THIRD-PARTY-NOTICES.txt), a "Tests" folder holding
                            the test project, and the library project.
    src/CodeBrix.Cryptography/
                            The library. Folder layout matches sub-namespace,
                            one folder level per namespace segment, so
                            CodeBrix.Cryptography.Crypto.Digests lives in
                            src/CodeBrix.Cryptography/Crypto/Digests/. Upstream
                            used lowercase folder names that did not always
                            match its namespaces — its "util" folder held
                            Org.BouncyCastle.Utilities and "openpgp" held
                            Org.BouncyCastle.Bcpg.OpenPgp — so paths differ from
                            upstream even though file names generally do not.
    tests/CodeBrix.Cryptography.Tests/
                            The test project, mirroring the same folder tree.
    tests/CodeBrix.Cryptography.Tests/data/
                            Fixtures embedded into the test assembly.
    test-data/              Fixtures copied next to the test assembly at build
                            time. See EXTRAS-README.txt.

The eight AI-agent pointer files (AGENTS.md, CLAUDE.md, .clinerules,
.cursorrules, .cursor/rules/agent-readme.mdc, .windsurfrules,
.github/copilot-instructions.md, .junie/guidelines.md) point at AGENT-README.txt
and are maintained centrally across the CodeBrix family; do not hand-edit them
here.


ARCHITECTURE — THE LAYER MODEL
==============================

The library is layered, and it is worth knowing which layer you are in:

  1. Math          BigInteger and the EC / field arithmetic everything else
                   builds on. Performance-critical; several files have x86
                   intrinsics variants gated by
                   CodeBrix.Cryptography.Runtime.Intrinsics.X86.

  2. Crypto        The algorithm layer. Engines are raw block/stream ciphers,
                   Modes wrap an engine into a mode of operation, Paddings add
                   padding, and Digests / Macs / Signers / Agreement /
                   Generators / Kems are the corresponding primitives.
                   Parameters carries keyed and unkeyed inputs (KeyParameter,
                   ParametersWithIV, ParametersWithRandom, AeadParameters, ...).

  3. Asn1          Encoding of everything the higher layers exchange. The
                   sub-namespaces are one-per-specification and are almost
                   entirely mechanical structure definitions plus OID constants.

  4. Security      A name/OID-driven facade over layer 2, so callers can select
                   an algorithm at runtime from a string. If you are adding an
                   algorithm, it usually needs registering here too.

  5. Protocol      X509, Pkix, Pkcs, Cms, Cmp, Crmf, Ocsp, Tsp, Bcpg (OpenPGP),
                   OpenSsl and Tls. These compose layers 2-4; they rarely do
                   arithmetic themselves.

  6. Pqc           Post-quantum algorithms, structured like layer 2 with its own
                   Asn1 and Utilities helpers. (ML-KEM, ML-DSA and SLH-DSA are
                   the exception: they were promoted into layer 2 upstream and
                   live under Crypto.Kems / Crypto.Signers / Crypto.Generators.)

Cross-cutting: Utilities (Arrays, BigIntegers, Encoders, IO, Collections, Date,
Net, Zlib, Bzip2, Properties) is used by every layer, and
Runtime.Intrinsics.X86 is the single place CPU features are probed.


BUILDING
========

    dotnet restore CodeBrix.Cryptography.slnx
    dotnet build CodeBrix.Cryptography.slnx

The build must be 0 warnings / 0 errors, in Debug and in Release.
GeneratePackageOnBuild is true on the library project, so every build also
produces a .nupkg — see PACKAGING AND PUBLISHING below for what that implies.


TESTING
=======

    dotnet test CodeBrix.Cryptography.slnx

That runs clean out of the box. No external checkout, download or environment
variable is needed for the default run.

The test runner is Microsoft.Testing.Platform, selected by global.json at the
repository root:

    { "test": { "runner": "Microsoft.Testing.Platform" } }

That file pins no SDK version, so the newest installed .NET 10 SDK is still
used. Keep it committed -- without it, `dotnet test` falls back to the older
VSTest bridge.

The suite is the upstream NUnit suite translated to xUnit.v3. Fixtures come
from three places:

  * tests/CodeBrix.Cryptography.Tests/data/ — 303 files inherited from the
    upstream repository's own crypto/test/data (MIT, like the rest of that
    repository), embedded into the test assembly as resources under the logical
    prefix "CodeBrix.Cryptography.data.". That prefix is why the test project
    sets <RootNamespace>CodeBrix.Cryptography</RootNamespace> rather than the
    test assembly name. SimpleTest.GetTestData and GetTestDataAsStream read
    these.

  * test-data/ — 1,762 files (about 18 MB), copied next to the test assembly at
    build time by the <Content Include="..\..\test-data\**\*.*"> item group.
    SimpleTest.FindTestResource reads these, resolving from
    AppContext.BaseDirectory so the suite never reaches outside the repository.
    See EXTRAS-README.txt for the origins and licences.

  * The external bc-test-data repository — OPTIONAL, and the reason a set of
    tests is skipped by default.

REGENERATING THE SELF-AUTHORED FIXTURES

    CODEBRIX_CRYPTOGRAPHY_REGENERATE_TEST_DATA=1 dotnet test \
        --filter "FullyQualifiedName~TestDataGeneration"

The generators live in tests/CodeBrix.Cryptography.Tests/TestDataGeneration/
(Asn1FixtureGenerator, CmpFixtureGenerator, SampleCertificateGenerator,
TlsCredentialGenerator, TestDataPaths) and are skipped unless that variable is
set, so they never run in CI. They produce the ML-DSA / ML-KEM / SLH-DSA sample
credentials, the CMS SignedData samples, the TLS and DTLS certificate and key
set, and the deeply-nested ASN.1 stress fixtures.

THE SKIPPED TESTS AND HOW TO RUN THEM

Upstream keeps the remaining fixtures in a separate repository,
https://github.com/bcgit/bc-test-data.git — roughly 4.6 GB, with no licence
file anywhere in it. Without a licence those files cannot be redistributed
inside an MIT-licensed repository, and several individual files would breach
GitHub's size limits anyway (picnic ships a single 40 MB vector file), so the
tests that read them are skipped rather than failing.

What is gated: the post-quantum known-answer vectors from the individual NIST
PQC submission packages (Saber, Picnic, NTRU Prime, Classic McEliece, NTRU,
FrodoKEM, HQC, BIKE, Falcon, and parts of ML-KEM / ML-DSA / SLH-DSA), the
LMS/HSS vectors, one Grain-128AEAD vector, and the NIST PKITS certificate-path
suites. Each submission carries its own unstated terms, and self-generated
vectors would only prove the library agrees with itself, so neither sourcing nor
authoring them is available.

To run them:

  1. Clone https://github.com/bcgit/bc-test-data.git so that it sits BESIDE this
     repository — the two directories must be siblings, for example
     ~/GitHome/CodeBrix.Cryptography and ~/GitHome/bc-test-data.

  2. Set CODEBRIX_CRYPTOGRAPHY_USE_BC_TEST_DATA=1.

        CODEBRIX_CRYPTOGRAPHY_USE_BC_TEST_DATA=1 dotnet test CodeBrix.Cryptography.slnx

The gating lives in tests/CodeBrix.Cryptography.Tests/Utilities/Test/BcTestData.cs,
which exposes EnvironmentVariableName, DirectoryName, SkipReason and
IsAvailable. Twenty-seven test methods carry
Skip = BcTestData.SkipReason with SkipUnless = nameof(BcTestData.IsAvailable);
because several of them are theories, the number of SKIPPED TEST CASES the
runner reports is larger than twenty-seven and depends on how the data files
expand. Each affected class also carries a <remarks> block saying the same
thing. The gated files are spread across Crypto/Tests, Pqc/Crypto/Tests,
Pqc/Crypto/Lms/Tests, Cmp/Tests and Tests/Nist.

IsAvailable is true only when the opt-in variable is set AND a sibling
bc-test-data directory is actually found (FindSiblingDirectory walks up from
AppContext.BaseDirectory). A fixture in this repository always wins over the
external copy, so opting in can only add files — it can never change the result
of a test that already passes.

Two things worth knowing when a test fails:

  * Check whether it calls FindTestResource (test-data, plus the optional
    external set) or GetTestDataAsStream (embedded, always present) before
    assuming a real regression.

  * Tls.Tests.DtlsPskProtocolTest.BadClientKeyTimeout and BadServerKeyTimeout
    assert that a DTLS handshake times out, so their outcome depends on elapsed
    time rather than on a value. Under the CPU contention of a full parallel run
    the handshake used to fail a different way first, making them flaky. They
    are now in TimingSensitiveCollection, which xUnit runs on its own and never
    alongside another collection; that removed the flakiness. If you add another
    timing-dependent test, put it in that collection rather than skipping it.


PACKAGING AND PUBLISHING
========================

The library project sets GeneratePackageOnBuild, so `dotnet build` in Release
already produces the .nupkg; there is no separate pack driver script.

Versioning is the CodeBrix date-stamped auto-incrementing scheme computed in the
csproj from System.DateTime.UtcNow:

    1.<years since _VersionBaseYear>.<day of year>.<minute of day>

  * major is pinned to 1;
  * minor is whole years since the _VersionBaseYear property;
  * build is the 1-based UTC day of year;
  * revision is the UTC minute of day, 0..1439 (Math.Floor keeps it under 1440
    late in the day).

The value is strictly increasing over time. Two builds in the SAME UTC minute
produce the SAME version, so do not publish two packages from within one
minute. This is date-stamp versioning, not SemVer: major/minor do not signal API
compatibility. To re-baseline, change _VersionBaseYear.

What ships in the nupkg, from the <None Include=...> item group:

    icon-codebrix-128.png       (PackageIcon)
    README.md                   (PackageReadmeFile)
    AGENT-README.txt            consumer documentation
    THIRD-PARTY-NOTICES.txt     attribution

MAINTAINER-README.txt, EXTRAS-README.txt and README-INDEX.txt are NOT packed.

Package metadata: PackageLicenseExpression MIT,
PackageRequireLicenseAcceptance true, project and repository URL
https://github.com/ellisnet/CodeBrix.Cryptography.


PROVENANCE AND VENDORED SOURCES
===============================

The library is a port of BouncyCastle.NET 2.7.0
(https://github.com/bcgit/bc-csharp), MIT licensed, narrowed to a single modern
.NET target and rehomed under the CodeBrix.Cryptography namespace. Public type
names, member names and signatures are preserved so the package is a drop-in
replacement for BouncyCastle.Cryptography.

Every file ported from upstream carries a provenance comment on its namespace
line:

    namespace CodeBrix.Cryptography.Crypto.Digests;
        //was previously: Org.BouncyCastle.Crypto.Digests;

Keep it when editing a ported file. New-in-fork files do not get one.

THIRD-PARTY-NOTICES.txt carries the full attribution for the upstream project
and for the JZlib, Apache Ant BZip2, Falcon and Blake2Fast components it
incorporates, plus the origins of the checked-in test data.

The runtime configuration keys read through
CodeBrix.Cryptography.Utilities.Properties deliberately keep their upstream
"Org.BouncyCastle.*" spelling, so an application already configured for the
upstream package keeps working unchanged after swapping in this one. Do NOT
"fix" those strings to say CodeBrix; that would be a breaking change for
consumers. They are the only remaining occurrences of the string
"Org.BouncyCastle" outside the per-file provenance comments.


CODING CONVENTIONS
==================

These rules apply to every change made to this repository.

  * Target framework is net10.0 only. Do not add target frameworks and do not
    reintroduce framework-selection #if directives. The port already evaluated
    every one of them for net10.0 and deleted the dead branches.

  * Nullable reference types are OFF. Never write `?` on a reference type
    (`string?`, `MyClass?`, `object?`) and never use the null-forgiveness `!`
    operator. Value-type nullables (`int?`, `bool?`, `DateTime?`) are fine.
    Do not add `#nullable` directives or a <Nullable> csproj property.

  * No implicit usings and no `global using`. Every file declares the usings it
    needs.

  * File-scoped namespaces only (`namespace X;`), never block-scoped.

  * Usings sit above the namespace in a single contiguous block with no blank
    lines inside it: System.* first, then everything else, alphabetical within
    each group, with aliases last.

  * The build must be 0 warnings / 0 errors, in Debug and in Release. Do not add
    <NoWarn>, <WarningLevel>, or #pragma warning disable to silence anything
    beyond the two exceptions documented below.

  * DOCUMENTED EXCEPTION 1 — CS1591 in the library project.
    <GenerateDocumentationFile> is true, but <NoWarn>1591</NoWarn> is set,
    because the ported surface is thousands of public members with no upstream
    XML doc comments; upstream builds with the same suppression. This is the
    same situational exception already taken by CodeBrix.Platform.OpenGL and
    CodeBrix.AssemblyTools. When you ADD a new public member, still write an XML
    doc comment for it.

  * DOCUMENTED EXCEPTION 2 — CS0618 in the test project.
    A cryptography suite has to keep testing algorithms the library has
    deprecated but still ships, so the test project sets <NoWarn>618</NoWarn>.
    Upstream does the same. This applies to test code only, never to the
    library.

  * Two `#pragma warning disable CA1857` regions exist, in
    Crypto/Engines/AesEngine_X86.cs and Crypto/Engines/Salsa20Engine.cs, where
    hand-tuned intrinsics pass loop-carried values to parameters declared
    [ConstantExpected]. Each carries a comment explaining why. Do not add more
    pragmas without the same kind of justification.

  * The formatter-based serialization constructors and GetObjectData overrides
    on the exception types are marked [Obsolete] with the framework's own
    wording. That is what silences SYSLIB0051 and CS0672 on net10.0. Keep the
    attribute if you touch those members; do not delete the members, because
    they are part of the public surface this library promises.

  * Tests use xUnit.v3 with SilverAssertions available. Any call inside a test
    that accepts a CancellationToken must be passed
    TestContext.Current.CancellationToken, or xUnit1051 fires.

  * These tests are a port of the upstream NUnit suite, so they keep the
    upstream test class and method names rather than the CodeBrix
    <ClassUnderTest>Tests / snake_case convention. Follow the surrounding file
    when adding to an existing test class.


NOTES
=====

  * AGENT-README.txt is a CONSUMER document. Build, test, packaging, versioning,
    vendored-source and contributor-convention material belongs here, not there,
    and no version numbers belong in AGENT-README.txt at all (the one-line
    upstream-provenance statement is the exception, because it is a historical
    fact).

  * The public surface is roughly 1,900 public types across about 140
    namespaces. When adding or renaming anything public, check whether
    AGENT-README.txt's feature-area sections and QUICK REFERENCE CARD still
    match.
