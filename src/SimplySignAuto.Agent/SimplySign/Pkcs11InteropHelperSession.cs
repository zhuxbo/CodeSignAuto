namespace SimplySignAuto.Agent.SimplySign;

internal enum Pkcs11HelperObjectClass
{
    Certificate,
    PrivateKey,
}

internal readonly record struct Pkcs11HelperAttributeLengths(int Identifier, int Value);

internal interface IPkcs11LowLevelSession : IDisposable
{
    IPkcs11LowLevelFindOperation BeginFind(
        Pkcs11HelperObjectClass objectClass,
        byte[]? id);

    Pkcs11HelperAttributeLengths ReadAttributeLengths(ulong objectHandle, bool includeValue);

    Pkcs11HelperObject ReadAttributes(
        ulong objectHandle,
        Pkcs11HelperAttributeLengths expected,
        bool includeValue);
}

internal interface IPkcs11LowLevelFindOperation : IDisposable
{
    IReadOnlyList<ulong> Read(int maximumObjects);
}

internal sealed class Pkcs11HelperContractException : Exception
{
}

internal sealed class Pkcs11HelperTokenMissingException : Exception
{
}

internal sealed class Pkcs11HelperSessionLostException : Exception
{
}

internal sealed class Pkcs11HelperNativeUnavailableException : Exception
{
}

internal sealed class Pkcs11HelperProbeUnavailableException(
    bool tokenPresent,
    bool certificatePresent) : Exception
{
    public bool TokenPresent { get; } = tokenPresent;

    public bool CertificatePresent { get; } = certificatePresent;
}

internal sealed class Pkcs11InteropHelperSession : IPkcs11HelperSession
{
    private const int MaximumIdentifierBytes = 128;
    private const int MaximumCertificateBytes = 64 * 1024;
    private readonly IPkcs11LowLevelSession _native;

    public Pkcs11InteropHelperSession(IPkcs11LowLevelSession native)
    {
        _native = native ?? throw new ArgumentNullException(nameof(native));
    }

    internal bool ContractInvalid { get; private set; }

    public IEnumerable<Pkcs11HelperObject> FindCertificates(byte[]? id) =>
        Find(Pkcs11HelperObjectClass.Certificate, id, maximumObjects: 257, includeValue: true);

    public IEnumerable<Pkcs11HelperObject> FindPrivateKeys(byte[] id) =>
        Find(Pkcs11HelperObjectClass.PrivateKey, id, maximumObjects: 2, includeValue: false);

    public void Dispose() => _native.Dispose();

    private IEnumerable<Pkcs11HelperObject> Find(
        Pkcs11HelperObjectClass objectClass,
        byte[]? id,
        int maximumObjects,
        bool includeValue)
    {
        var handles = new List<ulong>();
        using (var search = _native.BeginFind(objectClass, id))
        {
            while (handles.Count < maximumObjects)
            {
                var requested = maximumObjects - handles.Count;
                var batch = search.Read(requested);
                if (batch.Count > requested)
                {
                    ContractInvalid = true;
                    throw new Pkcs11HelperContractException();
                }

                if (batch.Count == 0)
                {
                    break;
                }

                handles.AddRange(batch);
            }
        }

        if (objectClass == Pkcs11HelperObjectClass.Certificate && handles.Count >= maximumObjects)
        {
            ContractInvalid = true;
            throw new Pkcs11HelperContractException();
        }

        foreach (var handle in handles)
        {
            var lengths = _native.ReadAttributeLengths(handle, includeValue);
            if (lengths.Identifier is <= 0 or > MaximumIdentifierBytes ||
                includeValue && lengths.Value is <= 0 or > MaximumCertificateBytes ||
                !includeValue && lengths.Value != 0)
            {
                ContractInvalid = true;
                throw new Pkcs11HelperContractException();
            }

            var item = _native.ReadAttributes(handle, lengths, includeValue);
            if (item.Id?.Length != lengths.Identifier ||
                includeValue && item.Value?.Length != lengths.Value ||
                !includeValue && item.Value is not null)
            {
                ContractInvalid = true;
                throw new Pkcs11HelperContractException();
            }

            yield return item;
        }
    }
}
