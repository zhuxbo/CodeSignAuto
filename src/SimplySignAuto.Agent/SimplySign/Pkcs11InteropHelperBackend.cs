using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Net.Pkcs11Interop.Common;

namespace SimplySignAuto.Agent.SimplySign;

internal enum Pkcs11InteropAbi
{
    Api40,
    Api41,
    Api80,
    Api81,
}

internal static class Pkcs11InteropAbiSelector
{
    public static Pkcs11InteropAbi Select(int nativeUnsignedLongSize, int structPackingSize) =>
        (nativeUnsignedLongSize, structPackingSize) switch
        {
            (4, 0) => Pkcs11InteropAbi.Api40,
            (4, 1) => Pkcs11InteropAbi.Api41,
            (8, 0) => Pkcs11InteropAbi.Api80,
            (8, 1) => Pkcs11InteropAbi.Api81,
            _ => throw new PlatformNotSupportedException(),
        };
}

internal static class Pkcs11InteropNativeValue
{
    public static object Box(int nativeUnsignedLongSize, ulong value) => nativeUnsignedLongSize switch
    {
        4 => (object)checked((uint)value),
        8 => value,
        _ => throw new PlatformNotSupportedException(),
    };
}

internal static class Pkcs11InteropReturnCode
{
    private const ulong ReturnOk = 0;
    private const ulong ReturnAttributeSensitive = 0x11;
    private const ulong ReturnAttributeTypeInvalid = 0x12;
    private const ulong ReturnDeviceRemoved = 0x32;
    private const ulong ReturnSessionClosed = 0xb0;
    private const ulong ReturnSessionHandleInvalid = 0xb3;
    private const ulong ReturnTokenNotPresent = 0xe0;
    private const ulong ReturnUserNotLoggedIn = 0x101;

    public static void ThrowIfFailed(ulong returnCode)
    {
        if (returnCode == ReturnOk)
        {
            return;
        }

        if (returnCode is ReturnAttributeSensitive or ReturnAttributeTypeInvalid)
        {
            throw new Pkcs11HelperContractException();
        }

        if (returnCode == ReturnTokenNotPresent)
        {
            throw new Pkcs11HelperTokenMissingException();
        }

        if (returnCode is ReturnDeviceRemoved or ReturnSessionClosed or
            ReturnSessionHandleInvalid or ReturnUserNotLoggedIn)
        {
            throw new Pkcs11HelperSessionLostException();
        }

        throw new Pkcs11HelperNativeUnavailableException();
    }
}

internal sealed class Pkcs11InteropHelperBackend : IPkcs11HelperBackend
{
    public IPkcs11HelperLibrary Load(string modulePath)
    {
        try
        {
            var abi = Pkcs11InteropAbiSelector.Select(
                Platform.NativeULongSize,
                Platform.StructPackingSize);
            return new ReflectionLowLevelLibrary(modulePath, abi);
        }
        catch (Exception error) when (
            error is not Pkcs11HelperContractException &&
            error is not Pkcs11HelperTokenMissingException &&
            error is not Pkcs11HelperSessionLostException &&
            error is not Pkcs11HelperNativeUnavailableException)
        {
            throw new Pkcs11HelperNativeUnavailableException();
        }
    }

    private sealed class ReflectionLowLevelLibrary : IPkcs11HelperLibrary
    {
        private const ulong ReturnOk = 0;
        private const ulong ReturnCryptokiAlreadyInitialized = 0x191;
        private const ulong OsLockingOk = 0x2;
        private const ulong SessionSerial = 0x4;
        private const int MaximumObservedSlots = 33;
        private readonly object _library;
        private readonly Type _libraryType;
        private readonly Type _attributeType;
        private readonly Type _tokenInfoType;
        private readonly Type _nativeUnsignedLongType;
        private bool _initialized;
        private bool _disposed;

        public ReflectionLowLevelLibrary(string modulePath, Pkcs11InteropAbi abi)
        {
            var suffix = abi.ToString()[3..];
            var assembly = typeof(Platform).Assembly;
            _libraryType = assembly.GetType(
                $"Net.Pkcs11Interop.LowLevelAPI{suffix}.Pkcs11Library",
                throwOnError: true)!;
            _attributeType = assembly.GetType(
                $"Net.Pkcs11Interop.LowLevelAPI{suffix}.CK_ATTRIBUTE",
                throwOnError: true)!;
            _tokenInfoType = assembly.GetType(
                $"Net.Pkcs11Interop.LowLevelAPI{suffix}.CK_TOKEN_INFO",
                throwOnError: true)!;
            _nativeUnsignedLongType = Platform.NativeULongSize == 4 ? typeof(uint) : typeof(ulong);
            _library = Activator.CreateInstance(_libraryType, modulePath)
                ?? throw new InvalidOperationException();
            var initialize = Method("C_Initialize");
            var initializeArgs = Activator.CreateInstance(initialize.GetParameters()[0].ParameterType)!;
            SetField(initializeArgs, "Flags", Native(OsLockingOk));
            var result = ReturnValue(initialize.Invoke(_library, [initializeArgs]));
            if (result is not (ReturnOk or ReturnCryptokiAlreadyInitialized))
            {
                throw new InvalidOperationException();
            }

            _initialized = result == ReturnOk;
        }

        public IEnumerable<IPkcs11HelperSlot> GetSlots()
        {
            ThrowIfDisposed();
            var countArgs = new object?[] { true, null, Native(0) };
            EnsureOk(Method("C_GetSlotList").Invoke(_library, countArgs));
            var count = CheckedInt(countArgs[2], MaximumObservedSlots);
            var nativeSlots = Array.CreateInstance(_nativeUnsignedLongType, count);
            var listArgs = new object?[] { true, nativeSlots, Native((ulong)count) };
            EnsureOk(Method("C_GetSlotList").Invoke(_library, listArgs));
            var returned = CheckedInt(listArgs[2], count);
            var slots = new List<IPkcs11HelperSlot>(returned);
            for (var index = 0; index < returned; index++)
            {
                var slotId = Convert.ToUInt64(nativeSlots.GetValue(index),
                    System.Globalization.CultureInfo.InvariantCulture);
                var tokenInfo = Activator.CreateInstance(_tokenInfoType)!;
                var infoArgs = new[] { Native(slotId), tokenInfo };
                EnsureOk(Method("C_GetTokenInfo").Invoke(_library, infoArgs));
                tokenInfo = infoArgs[1];
                var serial = (byte[]?)_tokenInfoType.GetField("SerialNumber")!.GetValue(tokenInfo)
                    ?? throw new InvalidOperationException();
                if (serial.Any(static value => value > 0x7f))
                {
                    throw new Pkcs11HelperContractException();
                }

                var tokenSerial = Encoding.ASCII.GetString(serial).TrimEnd(' ');
                slots.Add(new Slot(this, slotId, tokenSerial));
            }

            return slots;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            try
            {
                if (_initialized)
                {
                    EnsureOk(Method("C_Finalize").Invoke(_library, [IntPtr.Zero]));
                }
            }
            finally
            {
                (_library as IDisposable)?.Dispose();
            }
        }

        private IPkcs11LowLevelSession OpenSession(ulong slotId)
        {
            ThrowIfDisposed();
            var args = new object?[]
            {
                Native(slotId),
                Native(SessionSerial),
                IntPtr.Zero,
                IntPtr.Zero,
                Native(0),
            };
            EnsureOk(Method("C_OpenSession").Invoke(_library, args));
            return new Session(this, Convert.ToUInt64(args[4],
                System.Globalization.CultureInfo.InvariantCulture));
        }

        private IPkcs11LowLevelFindOperation BeginFind(
            ulong session,
            Pkcs11HelperObjectClass objectClass,
            byte[]? id)
        {
            var allocations = new List<IntPtr>();
            var attributes = CreateAttributeArray(
                objectClass == Pkcs11HelperObjectClass.Certificate ? 1UL : 3UL,
                id,
                allocations);
            try
            {
                EnsureOk(Method("C_FindObjectsInit").Invoke(
                    _library,
                    [Native(session), attributes, Native((ulong)attributes.Length)]));
                return new FindOperation(this, session);
            }
            finally
            {
                FreeAll(allocations);
            }
        }

        private Pkcs11HelperAttributeLengths ReadAttributeLengths(
            ulong session,
            ulong objectHandle,
            bool includeValue)
        {
            var attributes = CreateEmptyAttributeArray(includeValue);
            EnsureOk(Method("C_GetAttributeValue").Invoke(
                _library,
                [Native(session), Native(objectHandle), attributes, Native((ulong)attributes.Length)]));
            var identifier = ReadLength(attributes.GetValue(0)!);
            var value = includeValue ? ReadLength(attributes.GetValue(1)!) : 0;
            return new Pkcs11HelperAttributeLengths(identifier, value);
        }

        private Pkcs11HelperObject ReadAttributes(
            ulong session,
            ulong objectHandle,
            Pkcs11HelperAttributeLengths expected,
            bool includeValue)
        {
            var allocations = new List<IntPtr>();
            var attributes = CreateReadableAttributeArray(expected, includeValue, allocations);
            try
            {
                EnsureOk(Method("C_GetAttributeValue").Invoke(
                    _library,
                    [Native(session), Native(objectHandle), attributes, Native((ulong)attributes.Length)]));
                if (ReadLength(attributes.GetValue(0)!) != expected.Identifier ||
                    includeValue && ReadLength(attributes.GetValue(1)!) != expected.Value)
                {
                    throw new InvalidOperationException();
                }

                var identifier = Copy((IntPtr)Field(attributes.GetValue(0)!, "value"), expected.Identifier);
                var value = includeValue
                    ? Copy((IntPtr)Field(attributes.GetValue(1)!, "value"), expected.Value)
                    : null;
                return new Pkcs11HelperObject(identifier, value);
            }
            finally
            {
                FreeAll(allocations);
            }
        }

        private Array CreateAttributeArray(
            ulong objectClass,
            byte[]? id,
            List<IntPtr> allocations)
        {
            var count = id is null ? 1 : 2;
            var result = Array.CreateInstance(_attributeType, count);
            result.SetValue(CreateAttribute(0UL, NativeBytes(objectClass), allocations), 0);
            if (id is not null)
            {
                result.SetValue(CreateAttribute(0x102UL, id, allocations), 1);
            }

            return result;
        }

        private Array CreateEmptyAttributeArray(bool includeValue)
        {
            var result = Array.CreateInstance(_attributeType, includeValue ? 2 : 1);
            result.SetValue(CreateEmptyAttribute(0x102UL), 0);
            if (includeValue)
            {
                result.SetValue(CreateEmptyAttribute(0x11UL), 1);
            }

            return result;
        }

        private Array CreateReadableAttributeArray(
            Pkcs11HelperAttributeLengths expected,
            bool includeValue,
            List<IntPtr> allocations)
        {
            var result = Array.CreateInstance(_attributeType, includeValue ? 2 : 1);
            result.SetValue(CreateAttribute(0x102UL, new byte[expected.Identifier], allocations), 0);
            if (includeValue)
            {
                result.SetValue(CreateAttribute(0x11UL, new byte[expected.Value], allocations), 1);
            }

            return result;
        }

        private object CreateEmptyAttribute(ulong type)
        {
            var attribute = Activator.CreateInstance(_attributeType)!;
            SetField(attribute, "type", Native(type));
            SetField(attribute, "value", IntPtr.Zero);
            SetField(attribute, "valueLen", Native(0));
            return attribute;
        }

        private object CreateAttribute(ulong type, byte[] value, List<IntPtr> allocations)
        {
            var attribute = CreateEmptyAttribute(type);
            var pointer = Marshal.AllocHGlobal(value.Length);
            allocations.Add(pointer);
            Marshal.Copy(value, 0, pointer, value.Length);
            SetField(attribute, "value", pointer);
            SetField(attribute, "valueLen", Native((ulong)value.Length));
            return attribute;
        }

        private byte[] NativeBytes(ulong value) => Platform.NativeULongSize == 4
            ? BitConverter.GetBytes(checked((uint)value))
            : BitConverter.GetBytes(value);

        private int ReadLength(object attribute) =>
            CheckedInt(Field(attribute, "valueLen"), int.MaxValue);

        private object Native(ulong value) =>
            Pkcs11InteropNativeValue.Box(Platform.NativeULongSize, value);

        private MethodInfo Method(string name) =>
            _libraryType.GetMethod(name, BindingFlags.Instance | BindingFlags.Public)
            ?? throw new MissingMethodException(_libraryType.FullName, name);

        private static object Field(object value, string name) =>
            value.GetType().GetField(name)!.GetValue(value)
            ?? throw new InvalidOperationException();

        private static void SetField(object value, string name, object fieldValue) =>
            value.GetType().GetField(name)!.SetValue(value, fieldValue);

        private static int CheckedInt(object? value, int maximum)
        {
            var converted = Convert.ToUInt64(value, System.Globalization.CultureInfo.InvariantCulture);
            if (converted > (ulong)maximum)
            {
                throw new Pkcs11HelperContractException();
            }

            return checked((int)converted);
        }

        private static ulong ReturnValue(object? result) =>
            Convert.ToUInt64(result, System.Globalization.CultureInfo.InvariantCulture);

        private static void EnsureOk(object? result)
        {
            var value = ReturnValue(result);
            Pkcs11InteropReturnCode.ThrowIfFailed(value);
        }

        private static byte[] Copy(IntPtr pointer, int length)
        {
            var value = new byte[length];
            Marshal.Copy(pointer, value, 0, length);
            return value;
        }

        private static void FreeAll(IEnumerable<IntPtr> allocations)
        {
            foreach (var pointer in allocations)
            {
                Marshal.FreeHGlobal(pointer);
            }
        }

        private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

        private sealed class Slot(
            ReflectionLowLevelLibrary owner,
            ulong slotId,
            string tokenSerial) : IPkcs11HelperSlot
        {
            public ulong SlotId => slotId;

            public string TokenSerial => tokenSerial;

            public IPkcs11HelperSession OpenSession() =>
                new Pkcs11InteropHelperSession(owner.OpenSession(slotId));
        }

        private sealed class Session(ReflectionLowLevelLibrary owner, ulong session) : IPkcs11LowLevelSession
        {
            private bool _disposed;

            public IPkcs11LowLevelFindOperation BeginFind(
                Pkcs11HelperObjectClass objectClass,
                byte[]? id) =>
                owner.BeginFind(session, objectClass, id);

            public Pkcs11HelperAttributeLengths ReadAttributeLengths(
                ulong objectHandle,
                bool includeValue) =>
                owner.ReadAttributeLengths(session, objectHandle, includeValue);

            public Pkcs11HelperObject ReadAttributes(
                ulong objectHandle,
                Pkcs11HelperAttributeLengths expected,
                bool includeValue) =>
                owner.ReadAttributes(session, objectHandle, expected, includeValue);

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                EnsureOk(owner.Method("C_CloseSession").Invoke(owner._library, [owner.Native(session)]));
            }
        }

        private sealed class FindOperation(
            ReflectionLowLevelLibrary owner,
            ulong session) : IPkcs11LowLevelFindOperation
        {
            private bool _disposed;

            public IReadOnlyList<ulong> Read(int maximumObjects)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (maximumObjects <= 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(maximumObjects));
                }

                var handles = Array.CreateInstance(owner._nativeUnsignedLongType, maximumObjects);
                var args = new object?[]
                {
                    owner.Native(session),
                    handles,
                    owner.Native((ulong)maximumObjects),
                    owner.Native(0),
                };
                EnsureOk(owner.Method("C_FindObjects").Invoke(owner._library, args));
                var count = CheckedInt(args[3], maximumObjects);
                return Enumerable.Range(0, count)
                    .Select(index => Convert.ToUInt64(
                        handles.GetValue(index),
                        System.Globalization.CultureInfo.InvariantCulture))
                    .ToArray();
            }

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                EnsureOk(owner.Method("C_FindObjectsFinal").Invoke(
                    owner._library,
                    [owner.Native(session)]));
            }
        }
    }
}
