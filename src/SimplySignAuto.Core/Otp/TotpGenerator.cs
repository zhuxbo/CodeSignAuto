using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace SimplySignAuto.Core.Otp;

public static class TotpGenerator
{
    public static string Generate(OtpauthProfile profile, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var unixSeconds = now.ToUnixTimeSeconds();
        if (unixSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(now));
        }

        var counter = (ulong)(unixSeconds / profile.Period);
        Span<byte> counterBytes = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(counterBytes, counter);

        var secret = Base32.Decode(profile.Secret);
        try
        {
            using var hmac = new HMACSHA256(secret);
            var digest = hmac.ComputeHash(counterBytes.ToArray());
            var offset = digest[^1] & 0x0f;
            var binary = BinaryPrimitives.ReadUInt32BigEndian(digest.AsSpan(offset, sizeof(uint))) & 0x7fffffff;
            var divisor = profile.Digits == 6 ? 1_000_000u : 100_000_000u;
            return (binary % divisor).ToString($"D{profile.Digits}", CultureInfo.InvariantCulture);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
