namespace CodeSignAuto.Protocol;

public static class UploadSizeLimit
{
    public const int DefaultMegabytes = 512;
    public const int MaximumMegabytes = 5120;
    public const long BytesPerMegabyte = 1024L * 1024;

    public static long EffectiveBytes(int megabytes)
    {
        if (megabytes is < 0 or > MaximumMegabytes)
        {
            throw new ArgumentOutOfRangeException(nameof(megabytes));
        }

        return megabytes == 0 ? long.MaxValue : megabytes * BytesPerMegabyte;
    }
}
