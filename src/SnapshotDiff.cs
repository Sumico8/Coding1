using System.Text;

namespace MemReader;

/// <summary>Un tramo de bytes que cambio entre dos capturas de memoria.</summary>
public sealed record DiffRun(ulong Address, byte[] Before, byte[] After)
{
    public string AddressText => $"0x{Address:X}";
    public string BeforeHex => Hex(Before);
    public string AfterHex => Hex(After);

    private static string Hex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 3);
        foreach (var x in b) sb.Append(x.ToString("X2")).Append(' ');
        return sb.ToString().TrimEnd();
    }
}

/// <summary>
/// Compara dos capturas (snapshots) de una misma zona de memoria tomadas en
/// momentos distintos y devuelve los tramos que cambiaron. Util para observar
/// como una app modifica un valor, o como un cargador desempaqueta codigo en
/// memoria. Solo lectura.
/// </summary>
public static class SnapshotDiff
{
    public static List<DiffRun> Diff(byte[] a, byte[] b, ulong baseAddr, int maxRuns = 5000)
    {
        var runs = new List<DiffRun>();
        int n = Math.Min(a.Length, b.Length);
        int i = 0;
        while (i < n && runs.Count < maxRuns)
        {
            if (a[i] == b[i]) { i++; continue; }
            int start = i;
            while (i < n && a[i] != b[i] && i - start < 4096) i++;
            int len = i - start;
            var before = new byte[len];
            var after = new byte[len];
            Array.Copy(a, start, before, 0, len);
            Array.Copy(b, start, after, 0, len);
            runs.Add(new DiffRun(baseAddr + (ulong)start, before, after));
        }
        return runs;
    }

    public static int CountChanged(byte[] a, byte[] b)
    {
        int n = Math.Min(a.Length, b.Length);
        int c = 0;
        for (int i = 0; i < n; i++) if (a[i] != b[i]) c++;
        return c;
    }
}
