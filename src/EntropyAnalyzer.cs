namespace MemReader;

/// <summary>Entropia de Shannon (0..8 bits/byte). Alta entropia (>7.2) sugiere
/// datos comprimidos, cifrados o empaquetados.</summary>
public static class EntropyAnalyzer
{
    public static double Shannon(byte[] data)
    {
        if (data.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;

        double n = data.Length;
        double e = 0;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / n;
            e -= p * Math.Log2(p);
        }
        return e;
    }
}
