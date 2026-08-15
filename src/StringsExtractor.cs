namespace MemReader;

/// <summary>Una cadena encontrada en la memoria del proceso.</summary>
public sealed record FoundString(ulong Address, string Encoding, string Text);

/// <summary>
/// Extrae cadenas imprimibles (ASCII y UTF-16LE) de la memoria legible, al estilo
/// de la utilidad 'strings'. Util para triage/forense: localizar rutas, URLs,
/// comandos, claves o mensajes en claro. Solo lectura.
/// </summary>
public static class StringsExtractor
{
    public static List<FoundString> Extract(
        ProcessMemoryReader reader, int minLen, int maxResults,
        IProgress<string>? progress, CancellationToken ct)
    {
        var result = new List<FoundString>();
        if (minLen < 1) minLen = 1;

        var regions = reader.EnumerateRegions(onlyReadable: true);
        const int chunk = 1 << 20;
        int idx = 0;

        foreach (var r in regions)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            progress?.Report($"Extrayendo strings... region {idx}/{regions.Count} ({result.Count:N0})");

            ulong pos = r.BaseAddress;
            ulong end = r.BaseAddress + r.RegionSize;
            while (pos < end)
            {
                ct.ThrowIfCancellationRequested();
                int want = (int)Math.Min((ulong)chunk, end - pos);
                byte[] data;
                try { data = reader.ReadBytes(pos, want); }
                catch { break; }
                if (data.Length == 0) break;

                ExtractAscii(data, pos, minLen, result, maxResults);
                if (result.Count >= maxResults) return result;
                ExtractUtf16(data, pos, minLen, result, maxResults);
                if (result.Count >= maxResults) return result;

                if (data.Length < want) break;
                pos += (ulong)data.Length;
            }
        }
        return result;
    }

    private static bool Printable(byte b) => b >= 0x20 && b < 0x7F;

    private static void ExtractAscii(byte[] d, ulong bas, int minLen, List<FoundString> outp, int max)
    {
        int start = -1;
        for (int i = 0; i < d.Length; i++)
        {
            if (Printable(d[i]))
            {
                if (start < 0) start = i;
            }
            else
            {
                if (start >= 0 && i - start >= minLen)
                {
                    outp.Add(new FoundString(bas + (ulong)start, "ASCII", Ascii(d, start, i - start)));
                    if (outp.Count >= max) return;
                }
                start = -1;
            }
        }
        if (start >= 0 && d.Length - start >= minLen)
            outp.Add(new FoundString(bas + (ulong)start, "ASCII", Ascii(d, start, d.Length - start)));
    }

    private static void ExtractUtf16(byte[] d, ulong bas, int minLen, List<FoundString> outp, int max)
    {
        // Secuencias de char imprimible (byte bajo) con byte alto 0 (UTF-16LE, subconjunto ASCII).
        int start = -1, count = 0;
        for (int i = 0; i + 1 < d.Length; i += 2)
        {
            bool printable = d[i + 1] == 0 && Printable(d[i]);
            if (printable)
            {
                if (start < 0) { start = i; count = 0; }
                count++;
            }
            else
            {
                if (start >= 0 && count >= minLen)
                {
                    outp.Add(new FoundString(bas + (ulong)start, "UTF-16", Utf16(d, start, count)));
                    if (outp.Count >= max) return;
                }
                start = -1; count = 0;
            }
        }
        if (start >= 0 && count >= minLen)
            outp.Add(new FoundString(bas + (ulong)start, "UTF-16", Utf16(d, start, count)));
    }

    private static string Ascii(byte[] d, int off, int len)
    {
        var sb = new System.Text.StringBuilder(len);
        for (int i = 0; i < len; i++) sb.Append((char)d[off + i]);
        return sb.ToString();
    }

    private static string Utf16(byte[] d, int off, int count)
    {
        var sb = new System.Text.StringBuilder(count);
        for (int i = 0; i < count; i++) sb.Append((char)d[off + i * 2]);
        return sb.ToString();
    }
}
