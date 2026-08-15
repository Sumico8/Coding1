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

        // Dedup por direccion (el solape entre trozos re-lee unos bytes).
        var seenAscii = new HashSet<ulong>();
        var seenUtf16 = new HashSet<ulong>();

        var regions = reader.EnumerateRegions(onlyReadable: true);
        const int chunk = 1 << 20;
        const int overlap = 1024; // reensambla cadenas que cruzan el limite del trozo
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

                ExtractAscii(data, pos, minLen, result, maxResults, seenAscii);
                if (result.Count >= maxResults) return result;
                // UTF-16 en offsets pares e impares (subconjunto ASCII).
                ExtractUtf16(data, pos, minLen, result, maxResults, seenUtf16, 0);
                if (result.Count >= maxResults) return result;
                ExtractUtf16(data, pos, minLen, result, maxResults, seenUtf16, 1);
                if (result.Count >= maxResults) return result;

                int own = data.Length - overlap;
                bool last = data.Length < want || (pos + (ulong)data.Length) >= end || own <= 0;
                if (last) break;
                pos += (ulong)own;
            }
        }
        return result;
    }

    private static bool Printable(byte b) => b >= 0x20 && b < 0x7F;

    private static void ExtractAscii(byte[] d, ulong bas, int minLen, List<FoundString> outp, int max, HashSet<ulong> seen)
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
                    ulong addr = bas + (ulong)start;
                    if (seen.Add(addr))
                    {
                        outp.Add(new FoundString(addr, "ASCII", Ascii(d, start, i - start)));
                        if (outp.Count >= max) return;
                    }
                }
                start = -1;
            }
        }
        if (start >= 0 && d.Length - start >= minLen)
        {
            ulong addr = bas + (ulong)start;
            if (seen.Add(addr))
                outp.Add(new FoundString(addr, "ASCII", Ascii(d, start, d.Length - start)));
        }
    }

    private static void ExtractUtf16(byte[] d, ulong bas, int minLen, List<FoundString> outp, int max, HashSet<ulong> seen, int startOffset)
    {
        // Secuencias de char imprimible (byte bajo) con byte alto 0 (UTF-16LE, subconjunto ASCII).
        int start = -1, count = 0;
        for (int i = startOffset; i + 1 < d.Length; i += 2)
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
                    ulong addr = bas + (ulong)start;
                    if (seen.Add(addr))
                    {
                        outp.Add(new FoundString(addr, "UTF-16", Utf16(d, start, count)));
                        if (outp.Count >= max) return;
                    }
                }
                start = -1; count = 0;
            }
        }
        if (start >= 0 && count >= minLen)
        {
            ulong addr = bas + (ulong)start;
            if (seen.Add(addr))
                outp.Add(new FoundString(addr, "UTF-16", Utf16(d, start, count)));
        }
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
