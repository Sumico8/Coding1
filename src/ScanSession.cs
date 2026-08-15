namespace MemReader;

public enum ScanType { Int32, Int64, Float, Double }
public enum NextFilter { Exact, Changed, Unchanged, Increased, Decreased }

/// <summary>
/// Escaneo iterativo de valores (estilo "next scan"): un primer escaneo por valor
/// exacto produce candidatos, y sucesivos filtros (cambio/aumento/etc.) los
/// estrechan hasta dejar pocas direcciones. Solo lectura. Se combina con
/// PointerScanner: valor encontrado -> estrechar -> sacar ruta de puntero estable.
/// </summary>
public sealed class ScanSession
{
    private readonly ProcessMemoryReader _reader;
    private List<(ulong addr, byte[] prev)> _candidates = new();

    public ScanType Type { get; }
    public int Size { get; }
    public int Count => _candidates.Count;
    public IReadOnlyList<(ulong addr, byte[] value)> Candidates => _candidates;

    public ScanSession(ProcessMemoryReader reader, ScanType type)
    {
        _reader = reader;
        Type = type;
        Size = (type == ScanType.Int64 || type == ScanType.Double) ? 8 : 4;
    }

    private string KindString => Type switch
    {
        ScanType.Int32 => "Int32",
        ScanType.Int64 => "Int64",
        ScanType.Float => "Float",
        ScanType.Double => "Double",
        _ => "Int32"
    };

    /// <summary>Primer escaneo: busca el valor exacto en toda la memoria legible.</summary>
    public void FirstScan(string valueText, int maxCandidates, IProgress<string>? progress, CancellationToken ct)
    {
        var (pattern, label, preview) = ValueInterpreter.BuildPattern(KindString, valueText);
        var patterns = new List<(byte[] pattern, string label, string preview)> { (pattern, label, preview) };
        var hits = _reader.SearchPatterns(patterns, maxCandidates, progress, ct);
        _candidates = hits.Select(h => (h.Address, (byte[])pattern.Clone())).ToList();
    }

    /// <summary>Refina los candidatos segun el filtro (y un valor exacto si aplica).</summary>
    public void NextScan(NextFilter filter, string? valueText, IProgress<string>? progress, CancellationToken ct)
    {
        byte[]? target = null;
        if (filter == NextFilter.Exact)
        {
            if (string.IsNullOrWhiteSpace(valueText))
                throw new ArgumentException("Indica el valor exacto para este filtro.");
            target = ValueInterpreter.BuildPattern(KindString, valueText).pattern;
        }

        var kept = new List<(ulong, byte[])>(_candidates.Count);
        int i = 0;
        foreach (var (addr, prev) in _candidates)
        {
            ct.ThrowIfCancellationRequested();
            if ((++i & 0x3FFF) == 0)
                progress?.Report($"Refinando... {kept.Count:N0}/{_candidates.Count:N0}");

            byte[] cur;
            try { cur = _reader.ReadBytes(addr, Size); }
            catch { continue; }
            if (cur.Length < Size) continue;

            bool keep = filter switch
            {
                NextFilter.Exact => target != null && Equal(cur, target),
                NextFilter.Changed => !Equal(cur, prev),
                NextFilter.Unchanged => Equal(cur, prev),
                NextFilter.Increased => Compare(cur, prev) > 0,
                NextFilter.Decreased => Compare(cur, prev) < 0,
                _ => false
            };
            if (keep) kept.Add((addr, cur));
        }
        _candidates = kept;
    }

    public string FormatValue(byte[] v)
    {
        if (v.Length < Size) return "(?)";
        return Type switch
        {
            ScanType.Int32 => BitConverter.ToInt32(v, 0).ToString(),
            ScanType.Int64 => BitConverter.ToInt64(v, 0).ToString(),
            ScanType.Float => BitConverter.ToSingle(v, 0).ToString("R"),
            ScanType.Double => BitConverter.ToDouble(v, 0).ToString("R"),
            _ => "(?)"
        };
    }

    private int Compare(byte[] a, byte[] b) => Type switch
    {
        ScanType.Int32 => BitConverter.ToInt32(a, 0).CompareTo(BitConverter.ToInt32(b, 0)),
        ScanType.Int64 => BitConverter.ToInt64(a, 0).CompareTo(BitConverter.ToInt64(b, 0)),
        ScanType.Float => BitConverter.ToSingle(a, 0).CompareTo(BitConverter.ToSingle(b, 0)),
        ScanType.Double => BitConverter.ToDouble(a, 0).CompareTo(BitConverter.ToDouble(b, 0)),
        _ => 0
    };

    private static bool Equal(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}
