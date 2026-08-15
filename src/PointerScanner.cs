namespace MemReader;

/// <summary>Una direccion que contiene un puntero cercano al objetivo.</summary>
public sealed record PointerHit(ulong Address, long Offset, ulong Value);

/// <summary>
/// Una ruta de puntero estatica: modulo+offset base y una lista de offsets.
/// Resolucion: addr = base; por cada off: addr = read_ptr(addr) + off; el ultimo
/// addr es la direccion final. Permite reencontrar un valor tras reiniciar la app.
/// </summary>
public sealed record PointerPath(
    string ModuleName, ulong ModuleBase, long BaseOffset, IReadOnlyList<long> Offsets)
{
    public string Text
    {
        get
        {
            var sb = new System.Text.StringBuilder();
            sb.Append($"[\"{ModuleName}\"+0x{BaseOffset:X}]");
            foreach (var o in Offsets)
                sb.Append($" -> +0x{o:X}");
            return sb.ToString();
        }
    }
}

/// <summary>
/// Motor de punteros/offsets (solo lectura). Construye un indice inverso de
/// valores-puntero y escanea hacia atras desde una direccion objetivo para hallar
/// rutas de puntero estables ancladas a un modulo. No escribe ni modifica nada.
/// </summary>
public sealed class PointerScanner
{
    private readonly ProcessMemoryReader _reader;
    private readonly int _ptrSize;

    private ulong[] _idxValues = Array.Empty<ulong>();
    private ulong[] _idxAddrs = Array.Empty<ulong>();
    private (ulong start, ulong end)[] _readable = Array.Empty<(ulong, ulong)>();
    private List<ModuleInfo> _modules;

    public bool IndexBuilt => _idxValues.Length > 0;
    public int IndexCount => _idxValues.Length;
    public int PointerSize => _ptrSize;

    public PointerScanner(ProcessMemoryReader reader)
    {
        _reader = reader;
        _ptrSize = reader.IsTargetWow64() ? 4 : 8;
        _modules = reader.EnumerateModules();
    }

    /// <summary>A1: expresa una direccion como modulo + offset, si cae en un modulo.</summary>
    public (ModuleInfo mod, ulong offset)? ResolveModuleOffset(ulong address)
    {
        foreach (var m in _modules)
        {
            ulong end = m.BaseAddress + (ulong)m.Size;
            if (address >= m.BaseAddress && address < end)
                return (m, address - m.BaseAddress);
        }
        return null;
    }

    /// <summary>Construye el indice inverso de valores-puntero de toda la memoria legible.</summary>
    public void BuildIndex(int maxMillionPointers, IProgress<string>? progress, CancellationToken ct)
    {
        var regions = _reader.EnumerateRegions(onlyReadable: true);
        _readable = regions
            .Select(r => (r.BaseAddress, r.BaseAddress + r.RegionSize))
            .OrderBy(t => t.Item1)
            .ToArray();
        _modules = _reader.EnumerateModules();

        ulong minPtr = 0x10000;
        ulong maxPtr = _ptrSize == 8 ? 0x7FFFFFFFFFFFUL : 0xFFFFFFFFUL;
        long cap = (long)maxMillionPointers * 1_000_000L;

        var values = new List<ulong>(1 << 20);
        var addrs = new List<ulong>(1 << 20);
        const int chunkSize = 1 << 20;

        int idx = 0;
        bool capped = false;
        foreach (var r in regions)
        {
            if (capped) break;
            ct.ThrowIfCancellationRequested();
            idx++;
            progress?.Report($"Indexando punteros... region {idx}/{regions.Count} ({values.Count:N0})");

            ulong pos = r.BaseAddress;
            ulong end = r.BaseAddress + r.RegionSize;
            while (pos < end)
            {
                ct.ThrowIfCancellationRequested();
                int want = (int)Math.Min((ulong)chunkSize, end - pos);
                byte[] data;
                try { data = _reader.ReadBytes(pos, want); }
                catch { break; }
                if (data.Length < _ptrSize) break;

                for (int i = 0; i + _ptrSize <= data.Length; i += _ptrSize)
                {
                    ulong v = _ptrSize == 8
                        ? BitConverter.ToUInt64(data, i)
                        : BitConverter.ToUInt32(data, i);
                    if (v < minPtr || v > maxPtr) continue;
                    if (!InReadable(v)) continue;
                    values.Add(v);
                    addrs.Add(pos + (ulong)i);
                    if (values.Count >= cap) { capped = true; break; }
                }

                if (data.Length < want) break;
                pos += (ulong)data.Length; // regiones alineadas: mantiene alineacion de puntero
            }
        }

        if (capped)
            progress?.Report($"Tope de {cap:N0} punteros alcanzado; el escaneo puede ser incompleto.");

        _idxValues = values.ToArray();
        _idxAddrs = addrs.ToArray();
        Array.Sort(_idxValues, _idxAddrs); // ordena por valor, reordenando direcciones en paralelo
    }

    /// <summary>A2: direcciones cuyo puntero cae en [target-maxOffset, target].</summary>
    public List<PointerHit> FindPointersTo(ulong target, ulong maxOffset)
    {
        var hits = new List<PointerHit>();
        ulong lo = target > maxOffset ? target - maxOffset : 0;
        int start = LowerBound(_idxValues, lo);
        for (int i = start; i < _idxValues.Length && _idxValues[i] <= target; i++)
            hits.Add(new PointerHit(_idxAddrs[i], (long)(target - _idxValues[i]), _idxValues[i]));
        return hits;
    }

    /// <summary>A3: rutas de puntero estaticas (modulo+offsets) que resuelven al objetivo.</summary>
    public List<PointerPath> ScanChains(
        ulong target, int maxDepth, ulong maxOffset, int maxResults,
        IProgress<string>? progress, CancellationToken ct)
    {
        var results = new List<PointerPath>();
        var queue = new Queue<(ulong addr, List<long> offsetsRev)>();
        queue.Enqueue((target, new List<long>()));

        long expanded = 0;
        const long maxExpanded = 300_000;

        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (addrNear, offsetsRev) = queue.Dequeue();
            expanded++;
            if (expanded % 500 == 0)
                progress?.Report($"Escaneando... nodos {expanded:N0}, rutas {results.Count}");
            if (expanded > maxExpanded) break;

            foreach (var h in FindPointersTo(addrNear, maxOffset))
            {
                var newRev = new List<long>(offsetsRev.Count + 1) { h.Offset };
                newRev.AddRange(offsetsRev);

                var mod = ResolveModuleOffset(h.Address);
                if (mod != null)
                {
                    results.Add(new PointerPath(
                        mod.Value.mod.Name, mod.Value.mod.BaseAddress, (long)mod.Value.offset, newRev));
                    if (results.Count >= maxResults) return results;
                }
                else if (offsetsRev.Count + 1 < maxDepth)
                {
                    queue.Enqueue((h.Address, newRev));
                }
            }
        }
        return results;
    }

    /// <summary>A4: resuelve una ruta de puntero en vivo y devuelve la direccion final.</summary>
    public (ulong finalAddress, byte[] value)? ResolvePath(
        ulong moduleBase, long baseOffset, IReadOnlyList<long> offsets, int valueBytes)
    {
        ulong addr = moduleBase + (ulong)baseOffset;
        foreach (var off in offsets)
        {
            byte[] p;
            try { p = _reader.ReadBytes(addr, _ptrSize); }
            catch { return null; }
            if (p.Length < _ptrSize) return null;
            ulong val = _ptrSize == 8
                ? BitConverter.ToUInt64(p, 0)
                : BitConverter.ToUInt32(p, 0);
            addr = val + (ulong)off;
        }
        byte[] value;
        try { value = _reader.ReadBytes(addr, valueBytes); }
        catch { value = Array.Empty<byte>(); }
        return (addr, value);
    }

    private bool InReadable(ulong v)
    {
        int lo = 0, hi = _readable.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            var (s, e) = _readable[mid];
            if (v < s) hi = mid - 1;
            else if (v >= e) lo = mid + 1;
            else return true;
        }
        return false;
    }

    private static int LowerBound(ulong[] arr, ulong key)
    {
        int lo = 0, hi = arr.Length;
        while (lo < hi)
        {
            int mid = (lo + hi) >> 1;
            if (arr[mid] < key) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }
}
