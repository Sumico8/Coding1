using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MemReader;

/// <summary>Un modulo (DLL/EXE) cargado en el proceso.</summary>
public sealed record ModuleInfo(string Name, ulong BaseAddress, long Size, string Path)
{
    public string BaseText => $"0x{BaseAddress:X}";
    public string SizeText => Size >= 1024 * 1024
        ? $"{Size / (1024.0 * 1024.0):0.##} MB"
        : $"{Size / 1024.0:0.##} KB";
}

/// <summary>Describe una region de memoria de un proceso.</summary>
public sealed record MemoryRegion(
    ulong BaseAddress,
    ulong RegionSize,
    uint State,
    uint Protect,
    uint Type)
{
    public bool IsReadable => NativeMethods.IsReadable(Protect);
    public string ProtectText => NativeMethods.ProtectToString(Protect);
    public string TypeText => NativeMethods.TypeToString(Type);
    public string BaseText => $"0x{BaseAddress:X}";
    public string SizeText => FormatSize(RegionSize);

    private static string FormatSize(ulong bytes)
    {
        string[] u = { "B", "KB", "MB", "GB" };
        double v = bytes;
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return i == 0 ? $"{bytes} B" : $"{v:0.##} {u[i]}";
    }
}

/// <summary>Un resultado de la busqueda de patrones/cadenas en memoria.</summary>
public sealed record SearchHit(ulong Address, string Encoding, string Preview);

/// <summary>
/// Nucleo de la herramienta. Abre un proceso con permiso de solo-lectura,
/// enumera sus regiones de memoria y lee bytes usando ReadProcessMemory.
/// Implementa IDisposable para cerrar siempre el handle del proceso.
/// </summary>
public sealed class ProcessMemoryReader : IDisposable
{
    private IntPtr _handle = IntPtr.Zero;
    public int ProcessId { get; }
    public bool IsOpen => _handle != IntPtr.Zero;

    public ProcessMemoryReader(int pid)
    {
        ProcessId = pid;
        // Solo pedimos lo minimo necesario: consultar informacion + leer memoria.
        // No pedimos PROCESS_VM_WRITE ni PROCESS_VM_OPERATION: esta herramienta
        // no modifica la memoria de otros procesos, solo la lee.
        uint access = NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ;
        _handle = NativeMethods.OpenProcess(access, false, pid);

        if (_handle == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err,
                $"No se pudo abrir el proceso {pid}. Codigo Win32: {err}. " +
                "Causas habituales: falta ejecutar como Administrador, o el proceso " +
                "esta protegido por el sistema (PPL) y Windows deniega el acceso.");
        }
    }

    /// <summary>Recorre todo el espacio de direcciones y devuelve las regiones asignadas.</summary>
    public List<MemoryRegion> EnumerateRegions(bool onlyReadable = true)
    {
        EnsureOpen();
        var regions = new List<MemoryRegion>();
        ulong address = 0;
        // Limite superior tipico del espacio de usuario en x64 (128 TB).
        const ulong maxUserAddress = 0x00007FFFFFFFFFFF;
        int mbiSize = Marshal.SizeOf<NativeMethods.MEMORY_BASIC_INFORMATION64>();

        while (address < maxUserAddress)
        {
            IntPtr result = NativeMethods.VirtualQueryEx(
                _handle, (IntPtr)address, out var mbi, (IntPtr)mbiSize);

            if (result == IntPtr.Zero)
                break; // Ya no hay mas regiones consultables.

            if (mbi.RegionSize == 0)
                break; // Salvaguarda para evitar un bucle infinito.

            bool committed = mbi.State == NativeMethods.MEM_COMMIT;
            if (committed && (!onlyReadable || NativeMethods.IsReadable(mbi.Protect)))
            {
                regions.Add(new MemoryRegion(
                    mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type));
            }

            ulong next = mbi.BaseAddress + mbi.RegionSize;
            if (next <= address) break; // Proteccion contra desbordamiento.
            address = next;
        }
        return regions;
    }

    /// <summary>Lee hasta <paramref name="size"/> bytes a partir de <paramref name="address"/>.</summary>
    public byte[] ReadBytes(ulong address, int size)
    {
        EnsureOpen();
        if (size <= 0) return Array.Empty<byte>();

        var buffer = new byte[size];
        bool ok = NativeMethods.ReadProcessMemory(
            _handle, (IntPtr)address, buffer, (IntPtr)size, out IntPtr read);

        int readCount = (int)read;
        if (!ok && readCount == 0)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err,
                $"No se pudo leer 0x{address:X}. Codigo Win32: {err} " +
                "(la region puede estar protegida, descargada o ser inaccesible).");
        }

        if (readCount == size) return buffer;

        // Lectura parcial: devolvemos solo lo que realmente se leyo.
        var partial = new byte[readCount];
        Array.Copy(buffer, partial, readCount);
        return partial;
    }

    /// <summary>
    /// Busca una cadena en todas las regiones legibles del proceso.
    /// Prueba las codificaciones ASCII/Latin1 y UTF-16LE (habitual en Windows).
    /// Util en pentesting/forense para localizar tokens, claves o texto en memoria.
    /// </summary>
    public List<SearchHit> SearchString(
        string needle,
        int maxHits,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(needle)) return new List<SearchHit>();
        var patterns = new List<(byte[] pattern, string label, string preview)>
        {
            (System.Text.Encoding.Latin1.GetBytes(needle), "ASCII", needle),
            (System.Text.Encoding.Unicode.GetBytes(needle), "UTF-16", needle),
        };
        return SearchPatterns(patterns, maxHits, progress, ct);
    }

    /// <summary>
    /// Busca uno o varios patrones de bytes en todas las regiones legibles.
    /// La UI construye los patrones segun el tipo (texto, Int32, Float, bytes hex...).
    /// </summary>
    public List<SearchHit> SearchPatterns(
        IReadOnlyList<(byte[] pattern, string label, string preview)> patterns,
        int maxHits,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        EnsureOpen();
        var hits = new List<SearchHit>();
        var active = patterns.Where(p => p.pattern.Length > 0).ToList();
        if (active.Count == 0) return hits;

        var regions = EnumerateRegions(onlyReadable: true);
        const int chunkSize = 1 << 20; // 1 MB por lectura.
        // Solape para no perder coincidencias que crucen el limite de un chunk.
        int overlap = active.Max(p => p.pattern.Length);

        int idx = 0;
        foreach (var region in regions)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            progress?.Report($"Buscando... region {idx}/{regions.Count} ({hits.Count} coincidencias)");

            ulong pos = region.BaseAddress;
            ulong end = region.BaseAddress + region.RegionSize;

            while (pos < end)
            {
                ct.ThrowIfCancellationRequested();
                int want = (int)Math.Min((ulong)chunkSize, end - pos);
                byte[] data;
                try { data = ReadBytes(pos, want); }
                catch { break; } // Region inaccesible: pasamos a la siguiente.

                if (data.Length == 0) break;

                foreach (var p in active)
                {
                    FindAll(data, p.pattern, pos, p.label, p.preview, hits, maxHits);
                    if (hits.Count >= maxHits) return hits;
                }

                if (data.Length < want) break; // No se leyo todo: fin de la region util.

                ulong advance = (ulong)Math.Max(1, data.Length - overlap);
                pos += advance;
            }
        }
        return hits;
    }

    /// <summary>
    /// Busca un patron de bytes con comodines (AOB) en todas las regiones
    /// legibles. En <paramref name="mask"/>, 0xFF = el byte debe coincidir y
    /// 0x00 = comodin. Util para firmas de reversing (p. ej. 48 8B ?? ?? E8).
    /// </summary>
    public List<SearchHit> SearchMasked(
        byte[] pattern, byte[] mask, string label, int maxHits,
        IProgress<string>? progress, CancellationToken ct)
    {
        EnsureOpen();
        var hits = new List<SearchHit>();
        if (pattern.Length == 0 || pattern.Length != mask.Length) return hits;

        var regions = EnumerateRegions(onlyReadable: true);
        const int chunkSize = 1 << 20;
        int overlap = pattern.Length;

        int idx = 0;
        foreach (var region in regions)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            progress?.Report($"Buscando AOB... region {idx}/{regions.Count} ({hits.Count} coincidencias)");

            ulong pos = region.BaseAddress;
            ulong end = region.BaseAddress + region.RegionSize;
            while (pos < end)
            {
                ct.ThrowIfCancellationRequested();
                int want = (int)Math.Min((ulong)chunkSize, end - pos);
                byte[] data;
                try { data = ReadBytes(pos, want); }
                catch { break; }
                if (data.Length == 0) break;

                FindAllMasked(data, pattern, mask, pos, label, hits, maxHits);
                if (hits.Count >= maxHits) return hits;

                if (data.Length < want) break;
                ulong advance = (ulong)Math.Max(1, data.Length - overlap);
                pos += advance;
            }
        }
        return hits;
    }

    private static void FindAllMasked(
        byte[] haystack, byte[] pattern, byte[] mask, ulong baseAddr,
        string label, List<SearchHit> hits, int maxHits)
    {
        int limit = haystack.Length - pattern.Length;
        for (int i = 0; i <= limit; i++)
        {
            int j = 0;
            for (; j < pattern.Length; j++)
                if (mask[j] != 0 && haystack[i + j] != pattern[j]) break;

            if (j == pattern.Length)
            {
                hits.Add(new SearchHit(baseAddr + (ulong)i, label, HexPreview(haystack, i, pattern.Length)));
                if (hits.Count >= maxHits) return;
            }
        }
    }

    private static string HexPreview(byte[] d, int off, int len)
    {
        var sb = new System.Text.StringBuilder(len * 3);
        for (int i = 0; i < len && off + i < d.Length; i++)
            sb.Append(d[off + i].ToString("X2")).Append(' ');
        return sb.ToString().TrimEnd();
    }

    /// <summary>Enumera los modulos (DLL/EXE) cargados en el proceso.</summary>
    public List<ModuleInfo> EnumerateModules()
    {
        var list = new List<ModuleInfo>();
        try
        {
            using var proc = Process.GetProcessById(ProcessId);
            foreach (ProcessModule m in proc.Modules)
            {
                try
                {
                    list.Add(new ModuleInfo(
                        m.ModuleName ?? "(sin nombre)",
                        (ulong)m.BaseAddress.ToInt64(),
                        m.ModuleMemorySize,
                        m.FileName ?? ""));
                }
                catch { /* modulo inaccesible: lo saltamos */ }
            }
        }
        catch
        {
            // Enumerar modulos puede fallar por diferencia de arquitectura
            // (proceso de 32 bits) o por permisos. Devolvemos lo que tengamos.
        }
        return list.OrderBy(m => m.BaseAddress).ToList();
    }

    /// <summary>Ruta completa del ejecutable del proceso, si es accesible.</summary>
    public string? GetProcessPath()
    {
        try
        {
            using var proc = Process.GetProcessById(ProcessId);
            return proc.MainModule?.FileName;
        }
        catch { return null; }
    }

    /// <summary>Devuelve true si el proceso objetivo es de 32 bits (WOW64).</summary>
    public bool IsTargetWow64()
    {
        try
        {
            if (NativeMethods.IsWow64Process(_handle, out bool wow64))
                return wow64;
        }
        catch { /* ignore */ }
        return false;
    }

    /// <summary>
    /// Vuelca TODAS las regiones legibles a una carpeta (un archivo por region)
    /// mas un indice de texto. Util para forense/analisis en tu laboratorio.
    /// </summary>
    public (int files, long bytes) DumpAllReadableRegions(
        string folder, IProgress<string>? progress, CancellationToken ct)
    {
        EnsureOpen();
        Directory.CreateDirectory(folder);
        var regions = EnumerateRegions(onlyReadable: true);
        var index = new System.Text.StringBuilder();
        index.AppendLine("archivo\tbase\ttamano\tproteccion\ttipo");

        int files = 0;
        long totalBytes = 0;
        int idx = 0;
        foreach (var r in regions)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            progress?.Report($"Volcando region {idx}/{regions.Count} ({files} archivos)");

            string fname = $"0x{r.BaseAddress:X}_{r.ProtectText}.bin";
            string fpath = Path.Combine(folder, fname);
            try
            {
                long written = DumpRegionToFile(r, fpath, ct);
                if (written > 0)
                {
                    files++;
                    totalBytes += written;
                    index.AppendLine($"{fname}\t0x{r.BaseAddress:X}\t{r.RegionSize}\t{r.ProtectText}\t{r.TypeText}");
                }
                else
                {
                    File.Delete(fpath); // No se pudo leer: no dejamos un archivo vacio.
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { /* region inaccesible */ }
        }

        File.WriteAllText(Path.Combine(folder, "_indice.txt"), index.ToString());
        return (files, totalBytes);
    }

    private static void FindAll(
        byte[] haystack, byte[] needle, ulong baseAddr,
        string encoding, string preview, List<SearchHit> hits, int maxHits)
    {
        if (needle.Length == 0) return;
        int i = 0;
        while (i <= haystack.Length - needle.Length)
        {
            int found = IndexOf(haystack, needle, i);
            if (found < 0) break;
            hits.Add(new SearchHit(baseAddr + (ulong)found, encoding, preview));
            if (hits.Count >= maxHits) return;
            i = found + needle.Length;
        }
    }

    private static int IndexOf(byte[] haystack, byte[] needle, int start)
    {
        int limit = haystack.Length - needle.Length;
        for (int i = start; i <= limit; i++)
        {
            int j = 0;
            while (j < needle.Length && haystack[i + j] == needle[j]) j++;
            if (j == needle.Length) return i;
        }
        return -1;
    }

    /// <summary>Vuelca una region completa a un archivo, leyendo por trozos.</summary>
    public long DumpRegionToFile(MemoryRegion region, string path, CancellationToken ct)
    {
        EnsureOpen();
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
        long total = 0;
        ulong pos = region.BaseAddress;
        ulong end = region.BaseAddress + region.RegionSize;
        const int chunk = 1 << 20;

        while (pos < end)
        {
            ct.ThrowIfCancellationRequested();
            int want = (int)Math.Min((ulong)chunk, end - pos);
            byte[] data;
            try { data = ReadBytes(pos, want); }
            catch { break; }
            if (data.Length == 0) break;
            fs.Write(data, 0, data.Length);
            total += data.Length;
            if (data.Length < want) break;
            pos += (ulong)data.Length;
        }
        return total;
    }

    /// <summary>
    /// Genera un minidump (.dmp) del proceso, analizable en WinDbg. Con
    /// <paramref name="fullMemory"/> incluye toda la memoria (archivo grande).
    /// Misma capacidad que "Crear archivo de volcado" del Administrador de tareas.
    /// </summary>
    public void WriteMiniDump(string path, bool fullMemory)
    {
        EnsureOpen();
        using var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite);
        int type = fullMemory ? NativeMethods.MiniDumpWithFullMemory : NativeMethods.MiniDumpNormal;
        bool ok = NativeMethods.MiniDumpWriteDump(
            _handle, (uint)ProcessId, fs.SafeFileHandle, type,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (!ok)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Win32Exception(err,
                $"MiniDumpWriteDump fallo (codigo Win32: {err}). " +
                "Algunos procesos protegidos no permiten el volcado.");
        }
    }

    private void EnsureOpen()
    {
        if (!IsOpen)
            throw new InvalidOperationException("El proceso no esta abierto.");
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            NativeMethods.CloseHandle(_handle);
            _handle = IntPtr.Zero;
        }
    }
}
