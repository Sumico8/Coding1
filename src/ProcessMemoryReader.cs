using System.ComponentModel;
using System.Runtime.InteropServices;

namespace MemReader;

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
        EnsureOpen();
        var hits = new List<SearchHit>();
        if (string.IsNullOrEmpty(needle)) return hits;

        byte[] ascii = System.Text.Encoding.Latin1.GetBytes(needle);
        byte[] utf16 = System.Text.Encoding.Unicode.GetBytes(needle);

        var regions = EnumerateRegions(onlyReadable: true);
        const int chunkSize = 1 << 20; // 1 MB por lectura.
        // Solape para no perder coincidencias que crucen el limite de un chunk.
        int overlap = Math.Max(ascii.Length, utf16.Length);

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

                FindAll(data, ascii, pos, "ASCII", needle, hits, maxHits);
                FindAll(data, utf16, pos, "UTF-16", needle, hits, maxHits);
                if (hits.Count >= maxHits) return hits;

                if (data.Length < want) break; // No se leyo todo: fin de la region util.

                ulong advance = (ulong)Math.Max(1, data.Length - overlap);
                pos += advance;
            }
        }
        return hits;
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
